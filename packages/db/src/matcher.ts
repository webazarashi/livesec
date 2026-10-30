import {
  cpeRangeMatches,
  getWatchlistProduct,
  individualRank,
  normalizeOsv,
  OSV_BATCH_LIMIT,
  purlWithoutVersion,
  sortVersions,
  type DataSensitivity,
  type Exposure,
  type OsvClient,
  type OsvRecord,
  type VulnFacts,
} from "@ichiji/core";
import type { CatalogRepo, WindowConfig } from "./catalog";
import { cacheKey, type SystemRepo } from "./system";
import type { AlertMatch, AlertRow, TenantRepo } from "./tenant";
import { chunk } from "./util";

export interface MatcherDeps {
  catalog: CatalogRepo;
  system: SystemRepo;
  osv: Pick<OsvClient, "queryBatch" | "getVuln">;
  /** OSVの原本をR2に保存する（11章：原本保存） */
  saveRaw?: (record: OsvRecord) => Promise<string | null>;
  newId: () => string;
  window: WindowConfig;
  /** 1回の実行で詳細を取りに行くOSVの最大件数（残りは次回） */
  maxDetailFetch?: number;
}

type PkgKey = { ecosystem: string; name: string; version: string };

/**
 * OSV querybatch で「パッケージ＋バージョン」ごとの該当IDを更新し（9-1）、
 * カタログにない脆弱性の詳細を /v1/vulns/{id} で取得してD1にキャッシュする。
 * OSVが止まっているときは例外を投げずに前回のキャッシュを使う。
 */
export async function refreshPackageVulns(deps: MatcherDeps, keys: PkgKey[]): Promise<{ queried: number; fetched: number; osvError: string | null }> {
  let osvError: string | null = null;
  const allIds = new Set<string>();
  let queried = 0;
  for (const part of chunk(keys, OSV_BATCH_LIMIT)) {
    try {
      const results = await deps.osv.queryBatch(part.map((k) => ({ package: { ecosystem: k.ecosystem, name: k.name }, version: k.version })));
      const entries = part.map((k, i) => ({ ...k, vulnIds: (results[i] ?? []).map((v) => v.id) }));
      await deps.system.putCachedVulns(entries);
      for (const e of entries) for (const id of e.vulnIds) allIds.add(id);
      queried += part.length;
    } catch (e) {
      osvError = String(e);
      // 停止時は前回のキャッシュで照合を続ける
      const cached = await deps.system.getCachedVulns(part);
      for (const c of cached.values()) for (const id of c.vulnIds) allIds.add(id);
    }
  }
  const fetched = await fetchMissingVulns(deps, [...allIds]);
  return { queried, fetched, osvError };
}

/** カタログにないOSVの詳細を取得して取り込む */
export async function fetchMissingVulns(deps: MatcherDeps, osvIds: string[]): Promise<number> {
  const known = await deps.catalog.knownVulnIds(osvIds);
  const missing = osvIds.filter((id) => !known.has(id)).slice(0, deps.maxDetailFetch ?? 300);
  const touched: string[] = [];
  for (const id of missing) {
    try {
      const record = await deps.osv.getVuln(id);
      if (!record) continue;
      const r2Key = deps.saveRaw ? await deps.saveRaw(record) : null;
      touched.push(await deps.catalog.upsertOsv(normalizeOsv(record), r2Key));
    } catch {
      // 次回に再取得する
    }
  }
  if (touched.length) await deps.catalog.refreshDerived(touched, deps.window);
  return touched.length;
}

/**
 * 1プロジェクトを照合し、アラートを更新する（9章・7-4）。
 * @returns 新しく作ったアラート
 */
export async function matchProject(deps: MatcherDeps, repo: TenantRepo, projectId: string): Promise<{ created: AlertRow[]; resolved: number; matched: number }> {
  const project = await repo.getProject(projectId);
  if (!project) throw new Error(`project not found: ${projectId}`);
  const [components, packages] = await Promise.all([repo.listComponents(projectId), repo.listPackages(projectId)]);
  const compByName = new Map(components.map((c) => [c.name, c]));

  // パッケージ（バージョンあり）→ OSV の該当ID（キャッシュ）
  const versioned = packages.filter((p) => p.kind === "package" && p.version);
  const cache = await deps.system.getCachedVulns(versioned.map((p) => ({ ecosystem: p.ecosystem, name: p.name, version: p.version! })));
  const osvIds = new Set<string>();
  for (const c of cache.values()) for (const id of c.vulnIds) osvIds.add(id);
  const osvToVuln = await deps.catalog.resolveOsvIds([...osvIds]);

  type Candidate = { vulnId: string; pkg: (typeof packages)[number]; versionUnknown: boolean; fixedOverride?: string[] };
  const candidates: Candidate[] = [];

  for (const p of versioned) {
    const hit = cache.get(cacheKey({ ecosystem: p.ecosystem, name: p.name, version: p.version! }));
    for (const osvId of hit?.vulnIds ?? []) {
      const vulnId = osvToVuln.get(osvId);
      if (vulnId) candidates.push({ vulnId, pkg: p, versionUnknown: false });
    }
  }

  // バージョン不明のパッケージ（CDNの常に最新など）→ そのパッケージのカタログの脆弱性すべて（B固定）
  for (const p of packages.filter((x) => x.kind === "package" && !x.version)) {
    for (const vulnId of await deps.catalog.listVulnIdsForPackage(p.ecosystem, p.name)) {
      candidates.push({ vulnId, pkg: p, versionUnknown: true });
    }
  }

  // ウォッチリスト（NVDのCPE）
  const watched = packages.filter((p) => p.kind === "watch");
  const cpes = await deps.catalog.listCpesForProducts([...new Set(watched.map((w) => w.name))]);
  for (const w of watched) {
    const rows = cpes.filter((c) => c.product_key === w.name);
    const byVuln = new Map<string, typeof rows>();
    for (const r of rows) byVuln.set(r.vuln_id, [...(byVuln.get(r.vuln_id) ?? []), r]);
    for (const [vulnId, ranges] of byVuln) {
      const fixed = sortVersions(ranges.map((r) => r.end_excl).filter((v): v is string => Boolean(v)));
      if (!w.version) {
        candidates.push({ vulnId, pkg: w, versionUnknown: true, fixedOverride: fixed });
        continue;
      }
      const hit = ranges.some((r) =>
        cpeRangeMatches(w.version!, {
          exact: r.version_exact,
          startIncluding: r.start_incl,
          startExcluding: r.start_excl,
          endIncluding: r.end_incl,
          endExcluding: r.end_excl,
        }),
      );
      if (hit) candidates.push({ vulnId, pkg: w, versionUnknown: false, fixedOverride: fixed });
    }
  }

  const facts = new Map<string, VulnFacts>();
  for (const f of await deps.catalog.getFactsMany([...new Set(candidates.map((c) => c.vulnId))], { includeRaw: true })) {
    if (f.raw?.withdrawn) continue;
    facts.set(f.id, f);
  }

  const matches: AlertMatch[] = [];
  for (const c of candidates) {
    const f = facts.get(c.vulnId);
    const comp = compByName.get(c.pkg.component);
    if (!f || !comp) continue;
    const result = individualRank(f.rank, {
      versionMatched: !c.versionUnknown,
      versionUnknown: c.versionUnknown,
      exposure: comp.exposure as Exposure,
      dataSensitivity: project.data_sensitivity as DataSensitivity,
      isDev: c.pkg.is_dev === 1,
      managed: comp.managed === 1,
      kev: f.kev,
    });
    if (!result.rank) continue;
    const isWatch = c.pkg.kind === "watch";
    const fixed =
      c.fixedOverride ??
      sortVersions(f.packages.filter((p) => p.ecosystem === c.pkg.ecosystem && p.name === c.pkg.name).flatMap((p) => p.fixed));
    matches.push({
      id: deps.newId(),
      vulnId: c.vulnId,
      component: c.pkg.component,
      packageKey: `${c.pkg.kind}:${c.pkg.ecosystem}:${c.pkg.name}`,
      packageLabel: isWatch
        ? getWatchlistProduct(c.pkg.name)?.label ?? c.pkg.name
        : c.pkg.source === "cdn"
          ? `${c.pkg.name}（CDN）`
          : purlWithoutVersion(c.pkg.purl),
      installedVersion: c.pkg.version,
      versionUnknown: c.versionUnknown,
      isDev: c.pkg.is_dev === 1,
      generalRank: f.rank,
      rank: result.rank,
      steps: result.steps,
      notes: result.notes,
      fixed,
    });
  }

  const { created, resolved } = await repo.applyMatches(projectId, matches);
  return { created, resolved, matched: matches.length };
}
