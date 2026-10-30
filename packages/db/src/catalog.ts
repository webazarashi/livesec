import {
  DEFAULT_SCORING_CONFIG,
  describeCpeRange,
  factsHash,
  generalRank,
  ghsaSeverityToScore,
  hasPoc,
  isTopicKey,
  normalizeRange,
  primaryTopic,
  sortVersions,
  getWatchlistProduct,
  type CvssFact,
  type NormalizedOsv,
  type NvdCve,
  type PackageFact,
  type Rank,
  type ScoringConfig,
  type TopicKey,
  type VulnFacts,
  type WatchlistCpeMatch,
} from "@ichiji/core";
import { chunk, MAX_BINDINGS, nowIso, parseJson, placeholders, runBatches } from "./util";

export interface VulnRow {
  id: string;
  is_cve: number;
  aliases: string;
  in_scope: number;
  topic: string | null;
  summary: string | null;
  published_at: string | null;
  modified_at: string | null;
  cvss_score: number | null;
  cvss_version: string | null;
  cvss_source: string | null;
  cvss_vector: string | null;
  ghsa_severity: string | null;
  epss: number | null;
  epss_percentile: number | null;
  kev: number;
  kev_added_at: string | null;
  poc: number;
  general_rank: Rank;
  rank_reasons: string;
  facts_hash: string | null;
  withdrawn: number;
  nvd_checked_at: string | null;
  first_seen_at: string;
  updated_at: string;
}

interface PackageRow {
  vuln_id: string;
  ecosystem: string;
  name: string;
  purl: string;
  affected: string;
  fixed: string;
  topic: string | null;
  source: string;
}

interface CpeRow {
  vuln_id: string;
  product_key: string;
  criteria: string;
  version_exact: string | null;
  start_incl: string | null;
  start_excl: string | null;
  end_incl: string | null;
  end_excl: string | null;
}

export interface ArticleRow {
  id: number;
  slug: string;
  topic: TopicKey;
  title: string;
  why_read: string;
  points: string;
  gains: string;
  faq: string;
  sources: string;
  tags: string;
  body_md: string;
  body_html: string;
  check_html: string | null;
  summary_html: string | null;
  toc: string;
  excerpt: string;
  description: string;
  reading_minutes: number;
  cve_ids: string;
  primary_cve: string;
  general_rank: Rank;
  facts_hash: string;
  needs_update: number;
  pinned: number;
  pinned_at: string | null;
  published_at: string;
  updated_at: string;
}

/** 一覧表示用（本文なし） */
export type ArticleSummary = Pick<
  ArticleRow,
  "id" | "slug" | "topic" | "title" | "why_read" | "description" | "primary_cve" | "general_rank" | "published_at" | "updated_at" | "reading_minutes" | "tags"
>;

const SUMMARY_COLUMNS =
  "a.id, a.slug, a.topic, a.title, a.why_read, a.description, a.primary_cve, a.general_rank, a.published_at, a.updated_at, a.reading_minutes, a.tags";

/** 実際に使うCVSS（7-2）：NVDの値、なければGHSAの深刻度で代用 */
export function effectiveCvss(row: Pick<VulnRow, "cvss_score" | "cvss_version" | "cvss_source" | "cvss_vector" | "ghsa_severity">, config: ScoringConfig = DEFAULT_SCORING_CONFIG): CvssFact | null {
  if (row.cvss_score !== null && row.cvss_score !== undefined) {
    return {
      score: row.cvss_score,
      version: row.cvss_version,
      source: (row.cvss_source as CvssFact["source"]) ?? "nvd",
      vector: row.cvss_vector,
    };
  }
  const sub = ghsaSeverityToScore(row.ghsa_severity, config);
  return sub === null ? null : { score: sub, version: null, source: "ghsa", vector: null };
}

function packagesFromRows(pkgs: PackageRow[], cpes: CpeRow[]): PackageFact[] {
  // 同じパッケージが複数のOSVレコード（GHSA と PYSEC など）にある場合は GHSA を優先する
  const byKey = new Map<string, PackageRow>();
  for (const p of pkgs) {
    const key = `${p.ecosystem}\u0000${p.name}`;
    const prev = byKey.get(key);
    if (!prev || (p.source.startsWith("GHSA-") && !prev.source.startsWith("GHSA-"))) byKey.set(key, p);
  }
  const out: PackageFact[] = [...byKey.values()].map((p) => ({
    purl: p.purl,
    ecosystem: p.ecosystem,
    name: p.name,
    affected: p.affected,
    fixed: parseJson<string[]>(p.fixed, []),
  }));
  const byProduct = new Map<string, CpeRow[]>();
  for (const c of cpes) byProduct.set(c.product_key, [...(byProduct.get(c.product_key) ?? []), c]);
  for (const [productKey, rows] of byProduct) {
    const ranges = rows.map((r) =>
      describeCpeRange({
        exact: r.version_exact,
        startIncluding: r.start_incl,
        startExcluding: r.start_excl,
        endIncluding: r.end_incl,
        endExcluding: r.end_excl,
      }),
    );
    out.push({
      purl: `pkg:generic/${productKey}`,
      ecosystem: "watchlist",
      name: getWatchlistProduct(productKey)?.label ?? productKey,
      affected: normalizeRange([...new Set(ranges)].join(" || ")),
      fixed: sortVersions(rows.map((r) => r.end_excl).filter((v): v is string => Boolean(v))),
    });
  }
  return out.sort((a, b) => a.purl.localeCompare(b.purl));
}

export interface WindowConfig {
  /** メディアに載せる公開日の下限（初回取り込み時点から30日遡る） */
  windowStart: string;
}

export class CatalogRepo {
  constructor(
    readonly db: D1Database,
    private readonly scoring: ScoringConfig = DEFAULT_SCORING_CONFIG,
  ) {}

  // ---------- site_meta ----------

  async getMeta(key: string): Promise<string | null> {
    const row = await this.db.prepare("SELECT value FROM site_meta WHERE key = ?").bind(key).first<{ value: string }>();
    return row?.value ?? null;
  }

  async setMeta(key: string, value: string): Promise<void> {
    await this.db
      .prepare("INSERT INTO site_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .bind(key, value)
      .run();
  }

  /** 掲載期間の開始日。初回に呼んだ時点から30日遡った日を保存する */
  async ensureWindowStart(now = new Date(), days = 30): Promise<string> {
    const existing = await this.getMeta("window_start");
    if (existing) return existing;
    const start = new Date(now.getTime() - days * 86_400_000).toISOString();
    await this.setMeta("window_start", start);
    return start;
  }

  async getIngestState(source: string): Promise<{ cursor: string | null; detail: string | null } | null> {
    return this.db
      .prepare("SELECT cursor, detail FROM ingest_state WHERE source = ?")
      .bind(source)
      .first<{ cursor: string | null; detail: string | null }>();
  }

  async setIngestState(source: string, cursor: string | null, detail?: string): Promise<void> {
    await this.db
      .prepare(
        "INSERT INTO ingest_state (source, cursor, updated_at, detail) VALUES (?, ?, ?, ?) ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at, detail = excluded.detail",
      )
      .bind(source, cursor, nowIso(), detail ?? null)
      .run();
  }

  // ---------- 取り込み ----------

  async getOsvModified(osvIds: string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const part of chunk(osvIds, MAX_BINDINGS)) {
      const { results } = await this.db
        .prepare(`SELECT osv_id, modified FROM osv_records WHERE osv_id IN (${placeholders(part.length)})`)
        .bind(...part)
        .all<{ osv_id: string; modified: string }>();
      for (const r of results) out.set(r.osv_id, r.modified);
    }
    return out;
  }

  /** OSV の1件を取り込む。同じOSVのIDの行は入れ替える */
  async upsertOsv(n: NormalizedOsv, r2Key: string | null): Promise<string> {
    const now = nowIso();
    const stmts: D1PreparedStatement[] = [
      this.db
        .prepare(
          `INSERT INTO vulns (id, is_cve, aliases, summary, published_at, modified_at, ghsa_severity, cvss_vector, withdrawn, first_seen_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             aliases = (SELECT json_group_array(DISTINCT value) FROM (SELECT value FROM json_each(vulns.aliases) UNION SELECT value FROM json_each(excluded.aliases))),
             summary = COALESCE(vulns.summary, excluded.summary),
             published_at = COALESCE(MIN(vulns.published_at, excluded.published_at), vulns.published_at, excluded.published_at),
             modified_at = MAX(COALESCE(vulns.modified_at, ''), excluded.modified_at),
             ghsa_severity = COALESCE(excluded.ghsa_severity, vulns.ghsa_severity),
             cvss_vector = COALESCE(vulns.cvss_vector, excluded.cvss_vector),
             withdrawn = excluded.withdrawn,
             updated_at = excluded.updated_at`,
        )
        .bind(
          n.vulnId,
          n.isCve ? 1 : 0,
          JSON.stringify(n.aliases),
          n.summary,
          n.publishedAt,
          n.modifiedAt,
          n.ghsaSeverity,
          n.cvssVector,
          n.withdrawn ? 1 : 0,
          now,
          now,
        ),
      this.db.prepare("DELETE FROM vuln_packages WHERE source = ?").bind(n.osvId),
      ...n.packages.map((p) =>
        this.db
          .prepare(
            "INSERT OR REPLACE INTO vuln_packages (vuln_id, ecosystem, name, purl, affected, fixed, topic, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .bind(n.vulnId, p.ecosystem, p.name, p.purl, p.affected, JSON.stringify(p.fixed), p.topic, n.osvId),
      ),
      ...n.references.slice(0, 60).map((r) =>
        this.db
          .prepare("INSERT OR IGNORE INTO vuln_references (vuln_id, url, tags) VALUES (?, ?, ?)")
          .bind(n.vulnId, r.url, JSON.stringify(r.tags)),
      ),
      this.db
        .prepare(
          "INSERT INTO osv_records (osv_id, vuln_id, modified, r2_key) VALUES (?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET vuln_id = excluded.vuln_id, modified = excluded.modified, r2_key = excluded.r2_key",
        )
        .bind(n.osvId, n.vulnId, n.modifiedAt, r2Key),
    ];
    await runBatches(this.db, stmts);
    return n.vulnId;
  }

  /** NVD の1件を反映する（CVSS・参照URL・ウォッチリストのCPE） */
  async applyNvd(cve: NvdCve, cvss: CvssFact | null, cpes: WatchlistCpeMatch[], options: { createIfMissing: boolean }): Promise<boolean> {
    const exists = await this.db.prepare("SELECT 1 FROM vulns WHERE id = ?").bind(cve.id).first();
    if (!exists && !options.createIfMissing) return false;
    const now = nowIso();
    const stmts: D1PreparedStatement[] = [];
    if (!exists) {
      stmts.push(
        this.db
          .prepare(
            "INSERT INTO vulns (id, is_cve, aliases, summary, published_at, modified_at, first_seen_at, updated_at) VALUES (?, 1, '[]', ?, ?, ?, ?, ?)",
          )
          .bind(
            cve.id,
            cve.descriptions?.find((d) => d.lang === "en")?.value?.slice(0, 1000) ?? null,
            toIso(cve.published),
            toIso(cve.lastModified),
            now,
            now,
          ),
      );
    }
    stmts.push(
      this.db
        .prepare(
          `UPDATE vulns SET cvss_score = ?, cvss_version = ?, cvss_source = ?, cvss_vector = COALESCE(?, cvss_vector),
             published_at = COALESCE(published_at, ?), modified_at = MAX(COALESCE(modified_at, ''), ?),
             nvd_checked_at = ?, updated_at = ? WHERE id = ?`,
        )
        .bind(cvss?.score ?? null, cvss?.version ?? null, cvss?.source ?? null, cvss?.vector ?? null, toIso(cve.published), toIso(cve.lastModified), now, now, cve.id),
      this.db.prepare("DELETE FROM vuln_cpes WHERE vuln_id = ?").bind(cve.id),
      ...cpes.map((c) =>
        this.db
          .prepare(
            "INSERT INTO vuln_cpes (vuln_id, product_key, criteria, version_exact, start_incl, start_excl, end_incl, end_excl) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .bind(cve.id, c.productKey, c.criteria, c.exact ?? null, c.startIncluding ?? null, c.startExcluding ?? null, c.endIncluding ?? null, c.endExcluding ?? null),
      ),
      ...(cve.references ?? []).slice(0, 60).map((r) =>
        this.db
          .prepare(
            "INSERT INTO vuln_references (vuln_id, url, tags) VALUES (?, ?, ?) ON CONFLICT(vuln_id, url) DO UPDATE SET tags = excluded.tags",
          )
          .bind(cve.id, r.url, JSON.stringify(r.tags ?? [])),
      ),
    );
    if (cve.cisaExploitAdd) {
      stmts.push(this.db.prepare("UPDATE vulns SET kev = 1, kev_added_at = COALESCE(kev_added_at, ?) WHERE id = ?").bind(cve.cisaExploitAdd, cve.id));
    }
    await runBatches(this.db, stmts);
    return true;
  }

  async markNvdChecked(ids: string[]): Promise<void> {
    const now = nowIso();
    await runBatches(
      this.db,
      ids.map((id) => this.db.prepare("UPDATE vulns SET nvd_checked_at = ? WHERE id = ?").bind(now, id)),
    );
  }

  /** NVD のCVSSをまだ確認していないCVE（新しい順） */
  async listNvdBacklog(limit: number): Promise<string[]> {
    const { results } = await this.db
      .prepare("SELECT id FROM vulns WHERE is_cve = 1 AND nvd_checked_at IS NULL ORDER BY COALESCE(published_at, first_seen_at) DESC LIMIT ?")
      .bind(limit)
      .all<{ id: string }>();
    return results.map((r) => r.id);
  }

  /** KEV を反映する。カタログにあるCVEだけ更新し、更新したIDを返す */
  async applyKev(entries: Array<{ cveId: string; dateAdded: string }>): Promise<string[]> {
    const changed: string[] = [];
    for (const part of chunk(entries, MAX_BINDINGS)) {
      const ids = part.map((e) => e.cveId);
      const { results } = await this.db
        .prepare(`SELECT id FROM vulns WHERE kev = 0 AND id IN (${placeholders(ids.length)})`)
        .bind(...ids)
        .all<{ id: string }>();
      const hit = new Set(results.map((r) => r.id));
      const stmts = part
        .filter((e) => hit.has(e.cveId))
        .map((e) => this.db.prepare("UPDATE vulns SET kev = 1, kev_added_at = ?, updated_at = ? WHERE id = ?").bind(e.dateAdded, nowIso(), e.cveId));
      await runBatches(this.db, stmts);
      changed.push(...hit);
    }
    return changed;
  }

  async listCveIdsForEpss(limit = 5000): Promise<string[]> {
    const { results } = await this.db
      .prepare(
        "SELECT id FROM vulns WHERE is_cve = 1 AND withdrawn = 0 AND (epss_updated_at IS NULL OR epss_updated_at < ?) ORDER BY in_scope DESC, COALESCE(published_at, first_seen_at) DESC LIMIT ?",
      )
      .bind(new Date(Date.now() - 20 * 3_600_000).toISOString(), limit)
      .all<{ id: string }>();
    return results.map((r) => r.id);
  }

  async applyEpss(scores: Array<{ cveId: string; epss: number; percentile: number }>, checkedIds: string[]): Promise<void> {
    const now = nowIso();
    const stmts = [
      ...scores.map((s) =>
        this.db.prepare("UPDATE vulns SET epss = ?, epss_percentile = ?, epss_updated_at = ? WHERE id = ?").bind(s.epss, s.percentile, now, s.cveId),
      ),
      // スコアが返らなかったCVEも確認済みにする（翌日に再確認）
      ...checkedIds.map((id) => this.db.prepare("UPDATE vulns SET epss_updated_at = ? WHERE id = ? AND epss_updated_at IS NULL").bind(now, id)),
    ];
    await runBatches(this.db, stmts);
  }

  /**
   * 派生値（トピック・掲載対象・CVSS・PoC・一般緊急度・facts_hash）を計算し直す。
   * facts_hash が変わった記事には「要更新」フラグを立てる（10-1 の5）。
   * @returns 一般緊急度または事実が変わったID
   */
  async refreshDerived(ids: string[], window: WindowConfig): Promise<{ changed: string[]; needsUpdate: string[] }> {
    const changed: string[] = [];
    const needsUpdate: string[] = [];
    for (const part of chunk([...new Set(ids)], 40)) {
      const facts = await this.getFactsMany(part, { includeRaw: true });
      const stmts: D1PreparedStatement[] = [];
      for (const f of facts) {
        const row = f.raw!;
        const poc = hasPoc(f.references);
        const cvss = effectiveCvss(row, this.scoring);
        const rank = generalRank({ cvss: cvss?.score ?? null, epss: row.epss, kev: row.kev === 1, poc }, this.scoring);
        const topics = new Set<TopicKey>();
        for (const p of f.packageTopics) if (p && isTopicKey(p)) topics.add(p);
        for (const p of f.packages) if (p.ecosystem === "watchlist") topics.add(getWatchlistProduct(p.purl.slice("pkg:generic/".length))?.topic ?? "middleware");
        const topic = primaryTopic(topics);
        const inScope =
          row.is_cve === 1 && row.withdrawn === 0 && topic !== null && (row.published_at ?? row.first_seen_at) >= window.windowStart ? 1 : 0;
        const hash = factsHash({ id: f.id, packages: f.packages, cvss, kev: row.kev === 1 });
        if (hash !== row.facts_hash || rank.rank !== row.general_rank || poc !== (row.poc === 1)) changed.push(f.id);
        stmts.push(
          this.db
            .prepare("UPDATE vulns SET topic = ?, in_scope = ?, poc = ?, general_rank = ?, rank_reasons = ?, facts_hash = ? WHERE id = ?")
            .bind(topic, inScope, poc ? 1 : 0, rank.rank, JSON.stringify(rank.reasons), hash, f.id),
          this.db.prepare("UPDATE articles SET general_rank = ? WHERE primary_cve = ?").bind(rank.rank, f.id),
        );
        if (row.facts_hash && hash !== row.facts_hash) {
          stmts.push(
            this.db
              .prepare(
                "UPDATE articles SET needs_update = 1 WHERE facts_hash != ? AND id IN (SELECT article_id FROM article_cves WHERE cve_id = ?)",
              )
              .bind(hash, f.id),
          );
          needsUpdate.push(f.id);
        }
      }
      await runBatches(this.db, stmts);
    }
    return { changed, needsUpdate };
  }

  // ---------- 事実データ ----------

  async getVulnRow(id: string): Promise<VulnRow | null> {
    return this.db.prepare("SELECT * FROM vulns WHERE id = ?").bind(id).first<VulnRow>();
  }

  async getFacts(id: string): Promise<VulnFacts | null> {
    const [f] = await this.getFactsMany([id]);
    return f ?? null;
  }

  async getFactsMany(
    ids: string[],
    options: { includeRaw?: boolean } = {},
  ): Promise<Array<VulnFacts & { raw?: VulnRow; packageTopics: Array<string | null>; summary: string | null; inScope: boolean; topic: string | null }>> {
    if (!ids.length) return [];
    const out = [];
    for (const part of chunk([...new Set(ids)], MAX_BINDINGS)) {
      const ph = placeholders(part.length);
      const [vulns, pkgs, cpes, refs] = await this.db.batch([
        this.db.prepare(`SELECT * FROM vulns WHERE id IN (${ph})`).bind(...part),
        this.db.prepare(`SELECT * FROM vuln_packages WHERE vuln_id IN (${ph})`).bind(...part),
        this.db.prepare(`SELECT * FROM vuln_cpes WHERE vuln_id IN (${ph})`).bind(...part),
        this.db.prepare(`SELECT vuln_id, url, tags FROM vuln_references WHERE vuln_id IN (${ph})`).bind(...part),
      ]);
      const pkgRows = (pkgs!.results ?? []) as PackageRow[];
      const cpeRows = (cpes!.results ?? []) as CpeRow[];
      const refRows = (refs!.results ?? []) as Array<{ vuln_id: string; url: string; tags: string }>;
      for (const v of (vulns!.results ?? []) as VulnRow[]) {
        const myPkgs = pkgRows.filter((p) => p.vuln_id === v.id);
        out.push({
          id: v.id,
          aliases: parseJson<string[]>(v.aliases, []),
          packages: packagesFromRows(myPkgs, cpeRows.filter((c) => c.vuln_id === v.id)),
          packageTopics: myPkgs.map((p) => p.topic),
          cvss: effectiveCvss(v, this.scoring),
          epss: v.epss,
          epssPercentile: v.epss_percentile,
          kev: v.kev === 1,
          kevAddedAt: v.kev_added_at,
          poc: v.poc === 1,
          rank: v.general_rank,
          rankReasons: parseJson<string[]>(v.rank_reasons, []),
          publishedAt: v.published_at,
          modifiedAt: v.modified_at,
          references: refRows.filter((r) => r.vuln_id === v.id).map((r) => ({ url: r.url, tags: parseJson<string[]>(r.tags, []) })),
          summary: v.summary,
          inScope: v.in_scope === 1,
          topic: v.topic,
          ...(options.includeRaw ? { raw: v } : {}),
        });
      }
    }
    return out;
  }

  /** ウォッチリスト製品のCPE範囲（MW突合用） */
  async listCpesForProducts(productKeys: string[]): Promise<CpeRow[]> {
    if (!productKeys.length) return [];
    const { results } = await this.db
      .prepare(`SELECT c.* FROM vuln_cpes c JOIN vulns v ON v.id = c.vuln_id WHERE v.withdrawn = 0 AND c.product_key IN (${placeholders(productKeys.length)})`)
      .bind(...productKeys)
      .all<CpeRow>();
    return results;
  }

  /** パッケージ名で、そのパッケージに関するカタログの脆弱性ID（CDNでバージョン不明の場合など） */
  async listVulnIdsForPackage(ecosystem: string, name: string): Promise<string[]> {
    const { results } = await this.db
      .prepare("SELECT DISTINCT p.vuln_id FROM vuln_packages p JOIN vulns v ON v.id = p.vuln_id WHERE v.withdrawn = 0 AND p.ecosystem = ? AND p.name = ?")
      .bind(ecosystem, name)
      .all<{ vuln_id: string }>();
    return results.map((r) => r.vuln_id);
  }

  async knownVulnIds(ids: string[]): Promise<Set<string>> {
    const out = new Set<string>();
    for (const part of chunk(ids, MAX_BINDINGS)) {
      const { results } = await this.db
        .prepare(`SELECT osv_id AS id FROM osv_records WHERE osv_id IN (${placeholders(part.length)})`)
        .bind(...part)
        .all<{ id: string }>();
      for (const r of results) out.add(r.id);
    }
    return out;
  }

  /** OSVのID → 正規ID */
  async resolveOsvIds(osvIds: string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const part of chunk(osvIds, MAX_BINDINGS)) {
      const { results } = await this.db
        .prepare(`SELECT osv_id, vuln_id FROM osv_records WHERE osv_id IN (${placeholders(part.length)})`)
        .bind(...part)
        .all<{ osv_id: string; vuln_id: string }>();
      for (const r of results) out.set(r.osv_id, r.vuln_id);
    }
    return out;
  }

  // ---------- 記事（メディア） ----------

  async stats(): Promise<{ cves: number; articles: number; weekUrgent: number }> {
    const weekAgo = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const [cves, articles, urgent] = await this.db.batch([
      this.db.prepare("SELECT COUNT(*) AS n FROM vulns WHERE in_scope = 1"),
      this.db.prepare("SELECT COUNT(*) AS n FROM articles"),
      this.db.prepare("SELECT COUNT(*) AS n FROM vulns WHERE in_scope = 1 AND general_rank IN ('S','A') AND COALESCE(published_at, first_seen_at) >= ?").bind(weekAgo),
    ]);
    const n = (r: D1Result | undefined) => Number((r?.results?.[0] as { n?: number } | undefined)?.n ?? 0);
    return { cves: n(cves), articles: n(articles), weekUrgent: n(urgent) };
  }

  async listArticles(options: {
    limit: number;
    offset?: number;
    topic?: string;
    ranks?: Rank[];
    tag?: string;
    pinned?: boolean;
    excludeIds?: number[];
  }): Promise<ArticleSummary[]> {
    const where: string[] = [];
    const binds: unknown[] = [];
    if (options.topic) {
      where.push("a.topic = ?");
      binds.push(options.topic);
    }
    if (options.ranks?.length) {
      where.push(`a.general_rank IN (${placeholders(options.ranks.length)})`);
      binds.push(...options.ranks);
    }
    if (options.tag) {
      where.push("a.id IN (SELECT article_id FROM article_tags WHERE tag = ?)");
      binds.push(options.tag);
    }
    if (options.pinned) where.push("a.pinned = 1");
    if (options.excludeIds?.length) {
      where.push(`a.id NOT IN (${placeholders(options.excludeIds.length)})`);
      binds.push(...options.excludeIds);
    }
    const order = options.pinned ? "a.pinned_at DESC" : "a.published_at DESC, a.id DESC";
    const sql = `SELECT ${SUMMARY_COLUMNS} FROM articles a ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ${order} LIMIT ? OFFSET ?`;
    const { results } = await this.db
      .prepare(sql)
      .bind(...binds, options.limit, options.offset ?? 0)
      .all<ArticleSummary>();
    return results;
  }

  async countArticles(options: { topic?: string; ranks?: Rank[]; tag?: string } = {}): Promise<number> {
    const where: string[] = [];
    const binds: unknown[] = [];
    if (options.topic) {
      where.push("topic = ?");
      binds.push(options.topic);
    }
    if (options.ranks?.length) {
      where.push(`general_rank IN (${placeholders(options.ranks.length)})`);
      binds.push(...options.ranks);
    }
    if (options.tag) {
      where.push("id IN (SELECT article_id FROM article_tags WHERE tag = ?)");
      binds.push(options.tag);
    }
    const row = await this.db
      .prepare(`SELECT COUNT(*) AS n FROM articles ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`)
      .bind(...binds)
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async countByTopic(): Promise<Record<string, number>> {
    const { results } = await this.db.prepare("SELECT topic, COUNT(*) AS n FROM articles GROUP BY topic").all<{ topic: string; n: number }>();
    return Object.fromEntries(results.map((r) => [r.topic, r.n]));
  }

  async listTags(limit = 200): Promise<Array<{ tag: string; n: number }>> {
    const { results } = await this.db
      .prepare("SELECT tag, COUNT(*) AS n FROM article_tags GROUP BY tag ORDER BY n DESC, tag LIMIT ?")
      .bind(limit)
      .all<{ tag: string; n: number }>();
    return results;
  }

  async searchArticles(q: string, limit = 50): Promise<ArticleSummary[]> {
    const term = q.trim().slice(0, 100);
    if (!term) return [];
    const like = `%${term.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    const { results } = await this.db
      .prepare(
        `SELECT ${SUMMARY_COLUMNS} FROM articles a
         WHERE a.title LIKE ?1 ESCAPE '\\' OR a.cve_ids LIKE ?1 ESCAPE '\\' OR a.tags LIKE ?1 ESCAPE '\\'
            OR a.id IN (SELECT ac.article_id FROM article_cves ac JOIN vuln_packages p ON p.vuln_id = ac.cve_id WHERE p.name LIKE ?1 ESCAPE '\\')
         ORDER BY a.published_at DESC LIMIT ?2`,
      )
      .bind(like, limit)
      .all<ArticleSummary>();
    return results;
  }

  async getArticle(topic: string, slug: string): Promise<ArticleRow | null> {
    return this.db.prepare("SELECT * FROM articles WHERE topic = ? AND slug = ?").bind(topic, slug).first<ArticleRow>();
  }

  async getArticleBySlug(slug: string): Promise<ArticleRow | null> {
    return this.db.prepare("SELECT * FROM articles WHERE slug = ?").bind(slug).first<ArticleRow>();
  }

  async getArticleByCve(cveId: string): Promise<ArticleSummary | null> {
    return this.db
      .prepare(`SELECT ${SUMMARY_COLUMNS} FROM articles a JOIN article_cves c ON c.article_id = a.id WHERE c.cve_id = ? ORDER BY a.published_at DESC LIMIT 1`)
      .bind(cveId)
      .first<ArticleSummary>();
  }

  async articleUrlsForCves(cveIds: string[]): Promise<Map<string, { topic: string; slug: string }>> {
    const out = new Map<string, { topic: string; slug: string }>();
    for (const part of chunk(cveIds, MAX_BINDINGS)) {
      const { results } = await this.db
        .prepare(`SELECT c.cve_id, a.topic, a.slug FROM article_cves c JOIN articles a ON a.id = c.article_id WHERE c.cve_id IN (${placeholders(part.length)})`)
        .bind(...part)
        .all<{ cve_id: string; topic: string; slug: string }>();
      for (const r of results) out.set(r.cve_id, { topic: r.topic, slug: r.slug });
    }
    return out;
  }

  /** 関連記事：同じトピック・同じタグの新しい順 */
  async relatedArticles(article: Pick<ArticleRow, "id" | "topic" | "tags">, limit: number, excludeIds: number[] = []): Promise<ArticleSummary[]> {
    const tags = parseJson<string[]>(article.tags, []);
    const exclude = [article.id, ...excludeIds];
    const { results } = await this.db
      .prepare(
        `SELECT ${SUMMARY_COLUMNS},
           (CASE WHEN a.topic = ? THEN 1 ELSE 0 END) + (SELECT COUNT(*) FROM article_tags t WHERE t.article_id = a.id AND t.tag IN (SELECT value FROM json_each(?))) AS score
         FROM articles a WHERE a.id NOT IN (${placeholders(exclude.length)})
         ORDER BY score DESC, a.published_at DESC LIMIT ?`,
      )
      .bind(article.topic, JSON.stringify(tags), ...exclude, limit)
      .all<ArticleSummary>();
    return results;
  }

  async adjacentArticles(article: Pick<ArticleRow, "id" | "published_at">): Promise<{ prev: ArticleSummary | null; next: ArticleSummary | null }> {
    const [prev, next] = await this.db.batch([
      this.db
        .prepare(`SELECT ${SUMMARY_COLUMNS} FROM articles a WHERE (a.published_at, a.id) < (?, ?) ORDER BY a.published_at DESC, a.id DESC LIMIT 1`)
        .bind(article.published_at, article.id),
      this.db
        .prepare(`SELECT ${SUMMARY_COLUMNS} FROM articles a WHERE (a.published_at, a.id) > (?, ?) ORDER BY a.published_at ASC, a.id ASC LIMIT 1`)
        .bind(article.published_at, article.id),
    ]);
    return {
      prev: ((prev!.results ?? [])[0] as ArticleSummary | undefined) ?? null,
      next: ((next!.results ?? [])[0] as ArticleSummary | undefined) ?? null,
    };
  }

  async listRevisions(articleId: number): Promise<Array<{ revised_at: string; kind: string; note: string }>> {
    const { results } = await this.db
      .prepare("SELECT revised_at, kind, note FROM article_revisions WHERE article_id = ? ORDER BY revised_at DESC")
      .bind(articleId)
      .all<{ revised_at: string; kind: string; note: string }>();
    return results;
  }

  async popularArticles(period: "24h" | "30d", limit: number): Promise<Array<ArticleSummary & { views: number }>> {
    const { results } = await this.db
      .prepare(`SELECT ${SUMMARY_COLUMNS}, r.views FROM article_rankings r JOIN articles a ON a.id = r.article_id WHERE r.period = ? ORDER BY r.position LIMIT ?`)
      .bind(period, limit)
      .all<ArticleSummary & { views: number }>();
    if (results.length) return results;
    // 集計前は新しい緊急度の高い記事で埋める
    const fallback = await this.listArticles({ limit, ranks: ["S", "A", "B"] });
    return fallback.map((a) => ({ ...a, views: 0 }));
  }

  async saveRankings(period: "24h" | "30d", rows: Array<{ slug: string; views: number }>): Promise<void> {
    const now = nowIso();
    const stmts: D1PreparedStatement[] = [this.db.prepare("DELETE FROM article_rankings WHERE period = ?").bind(period)];
    rows.forEach((r, i) => {
      stmts.push(
        this.db
          .prepare("INSERT OR IGNORE INTO article_rankings (period, article_id, views, position, computed_at) SELECT ?, id, ?, ?, ? FROM articles WHERE slug = ?")
          .bind(period, r.views, i + 1, now, r.slug),
      );
    });
    await runBatches(this.db, stmts);
  }

  async setPinned(slug: string, pinned: boolean): Promise<void> {
    await this.db
      .prepare("UPDATE articles SET pinned = ?, pinned_at = CASE WHEN ? = 1 THEN ? ELSE NULL END WHERE slug = ?")
      .bind(pinned ? 1 : 0, pinned ? 1 : 0, nowIso(), slug)
      .run();
  }

  // ---------- 管理画面 ----------

  /** 記事待ちCVE一覧（対象範囲のみ、緊急度順）。要更新の記事も含める */
  async listPendingCves(limit = 200, offset = 0): Promise<Array<{ id: string; topic: string; general_rank: Rank; published_at: string | null; summary: string | null; article_slug: string | null; needs_update: number }>> {
    const { results } = await this.db
      .prepare(
        `SELECT v.id, v.topic, v.general_rank, v.published_at, v.summary, a.slug AS article_slug, COALESCE(a.needs_update, 0) AS needs_update
         FROM vulns v
         LEFT JOIN article_cves ac ON ac.cve_id = v.id
         LEFT JOIN articles a ON a.id = ac.article_id
         WHERE v.in_scope = 1 AND (a.id IS NULL OR a.needs_update = 1)
         ORDER BY CASE v.general_rank WHEN 'S' THEN 0 WHEN 'A' THEN 1 WHEN 'B' THEN 2 ELSE 3 END, v.published_at DESC
         LIMIT ? OFFSET ?`,
      )
      .bind(limit, offset)
      .all<{ id: string; topic: string; general_rank: Rank; published_at: string | null; summary: string | null; article_slug: string | null; needs_update: number }>();
    return results;
  }

  async countPendingCves(): Promise<number> {
    const row = await this.db
      .prepare(
        `SELECT COUNT(*) AS n FROM vulns v LEFT JOIN article_cves ac ON ac.cve_id = v.id LEFT JOIN articles a ON a.id = ac.article_id
         WHERE v.in_scope = 1 AND (a.id IS NULL OR a.needs_update = 1)`,
      )
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async publishArticle(input: {
    slug: string;
    topic: TopicKey;
    title: string;
    whyRead: string;
    points: string[];
    gains: string[];
    faq: Array<{ q: string; a: string }>;
    sources: Array<{ title: string; url: string; note?: string }>;
    tags: string[];
    bodyMd: string;
    bodyHtml: string;
    checkHtml: string | null;
    summaryHtml: string | null;
    toc: unknown;
    excerpt: string;
    description: string;
    readingMinutes: number;
    cveIds: string[];
    rank: Rank;
    factsHash: string;
    revisionNote?: string;
    revisionKind?: "update" | "correction";
  }): Promise<{ id: number; created: boolean }> {
    const now = nowIso();
    const existing = await this.db.prepare("SELECT id, body_md FROM articles WHERE slug = ?").bind(input.slug).first<{ id: number; body_md: string }>();
    const values = [
      input.topic,
      input.title,
      input.whyRead,
      JSON.stringify(input.points),
      JSON.stringify(input.gains),
      JSON.stringify(input.faq),
      JSON.stringify(input.sources),
      JSON.stringify(input.tags),
      input.bodyMd,
      input.bodyHtml,
      input.checkHtml,
      input.summaryHtml,
      JSON.stringify(input.toc),
      input.excerpt,
      input.description,
      input.readingMinutes,
      JSON.stringify(input.cveIds),
      input.cveIds[0]!,
      input.rank,
      input.factsHash,
    ];
    let id: number;
    if (existing) {
      id = existing.id;
      await this.db
        .prepare(
          `UPDATE articles SET topic = ?, title = ?, why_read = ?, points = ?, gains = ?, faq = ?, sources = ?, tags = ?, body_md = ?, body_html = ?,
             check_html = ?, summary_html = ?, toc = ?, excerpt = ?, description = ?, reading_minutes = ?, cve_ids = ?, primary_cve = ?, general_rank = ?,
             facts_hash = ?, needs_update = 0, updated_at = ? WHERE id = ?`,
        )
        .bind(...values, now, id)
        .run();
      await this.db
        .prepare("INSERT INTO article_revisions (article_id, revised_at, kind, note, previous_body_md) VALUES (?, ?, ?, ?, ?)")
        .bind(id, now, input.revisionKind ?? "update", input.revisionNote ?? "ソースデータの更新にあわせて内容を更新しました", existing.body_md)
        .run();
    } else {
      const row = await this.db
        .prepare(
          `INSERT INTO articles (topic, title, why_read, points, gains, faq, sources, tags, body_md, body_html, check_html, summary_html, toc, excerpt,
             description, reading_minutes, cve_ids, primary_cve, general_rank, facts_hash, slug, published_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
        )
        .bind(...values, input.slug, now, now)
        .first<{ id: number }>();
      id = row!.id;
    }
    await runBatches(this.db, [
      this.db.prepare("DELETE FROM article_cves WHERE article_id = ?").bind(id),
      this.db.prepare("DELETE FROM article_tags WHERE article_id = ?").bind(id),
      ...input.cveIds.map((c) => this.db.prepare("INSERT OR IGNORE INTO article_cves (article_id, cve_id) VALUES (?, ?)").bind(id, c)),
      ...input.tags.map((t) => this.db.prepare("INSERT OR IGNORE INTO article_tags (article_id, tag) VALUES (?, ?)").bind(id, t)),
    ]);
    return { id, created: !existing };
  }

  async saveDraftRejection(input: { slug: string | null; cveIds: string[]; raw: string; errors: string[] }): Promise<void> {
    await this.db
      .prepare("INSERT INTO article_drafts (slug, cve_ids, raw, errors, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(input.slug, JSON.stringify(input.cveIds), input.raw.slice(0, 200_000), JSON.stringify(input.errors), nowIso())
      .run();
  }

  async listDrafts(limit = 50): Promise<Array<{ id: number; slug: string | null; cve_ids: string; errors: string; created_at: string }>> {
    const { results } = await this.db
      .prepare("SELECT id, slug, cve_ids, errors, created_at FROM article_drafts ORDER BY id DESC LIMIT ?")
      .bind(limit)
      .all<{ id: number; slug: string | null; cve_ids: string; errors: string; created_at: string }>();
    return results;
  }

  async getDraft(id: number): Promise<{ raw: string } | null> {
    return this.db.prepare("SELECT raw FROM article_drafts WHERE id = ?").bind(id).first<{ raw: string }>();
  }

  async deleteDraft(id: number): Promise<void> {
    await this.db.prepare("DELETE FROM article_drafts WHERE id = ?").bind(id).run();
  }

  /** 全記事のslug（サイトマップ・RSS用） */
  async listAllArticleSlugs(limit = 5000): Promise<Array<{ topic: string; slug: string; updated_at: string }>> {
    const { results } = await this.db
      .prepare("SELECT topic, slug, updated_at FROM articles ORDER BY published_at DESC LIMIT ?")
      .bind(limit)
      .all<{ topic: string; slug: string; updated_at: string }>();
    return results;
  }

  /** CVE DB（4-1）：対象範囲のCVE一覧 */
  async listCatalog(options: { limit: number; offset?: number; topic?: string; q?: string }): Promise<
    Array<{ id: string; topic: string | null; general_rank: Rank; published_at: string | null; cvss_score: number | null; ghsa_severity: string | null; kev: number; epss: number | null; article_slug: string | null; article_topic: string | null }>
  > {
    const where = ["v.in_scope = 1"];
    const binds: unknown[] = [];
    if (options.topic) {
      where.push("v.topic = ?");
      binds.push(options.topic);
    }
    if (options.q) {
      where.push("(v.id LIKE ? OR v.id IN (SELECT vuln_id FROM vuln_packages WHERE name LIKE ?))");
      binds.push(`%${options.q}%`, `%${options.q}%`);
    }
    const { results } = await this.db
      .prepare(
        `SELECT v.id, v.topic, v.general_rank, v.published_at, v.cvss_score, v.ghsa_severity, v.kev, v.epss,
           (SELECT a.slug FROM article_cves ac JOIN articles a ON a.id = ac.article_id WHERE ac.cve_id = v.id LIMIT 1) AS article_slug,
           (SELECT a.topic FROM article_cves ac JOIN articles a ON a.id = ac.article_id WHERE ac.cve_id = v.id LIMIT 1) AS article_topic
         FROM vulns v WHERE ${where.join(" AND ")}
         ORDER BY v.published_at DESC LIMIT ? OFFSET ?`,
      )
      .bind(...binds, options.limit, options.offset ?? 0)
      .all();
    return results as never;
  }
}

function toIso(nvdDate: string | undefined): string | null {
  if (!nvdDate) return null;
  return nvdDate.endsWith("Z") ? nvdDate : `${nvdDate}Z`;
}
