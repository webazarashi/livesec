import {
  extractWatchlistCpes,
  fetchEpss,
  fetchKev,
  fetchModifiedIds,
  normalizeOsv,
  NvdClient,
  OSV_GCS,
  selectNvdCvss,
  WATCHLIST,
  type FetchLike,
  type NvdCve,
  type OsvRecord,
} from "@ichiji/core";
import type { CatalogRepo, WindowConfig } from "@ichiji/db";

/** 取り込むOSVのエコシステム（3-1・3-2） */
export const OSV_ECOSYSTEMS = ["npm", "PyPI", "RubyGems", "Packagist", "Go", "Debian", "Alpine"] as const;

export interface PipelineDeps {
  catalog: CatalogRepo;
  fetch: FetchLike;
  /** 原本をR2へ保存する。キーを返す */
  saveRaw: (key: string, body: string) => Promise<void>;
  sleep: (ms: number) => Promise<void>;
}

const sanitizeKey = (s: string) => s.replace(/[^A-Za-z0-9._:@-]/g, "_");

/**
 * OSV の更新一覧から、取り込むべきIDを返す。
 * - 悪性パッケージ（MAL-）は CVE ではないので除く
 * - 同じ更新日時で取り込み済みのものは除く
 */
export async function listOsvUpdates(deps: PipelineDeps, ecosystem: string, since: string, limit = 3000): Promise<{ ids: Array<{ id: string; modified: string }>; newest: string | null }> {
  const all = await fetchModifiedIds(ecosystem, new Date(since), deps.fetch, 50_000);
  const newest = all[0]?.modified ?? null;
  const candidates = all.filter((x) => !x.id.startsWith("MAL-"));
  const known = await deps.catalog.getOsvModified(candidates.map((c) => c.id));
  const ids = candidates.filter((c) => known.get(c.id) !== c.modified).slice(0, limit);
  return { ids, newest };
}

/** OSV のレコードを取得・原本保存・正規化して取り込む。触った正規IDを返す */
export async function ingestOsvRecords(deps: PipelineDeps, ecosystem: string, ids: Array<{ id: string; modified: string }>): Promise<string[]> {
  const touched: string[] = [];
  for (const { id } of ids) {
    const res = await deps.fetch(`${OSV_GCS}/${encodeURIComponent(ecosystem)}/${encodeURIComponent(id)}.json`);
    if (res.status === 404) continue;
    if (!res.ok) throw new Error(`OSV ${ecosystem}/${id} ${res.status}`);
    const text = await res.text();
    const record = JSON.parse(text) as OsvRecord;
    const n = normalizeOsv(record);
    // CVE番号のないもの、対象範囲のパッケージがないもの（カーネル等）はカタログに入れない
    if (!n.isCve || n.packages.every((p) => p.topic === null)) continue;
    const key = `osv/${sanitizeKey(ecosystem)}/${sanitizeKey(id)}@${sanitizeKey(record.modified)}.json`;
    await deps.saveRaw(key, text);
    touched.push(await deps.catalog.upsertOsv(n, key));
  }
  return touched;
}

/** NVD の1件を反映する。ウォッチリスト製品のCVEはカタログになくても作る */
async function applyNvdCve(deps: PipelineDeps, cve: NvdCve): Promise<boolean> {
  const cpes = extractWatchlistCpes(cve);
  const applied = await deps.catalog.applyNvd(cve, selectNvdCvss(cve), cpes, { createIfMissing: cpes.length > 0 });
  if (applied) await deps.saveRaw(`nvd/${sanitizeKey(cve.id)}@${sanitizeKey(cve.lastModified)}.json`, JSON.stringify(cve));
  return applied;
}

/** 初回：ウォッチリストの製品ごとに、掲載期間内に更新されたCVEを取る（9-2） */
export async function nvdBackfillWatchlist(deps: PipelineDeps, nvd: NvdClient, window: WindowConfig, productIndex: number): Promise<{ touched: string[]; done: boolean }> {
  const products = WATCHLIST.flatMap((p) => p.cpes);
  const vp = products[productIndex];
  if (!vp) return { touched: [], done: true };
  const touched: string[] = [];
  const start = new Date(window.windowStart);
  const end = new Date();
  let startIndex = 0;
  for (let page = 0; page < 10; page++) {
    const res = await nvd.byVirtualMatch(vp, start, end, startIndex);
    for (const v of res.vulnerabilities) if (await applyNvdCve(deps, v.cve)) touched.push(v.cve.id);
    startIndex += res.resultsPerPage;
    if (startIndex >= res.totalResults || res.resultsPerPage === 0) break;
    await deps.sleep(nvd.minIntervalMs);
  }
  return { touched, done: productIndex + 1 >= products.length };
}

/** 2回目以降：前回からの更新分を1ページ取る */
export async function nvdIncrementalPage(deps: PipelineDeps, nvd: NvdClient, since: Date, until: Date, startIndex: number): Promise<{ touched: string[]; nextIndex: number | null }> {
  const res = await nvd.modifiedBetween(since, until, startIndex, 1000);
  const touched: string[] = [];
  for (const v of res.vulnerabilities) if (await applyNvdCve(deps, v.cve)) touched.push(v.cve.id);
  const next = startIndex + res.resultsPerPage;
  return { touched, nextIndex: next < res.totalResults && res.resultsPerPage > 0 ? next : null };
}

/** NVD のCVSSをまだ確認していないカタログのCVEを個別に取る */
export async function nvdBacklog(deps: PipelineDeps, nvd: NvdClient, limit: number): Promise<string[]> {
  const ids = await deps.catalog.listNvdBacklog(limit);
  const touched: string[] = [];
  const checked: string[] = [];
  for (const [i, id] of ids.entries()) {
    if (i > 0) await deps.sleep(nvd.minIntervalMs);
    try {
      const res = await nvd.getCve(id);
      const cve = res.vulnerabilities[0]?.cve;
      if (cve && (await applyNvdCve(deps, cve))) touched.push(id);
      else checked.push(id);
    } catch {
      // NVD の一時的なエラーは次回に回す
      break;
    }
  }
  if (checked.length) await deps.catalog.markNvdChecked(checked);
  return touched;
}

export async function ingestKev(deps: PipelineDeps): Promise<string[]> {
  const entries = await fetchKev(deps.fetch);
  await deps.saveRaw(`kev/${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(entries));
  return deps.catalog.applyKev(entries);
}

export async function ingestEpss(deps: PipelineDeps, limit = 3000): Promise<string[]> {
  const ids = await deps.catalog.listCveIdsForEpss(limit);
  if (!ids.length) return [];
  const scores = await fetchEpss(ids, deps.fetch);
  await deps.saveRaw(`epss/${new Date().toISOString().slice(0, 13)}.json`, JSON.stringify(scores));
  await deps.catalog.applyEpss(scores, ids);
  return scores.map((s) => s.cveId);
}
