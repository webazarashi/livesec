import { isTargetEcosystem, topicForPackage, type TopicKey } from "./topics";
import { osvToPurl } from "./purl";
import { intervalsToRange, sortVersions, type VersionInterval } from "./version";
import type { PackageFact } from "./facts";

/** OSV スキーマ（必要な部分のみ）https://ossf.github.io/osv-schema/ */
export interface OsvRecord {
  id: string;
  modified: string;
  published?: string;
  withdrawn?: string;
  aliases?: string[];
  upstream?: string[];
  related?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string; purl?: string };
    ranges?: Array<{ type: string; events: Array<Record<string, string>> }>;
    versions?: string[];
    database_specific?: Record<string, unknown>;
  }>;
  references?: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string; [k: string]: unknown };
}

export interface NormalizedOsv {
  osvId: string;
  /** 正規ID。CVE番号があればCVE、なければOSVのID */
  vulnId: string;
  isCve: boolean;
  aliases: string[];
  summary: string | null;
  publishedAt: string | null;
  modifiedAt: string;
  withdrawn: boolean;
  ghsaSeverity: string | null;
  cvssVector: string | null;
  packages: Array<PackageFact & { topic: TopicKey | null }>;
  references: Array<{ url: string; tags: string[] }>;
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const PREFIXED_CVE_RE = /^(?:DEBIAN|ALPINE|UBUNTU|DLA|PSF|GO|PYSEC)-?.*?(CVE-\d{4}-\d{4,})$/;

export function isCveId(id: string): boolean {
  return CVE_RE.test(id);
}

/** OSV のIDと別名から正規のCVE番号を決める */
export function canonicalVulnId(record: Pick<OsvRecord, "id" | "aliases" | "upstream">): { id: string; isCve: boolean } {
  if (isCveId(record.id)) return { id: record.id, isCve: true };
  const alias = [...(record.aliases ?? []), ...(record.upstream ?? [])].find(isCveId);
  if (alias) return { id: alias, isCve: true };
  const m = PREFIXED_CVE_RE.exec(record.id);
  if (m) return { id: m[1]!, isCve: true };
  return { id: record.id, isCve: false };
}

function rangeToIntervals(events: Array<Record<string, string>>): VersionInterval[] {
  const out: VersionInterval[] = [];
  let current: VersionInterval | null = null;
  for (const ev of events) {
    if (ev.introduced !== undefined) {
      if (current) out.push(current);
      current = { introduced: ev.introduced };
    } else if (ev.fixed !== undefined) {
      out.push({ ...(current ?? { introduced: "0" }), fixed: ev.fixed });
      current = null;
    } else if (ev.last_affected !== undefined) {
      out.push({ ...(current ?? { introduced: "0" }), lastAffected: ev.last_affected });
      current = null;
    } else if (ev.limit !== undefined) {
      out.push({ ...(current ?? { introduced: "0" }), fixed: ev.limit });
      current = null;
    }
  }
  if (current) out.push(current);
  return out;
}

export function normalizeOsv(record: OsvRecord): NormalizedOsv {
  const { id: vulnId, isCve } = canonicalVulnId(record);
  const aliases = [...new Set([record.id, ...(record.aliases ?? []), ...(record.upstream ?? [])])].filter((a) => a !== vulnId);

  const byKey = new Map<string, PackageFact & { topic: TopicKey | null; intervals: VersionInterval[] }>();
  for (const a of record.affected ?? []) {
    const pkg = a.package;
    if (!pkg?.ecosystem || !pkg.name || !isTargetEcosystem(pkg.ecosystem)) continue;
    const key = `${pkg.ecosystem}\u0000${pkg.name}`;
    const entry =
      byKey.get(key) ??
      ({
        purl: osvToPurl(pkg.ecosystem, pkg.name),
        ecosystem: pkg.ecosystem,
        name: pkg.name,
        affected: "",
        fixed: [],
        topic: topicForPackage(pkg.ecosystem, pkg.name),
        intervals: [],
      } satisfies PackageFact & { topic: TopicKey | null; intervals: VersionInterval[] });
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      const ivs = rangeToIntervals(r.events ?? []);
      entry.intervals.push(...ivs);
      for (const iv of ivs) if (iv.fixed) entry.fixed.push(iv.fixed);
    }
    if (!a.ranges?.some((r) => r.type !== "GIT") && a.versions?.length) {
      entry.intervals.push(...a.versions.map((v) => ({ exact: v })));
    }
    byKey.set(key, entry);
  }

  const packages = [...byKey.values()].map(({ intervals, ...p }) => ({
    ...p,
    affected: intervals.length ? intervalsToRange(intervals) : "*",
    fixed: sortVersions(p.fixed),
  }));

  const cvss = record.severity?.find((s) => s.type === "CVSS_V3") ?? record.severity?.find((s) => s.type === "CVSS_V4");
  const ghsaSeverity =
    record.id.startsWith("GHSA-") && typeof record.database_specific?.severity === "string"
      ? record.database_specific.severity.toUpperCase()
      : null;

  return {
    osvId: record.id,
    vulnId,
    isCve,
    aliases,
    summary: record.summary ?? null,
    publishedAt: record.published ?? null,
    modifiedAt: record.modified,
    withdrawn: Boolean(record.withdrawn),
    ghsaSeverity,
    cvssVector: cvss?.score ?? null,
    packages,
    references: (record.references ?? []).map((r) => ({ url: r.url, tags: r.type ? [r.type] : [] })),
  };
}

// ---- OSV API クライアント ----

export const OSV_API = "https://api.osv.dev";
export const OSV_GCS = "https://osv-vulnerabilities.storage.googleapis.com";

export interface OsvQuery {
  package: { ecosystem: string; name: string };
  version: string;
}

export interface OsvBatchResult {
  vulns?: Array<{ id: string; modified: string }>;
  next_page_token?: string;
}

/** querybatch は1回最大1000件（9-1） */
export const OSV_BATCH_LIMIT = 1000;

export interface FetchLike {
  (input: string, init?: RequestInit): Promise<Response>;
}

async function withRetry<T>(fn: () => Promise<T>, attempts = 3, baseDelayMs = 1000): Promise<T> {
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, baseDelayMs * 2 ** i));
    }
  }
  throw last;
}

export class OsvClient {
  constructor(
    private readonly fetchFn: FetchLike = (input, init) => fetch(input, init),
    private readonly base = OSV_API,
  ) {}

  /** querybatch。ページングされた結果は追加で取りに行く */
  async queryBatch(queries: OsvQuery[]): Promise<Array<Array<{ id: string; modified: string }>>> {
    if (queries.length > OSV_BATCH_LIMIT) throw new Error(`querybatch は${OSV_BATCH_LIMIT}件までです`);
    const results: Array<Array<{ id: string; modified: string }>> = queries.map(() => []);
    let pending = queries.map((q, i) => ({ q, i, token: undefined as string | undefined }));
    for (let round = 0; pending.length && round < 10; round++) {
      const body = { queries: pending.map(({ q, token }) => (token ? { ...q, page_token: token } : q)) };
      const json = await withRetry(async () => {
        const res = await this.fetchFn(`${this.base}/v1/querybatch`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        if (!res.ok) throw new Error(`OSV querybatch ${res.status}`);
        return (await res.json()) as { results: OsvBatchResult[] };
      });
      const next: typeof pending = [];
      json.results.forEach((r, idx) => {
        const p = pending[idx]!;
        results[p.i]!.push(...(r.vulns ?? []));
        if (r.next_page_token) next.push({ ...p, token: r.next_page_token });
      });
      pending = next;
    }
    return results;
  }

  async getVuln(id: string): Promise<OsvRecord | null> {
    return withRetry(async () => {
      const res = await this.fetchFn(`${this.base}/v1/vulns/${encodeURIComponent(id)}`);
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`OSV vulns/${id} ${res.status}`);
      return (await res.json()) as OsvRecord;
    });
  }
}

/**
 * OSV の GCS にある `{ecosystem}/modified_id.csv`（更新日時の新しい順）を読み、
 * `since` より新しいIDを返す。大きなファイルなので、古い行に達したらストリームを止める。
 */
export async function fetchModifiedIds(
  ecosystem: string,
  since: Date,
  fetchFn: FetchLike = (input, init) => fetch(input, init),
  limit = 20_000,
): Promise<Array<{ id: string; modified: string }>> {
  const res = await fetchFn(`${OSV_GCS}/${encodeURIComponent(ecosystem)}/modified_id.csv`);
  if (!res.ok || !res.body) throw new Error(`OSV modified_id.csv(${ecosystem}) ${res.status}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const out: Array<{ id: string; modified: string }> = [];
  let buf = "";
  let done = false;
  while (!done) {
    const chunk = await reader.read();
    if (chunk.done) {
      done = true;
      buf += decoder.decode();
    } else {
      buf += decoder.decode(chunk.value, { stream: true });
    }
    const lines = buf.split("\n");
    buf = done ? "" : lines.pop()!;
    for (const line of lines) {
      const [modified, rawId] = line.trim().split(",");
      if (!modified || !rawId) continue;
      if (new Date(modified) <= since || out.length >= limit) {
        done = true;
        break;
      }
      // 一部のエコシステムは `ecosystem/ID` の形式
      const id = rawId.includes("/") ? rawId.slice(rawId.lastIndexOf("/") + 1) : rawId;
      out.push({ id, modified });
    }
  }
  await reader.cancel().catch(() => {});
  return out;
}

/** 照合結果のキャッシュから差分を出す（前回結果との差分 ＝ 新たに該当したCVE） */
export function diffIds(previous: Iterable<string>, current: Iterable<string>): { added: string[]; removed: string[] } {
  const prev = new Set(previous);
  const cur = new Set(current);
  return {
    added: [...cur].filter((id) => !prev.has(id)),
    removed: [...prev].filter((id) => !cur.has(id)),
  };
}
