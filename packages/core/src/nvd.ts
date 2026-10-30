import type { CvssFact } from "./facts";
import type { FetchLike } from "./osv";
import { watchlistProductForCpe, cpeVersion, type CpeRange } from "./watchlist";

/** NVD API 2.0（必要な部分のみ） */
export interface NvdCvssMetric {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: { version: string; baseScore: number; vectorString: string; baseSeverity?: string };
}

export interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus?: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV40?: NvdCvssMetric[];
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
  };
  configurations?: Array<{
    nodes: Array<{
      operator?: string;
      negate?: boolean;
      cpeMatch?: Array<{
        vulnerable: boolean;
        criteria: string;
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      }>;
    }>;
  }>;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  cisaExploitAdd?: string;
}

export interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{ cve: NvdCve }>;
}

function pickMetric(list: NvdCvssMetric[] | undefined): { metric: NvdCvssMetric; source: "nvd" | "cna" } | null {
  if (!list?.length) return null;
  const primary = list.find((m) => m.type === "Primary");
  if (primary) return { metric: primary, source: "nvd" };
  return { metric: list[0]!, source: "cna" };
}

/**
 * CVSS（7-2）：NVDの基本値。v3.1を優先し、なければv4.0。
 * どちらもないときは v3.0 を使い、それもなければ null（呼び出し側でGHSAの深刻度で代用する）。
 */
export function selectNvdCvss(cve: NvdCve): CvssFact | null {
  const picked =
    pickMetric(cve.metrics?.cvssMetricV31) ?? pickMetric(cve.metrics?.cvssMetricV40) ?? pickMetric(cve.metrics?.cvssMetricV30);
  if (!picked) return null;
  return {
    score: picked.metric.cvssData.baseScore,
    version: picked.metric.cvssData.version,
    source: picked.source,
    vector: picked.metric.cvssData.vectorString ?? null,
  };
}

export interface WatchlistCpeMatch extends CpeRange {
  productKey: string;
  criteria: string;
}

/** 構成情報からウォッチリスト製品の脆弱なCPE範囲を取り出す */
export function extractWatchlistCpes(cve: NvdCve): WatchlistCpeMatch[] {
  const out: WatchlistCpeMatch[] = [];
  for (const conf of cve.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      if (node.negate) continue;
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable) continue;
        const product = watchlistProductForCpe(m.criteria);
        if (!product) continue;
        const exact = cpeVersion(m.criteria);
        out.push({
          productKey: product.key,
          criteria: m.criteria,
          exact: exact && !m.versionStartIncluding && !m.versionEndExcluding && !m.versionEndIncluding && !m.versionStartExcluding ? exact : null,
          startIncluding: m.versionStartIncluding ?? null,
          startExcluding: m.versionStartExcluding ?? null,
          endIncluding: m.versionEndIncluding ?? null,
          endExcluding: m.versionEndExcluding ?? null,
        });
      }
    }
  }
  return out;
}

export const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export class NvdClient {
  constructor(
    private readonly apiKey: string | undefined,
    private readonly fetchFn: FetchLike = (input, init) => fetch(input, init),
  ) {}

  /** APIキーなしは30秒に5回、ありは30秒に50回まで */
  get minIntervalMs(): number {
    return this.apiKey ? 700 : 6500;
  }

  async query(params: Record<string, string>): Promise<NvdResponse> {
    const url = `${NVD_API}?${new URLSearchParams(params).toString()}`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.apiKey) headers.apiKey = this.apiKey;
    const res = await this.fetchFn(url, { headers });
    if (!res.ok) throw new Error(`NVD ${res.status}: ${url}`);
    return (await res.json()) as NvdResponse;
  }

  getCve(cveId: string): Promise<NvdResponse> {
    return this.query({ cveId });
  }

  /** 最終更新日時の範囲で取得（範囲は最大120日） */
  modifiedBetween(start: Date, end: Date, startIndex = 0, resultsPerPage = 1000): Promise<NvdResponse> {
    return this.query({
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
      startIndex: String(startIndex),
      resultsPerPage: String(resultsPerPage),
    });
  }

  /** CPE（vendor:product）で絞り込んで取得 */
  byVirtualMatch(vendorProduct: string, start: Date, end: Date, startIndex = 0): Promise<NvdResponse> {
    return this.query({
      virtualMatchString: `cpe:2.3:*:${vendorProduct}`,
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
      startIndex: String(startIndex),
      resultsPerPage: "2000",
    });
  }
}
