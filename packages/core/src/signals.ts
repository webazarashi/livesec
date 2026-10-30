import type { FetchLike } from "./osv";

/** CISA KEV（7-2） */
export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export interface KevEntry {
  cveId: string;
  dateAdded: string;
}

export async function fetchKev(fetchFn: FetchLike = (i, init) => fetch(i, init)): Promise<KevEntry[]> {
  const res = await fetchFn(KEV_URL);
  if (!res.ok) throw new Error(`CISA KEV ${res.status}`);
  return parseKev(await res.json());
}

export function parseKev(json: unknown): KevEntry[] {
  const list = (json as { vulnerabilities?: Array<{ cveID?: string; dateAdded?: string }> })?.vulnerabilities ?? [];
  return list
    .filter((v) => typeof v.cveID === "string")
    .map((v) => ({ cveId: v.cveID!, dateAdded: v.dateAdded ?? "" }));
}

/** FIRST EPSS（7-2） */
export const EPSS_API = "https://api.first.org/data/v1/epss";
export const EPSS_BATCH = 100;

export interface EpssScore {
  cveId: string;
  epss: number;
  percentile: number;
  date: string;
}

export async function fetchEpss(cveIds: string[], fetchFn: FetchLike = (i, init) => fetch(i, init)): Promise<EpssScore[]> {
  const out: EpssScore[] = [];
  for (let i = 0; i < cveIds.length; i += EPSS_BATCH) {
    const batch = cveIds.slice(i, i + EPSS_BATCH);
    const res = await fetchFn(`${EPSS_API}?cve=${batch.join(",")}&limit=${EPSS_BATCH}`);
    if (!res.ok) throw new Error(`EPSS ${res.status}`);
    out.push(...parseEpss(await res.json()));
  }
  return out;
}

export function parseEpss(json: unknown): EpssScore[] {
  const data = (json as { data?: Array<{ cve: string; epss: string; percentile: string; date: string }> })?.data ?? [];
  return data.map((d) => ({
    cveId: d.cve,
    epss: Number.parseFloat(d.epss),
    percentile: Number.parseFloat(d.percentile),
    date: d.date,
  }));
}

/**
 * PoC（7-2）：参照URLに exploit タグが付いたもの、または Exploit-DB・Metasploit 等へのリンクがある。
 */
const POC_URL_PATTERNS: RegExp[] = [
  /(?:^|\/\/)(?:www\.)?exploit-db\.com\//i,
  /packetstormsecurity\.(?:com|org)\/files\//i,
  /packetstorm\.news\//i,
  /github\.com\/rapid7\/metasploit-framework\//i,
  /rapid7\.com\/db\/modules\//i,
  /github\.com\/projectdiscovery\/nuclei-templates\//i,
];

export function hasPoc(references: Array<{ url: string; tags?: string[] }>): boolean {
  return references.some(
    (r) => (r.tags ?? []).some((t) => t.toLowerCase() === "exploit") || POC_URL_PATTERNS.some((re) => re.test(r.url)),
  );
}
