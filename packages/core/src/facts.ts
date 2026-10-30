import type { Rank } from "./scoring";
import { compareVersions, normalizeRange, sortVersions } from "./version";

/** 影響パッケージごとの事実 */
export interface PackageFact {
  /** バージョンなしのPURL（MWウォッチリストは pkg:generic/<key>） */
  purl: string;
  ecosystem: string;
  name: string;
  /** 正規化した影響範囲。例：`>=4.0.0 <4.21.2` */
  affected: string;
  fixed: string[];
}

export interface CvssFact {
  score: number;
  /** "3.1" | "4.0" | "3.0"。GHSA の代用値は null */
  version: string | null;
  /** nvd = NVD(Primary) / cna = NVD上のCNAスコア / ghsa = GHSA深刻度の代用値 */
  source: "nvd" | "cna" | "ghsa";
  vector: string | null;
}

/**
 * 機械照合済みの事実データ（5-3 の8、6-5、10-2）。
 * 記事ページの「事実データ」ブロックはこれをDBから表示する。
 */
export interface VulnFacts {
  id: string;
  aliases: string[];
  packages: PackageFact[];
  cvss: CvssFact | null;
  epss: number | null;
  epssPercentile: number | null;
  kev: boolean;
  kevAddedAt: string | null;
  poc: boolean;
  rank: Rank;
  rankReasons: string[];
  publishedAt: string | null;
  modifiedAt: string | null;
  references: Array<{ url: string; tags: string[] }>;
}

/** 記事の `affected` に入れる正規の文字列。パッケージが1つなら範囲だけ、複数なら `purl 範囲; purl 範囲` */
export function factsAffected(packages: PackageFact[]): string {
  if (packages.length === 0) return "";
  const ranges = [...new Set(packages.map((p) => normalizeRange(p.affected)))];
  if (ranges.length === 1) return ranges[0]!;
  return [...packages]
    .sort((a, b) => a.purl.localeCompare(b.purl))
    .map((p) => `${p.purl} ${normalizeRange(p.affected)}`)
    .join("; ");
}

export function factsFixed(packages: PackageFact[]): string[] {
  return sortVersions(packages.flatMap((p) => p.fixed));
}

/** 比較用に `affected` を正規化（パッケージ付きの形式にも対応） */
export function normalizeAffected(value: string): string {
  const parts = value
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length <= 1 && !value.trim().startsWith("pkg:")) return normalizeRange(value);
  return parts
    .map((part) => {
      const m = /^(pkg:\S+)\s+(.*)$/.exec(part);
      if (!m) return normalizeRange(part);
      return `${m[1]!.toLowerCase()} ${normalizeRange(m[2]!)}`;
    })
    .sort()
    .join("; ");
}

/** 複数CVEをまとめた記事用に事実を合成する */
export function combineFacts(list: VulnFacts[]): { packages: string[]; affected: string; fixed: string[]; cvss: number | null } {
  const packages = [...new Set(list.flatMap((f) => f.packages.map((p) => p.purl)))].sort();
  const affected =
    list.length === 1
      ? factsAffected(list[0]!.packages)
      : [...new Set(list.map((f) => factsAffected(f.packages)))].join("; ");
  const fixed = sortVersions(list.flatMap((f) => factsFixed(f.packages)));
  const scores = list.map((f) => f.cvss?.score).filter((s): s is number => typeof s === "number");
  return { packages, affected, fixed, cvss: scores.length ? Math.max(...scores) : null };
}

/**
 * 記事の再生成が必要かを判定するためのハッシュ（10-1 の5）。
 * 記事本文に影響する事実（影響範囲・修正版・CVSS・KEV）だけを対象にする。EPSSの日々の変動では立てない。
 */
export function factsHash(facts: Pick<VulnFacts, "id" | "packages" | "cvss" | "kev">): string {
  const payload = JSON.stringify({
    id: facts.id,
    packages: [...facts.packages]
      .map((p) => ({ purl: p.purl, affected: normalizeRange(p.affected), fixed: sortVersions(p.fixed) }))
      .sort((a, b) => a.purl.localeCompare(b.purl)),
    cvss: facts.cvss?.score ?? null,
    kev: facts.kev,
  });
  return fnv1a64(payload);
}

export function fnv1a64(input: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const bytes = new TextEncoder().encode(input);
  for (const b of bytes) {
    h ^= BigInt(b);
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, "0");
}

export function cvssSourceLabel(cvss: CvssFact): string {
  return cvss.source === "ghsa" ? "GHSA深刻度からの代用値" : cvss.source === "cna" ? `CVSS v${cvss.version}・CNA` : `CVSS v${cvss.version}`;
}

export function cvssLabel(cvss: CvssFact | null): string {
  if (!cvss) return "未算出";
  return `${cvss.score.toFixed(1)}（${cvssSourceLabel(cvss)}）`;
}

export function severityLabel(score: number | null | undefined): string {
  if (score == null) return "不明";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "None";
}

export function latestFixed(facts: Pick<VulnFacts, "packages">): string | null {
  const all = factsFixed(facts.packages);
  return all.length ? all.sort(compareVersions)[all.length - 1]! : null;
}
