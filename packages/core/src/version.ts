/**
 * 数字ドット区切りのバージョン比較器（9-2）。
 * ミドルウェア・ランタイムのバージョン比較と、記事の影響範囲の正規化に使う。
 *
 * - `1.27.3` / `16.4` / `3.0.15` などは数字部分を左から比較（足りない桁は0）
 * - `1.1.1w`（OpenSSL）や `9.8p1`（OpenSSH）の英字の接尾辞は、数字部分が同じときだけ比べる
 * - `-rc1` `-beta` `alpha` などのプレリリースは正式版より前
 */
interface ParsedVersion {
  nums: number[];
  suffix: string;
  pre: boolean;
}

const PRE_RE = /^(?:[-_.~]?)(?:rc|alpha|beta|pre|preview|dev|a|b)\d*/i;

export function parseVersion(input: string): ParsedVersion | null {
  const v = input.trim().replace(/^v(?=\d)/i, "");
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(v);
  if (!m) return null;
  const nums = m[1]!.split(".").map((n) => Number.parseInt(n, 10));
  const suffix = (m[2] ?? "").trim();
  const pre = suffix.startsWith("-") || PRE_RE.test(suffix);
  return { nums, suffix, pre };
}

export function isComparableVersion(input: string): boolean {
  return parseVersion(input) !== null;
}

/** a < b なら負、a > b なら正、同じなら0。比較できない場合は文字列比較。 */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return a.localeCompare(b);
  const len = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i++) {
    const x = pa.nums[i] ?? 0;
    const y = pb.nums[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  if (pa.suffix === pb.suffix) return 0;
  // 接尾辞なし と プレリリース：プレリリースが前
  if (!pa.suffix) return pb.pre ? 1 : -1;
  if (!pb.suffix) return pa.pre ? -1 : 1;
  if (pa.pre !== pb.pre) return pa.pre ? -1 : 1;
  return pa.suffix.localeCompare(pb.suffix, "en", { numeric: true });
}

export function sortVersions(versions: Iterable<string>): string[] {
  return [...new Set(versions)].sort(compareVersions);
}

/** 影響範囲の1区間。境界は undefined なら無制限。 */
export interface VersionInterval {
  introduced?: string; // >=
  fixed?: string; // <
  lastAffected?: string; // <=
  exact?: string; // ==
}

export function intervalToString(iv: VersionInterval): string {
  if (iv.exact) return `=${iv.exact}`;
  const parts: string[] = [];
  if (iv.introduced && iv.introduced !== "0") parts.push(`>=${iv.introduced}`);
  if (iv.fixed) parts.push(`<${iv.fixed}`);
  else if (iv.lastAffected) parts.push(`<=${iv.lastAffected}`);
  if (parts.length === 0) return "*";
  return parts.join(" ");
}

/** 区間リストを正規の文字列にする。例：`>=4.0.0 <4.21.2 || >=5.0.0 <5.0.1` */
export function intervalsToRange(intervals: VersionInterval[]): string {
  const strs = [...new Set(intervals.map(intervalToString))];
  if (strs.includes("*")) return "*";
  return strs.sort(compareRangeStrings).join(" || ");
}

function firstBound(s: string): string {
  const m = /[\d][^\s]*/.exec(s);
  return m ? m[0] : "";
}

function compareRangeStrings(a: string, b: string): number {
  const ba = firstBound(a);
  const bb = firstBound(b);
  // 下限なし（`<x` だけ）の区間を先に
  const aOpen = !a.startsWith(">") && !a.startsWith("=");
  const bOpen = !b.startsWith(">") && !b.startsWith("=");
  if (aOpen !== bOpen) return aOpen ? -1 : 1;
  return compareVersions(ba, bb) || a.localeCompare(b);
}

/**
 * 範囲文字列を比較用に正規化する。空白・区切り・順序の揺れを吸収する。
 * `>= 4.0.0, < 4.21.2` → `>=4.0.0 <4.21.2`
 */
export function normalizeRange(range: string): string {
  const alternatives = range
    .split("||")
    .map((alt) =>
      alt
        .replace(/,/g, " ")
        .replace(/(>=|<=|>|<|==|=)\s+/g, "$1")
        .replace(/\bv(?=\d)/g, "")
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map((t) => t.replace(/^==/, "="))
        .sort((x, y) => {
          // 下限 → 上限 の順にそろえる
          const rank = (t: string) => (t.startsWith(">") ? 0 : t.startsWith("=") ? 1 : 2);
          return rank(x) - rank(y);
        })
        .join(" "),
    )
    .filter(Boolean);
  const unique = [...new Set(alternatives)];
  if (unique.includes("*")) return "*";
  return unique.sort(compareRangeStrings).join(" || ");
}

export function rangesEqual(a: string, b: string): boolean {
  return normalizeRange(a) === normalizeRange(b);
}

/** バージョンが区間に含まれるか（NVDのCPE範囲の判定に使う） */
export function inInterval(
  version: string,
  bounds: {
    exact?: string | null;
    startIncluding?: string | null;
    startExcluding?: string | null;
    endIncluding?: string | null;
    endExcluding?: string | null;
  },
): boolean {
  if (bounds.exact) return compareVersions(version, bounds.exact) === 0;
  if (bounds.startIncluding && compareVersions(version, bounds.startIncluding) < 0) return false;
  if (bounds.startExcluding && compareVersions(version, bounds.startExcluding) <= 0) return false;
  if (bounds.endIncluding && compareVersions(version, bounds.endIncluding) > 0) return false;
  if (bounds.endExcluding && compareVersions(version, bounds.endExcluding) >= 0) return false;
  return true;
}

/** 範囲文字列（intervalsToRange の出力）にバージョンが含まれるか */
export function satisfiesRange(version: string, range: string): boolean {
  const norm = normalizeRange(range);
  if (norm === "*") return true;
  return norm.split(" || ").some((alt) =>
    alt.split(" ").every((token) => {
      const m = /^(>=|<=|>|<|=)(.+)$/.exec(token);
      if (!m) return false;
      const cmp = compareVersions(version, m[2]!);
      switch (m[1]) {
        case ">=":
          return cmp >= 0;
        case ">":
          return cmp > 0;
        case "<=":
          return cmp <= 0;
        case "<":
          return cmp < 0;
        default:
          return cmp === 0;
      }
    }),
  );
}
