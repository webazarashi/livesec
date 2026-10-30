import type { ArticleFrontMatter } from "./article";
import { combineFacts, normalizeAffected, type VulnFacts } from "./facts";
import { purlWithoutVersion } from "./purl";
import { sortVersions } from "./version";

export interface GateMismatch {
  field: "cve_ids" | "affected" | "fixed" | "cvss" | "packages" | "topic";
  expected: string;
  actual: string;
  message: string;
}

export interface GateResult {
  ok: boolean;
  mismatches: GateMismatch[];
}

/**
 * 機械照合ゲート（10-2）。
 * 記事中のCVE番号・影響バージョン・修正版・CVSSをソースデータと突き合わせ、1つでも不一致なら公開しない。
 *
 * @param facts cve_ids に対応するカタログの事実。見つからないCVEは含めない
 */
export function verifyArticle(fm: Pick<ArticleFrontMatter, "cve_ids" | "affected" | "fixed" | "cvss" | "packages">, facts: VulnFacts[]): GateResult {
  const mismatches: GateMismatch[] = [];
  const found = new Set(facts.map((f) => f.id));
  const missing = fm.cve_ids.filter((id) => !found.has(id));
  if (missing.length) {
    mismatches.push({
      field: "cve_ids",
      expected: "カタログに存在するCVE番号",
      actual: missing.join(", "),
      message: `カタログにないCVE番号です：${missing.join(", ")}`,
    });
    return { ok: false, mismatches };
  }
  if (new Set(fm.cve_ids).size !== fm.cve_ids.length) {
    mismatches.push({ field: "cve_ids", expected: "重複なし", actual: fm.cve_ids.join(", "), message: "CVE番号が重複しています" });
  }

  const ordered = fm.cve_ids.map((id) => facts.find((f) => f.id === id)!);
  const expected = combineFacts(ordered);

  if (normalizeAffected(fm.affected) !== normalizeAffected(expected.affected)) {
    mismatches.push({
      field: "affected",
      expected: expected.affected,
      actual: fm.affected,
      message: "影響バージョンがソースデータと一致しません",
    });
  }

  const fixedActual = sortVersions(fm.fixed.map((v) => v.trim().replace(/^v(?=\d)/, "")));
  const fixedExpected = sortVersions(expected.fixed.map((v) => v.replace(/^v(?=\d)/, "")));
  if (fixedActual.join("\n") !== fixedExpected.join("\n")) {
    mismatches.push({
      field: "fixed",
      expected: fixedExpected.join(", ") || "（なし）",
      actual: fixedActual.join(", ") || "（なし）",
      message: "修正版がソースデータと一致しません",
    });
  }

  if (expected.cvss === null ? fm.cvss !== null : fm.cvss === null || Math.abs(fm.cvss - expected.cvss) > 0.05) {
    mismatches.push({
      field: "cvss",
      expected: expected.cvss === null ? "null（未算出）" : expected.cvss.toFixed(1),
      actual: fm.cvss === null ? "null" : String(fm.cvss),
      message: "CVSSがソースデータと一致しません",
    });
  }

  const expectedPkgs = new Set(expected.packages.map((p) => purlWithoutVersion(p).toLowerCase()));
  const unknownPkgs = fm.packages.filter((p) => !expectedPkgs.has(purlWithoutVersion(p).toLowerCase()));
  if (unknownPkgs.length) {
    mismatches.push({
      field: "packages",
      expected: [...expectedPkgs].join(", "),
      actual: fm.packages.join(", "),
      message: `ソースデータにないパッケージがあります：${unknownPkgs.join(", ")}`,
    });
  }

  return { ok: mismatches.length === 0, mismatches };
}
