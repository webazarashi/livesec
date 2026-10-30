import {
  parseCycloneDx,
  parseStackYaml,
  resolveCdnScript,
  resolveMiddlewarePurl,
  getWatchlistProduct,
  type Stack,
  type StackIssue,
} from "@ichiji/core";
import type { ProjectPackageInput } from "./tenant";

export interface StackUpload {
  stackYaml: string;
  /** SBOMのパス（stack.yaml の components[].sbom）→ CycloneDX JSON の本文 */
  boms: Record<string, string>;
}

export interface StackBuildSummary {
  components: number;
  packages: number;
  devPackages: number;
  watched: number;
  cdn: number;
  skippedSbomComponents: number;
}

export type StackBuildResult =
  | { ok: true; stack: Stack; packages: ProjectPackageInput[]; warnings: StackIssue[]; summary: StackBuildSummary }
  | { ok: false; errors: StackIssue[] };

function findBom(boms: Record<string, string>, path: string): string | undefined {
  if (boms[path] !== undefined) return boms[path];
  const norm = (p: string) => p.replace(/^\.?\//, "");
  const hit = Object.keys(boms).find((k) => norm(k) === norm(path));
  if (hit) return boms[hit];
  const base = path.split("/").pop();
  const byBase = Object.keys(boms).filter((k) => k.split("/").pop() === base);
  return byBase.length === 1 ? boms[byBase[0]!] : undefined;
}

/**
 * stack.yaml ＋ bom.json（8章）から照合対象を作る。
 * - components[].sbom → CycloneDX から言語・OSパッケージ（OSVで照合）
 * - components[].image / middleware → ウォッチリスト（NVDのCPEで照合）
 * - components[].cdn_scripts → CDNの対応表からパッケージ（バージョン不明なら unknown）
 */
export function buildStackInput(upload: StackUpload): StackBuildResult {
  const parsed = parseStackYaml(upload.stackYaml);
  if (!parsed.ok) return { ok: false, errors: parsed.errors };
  const { stack } = parsed;
  const warnings: StackIssue[] = [...parsed.warnings];
  const errors: StackIssue[] = [];
  const packages: ProjectPackageInput[] = [];
  const summary: StackBuildSummary = { components: stack.components.length, packages: 0, devPackages: 0, watched: 0, cdn: 0, skippedSbomComponents: 0 };

  if (Object.keys(upload.boms).length === 0) {
    errors.push({ path: "bom", message: "SBOM（CycloneDX JSON）は必須です。少なくとも1つ添付してください" });
  }

  stack.components.forEach((c, i) => {
    const base = `components[${i}]`;
    if (c.sbom) {
      const text = findBom(upload.boms, c.sbom);
      if (text === undefined) {
        errors.push({ path: `${base}.sbom`, message: `SBOM「${c.sbom}」が添付されていません` });
      } else {
        const bom = parseCycloneDx(text);
        if (!bom.ok) {
          errors.push({ path: `${base}.sbom`, message: `SBOM「${c.sbom}」：${bom.error}` });
        } else {
          for (const p of bom.packages) {
            packages.push({
              component: c.name,
              kind: "package",
              ecosystem: p.ecosystem,
              name: p.name,
              version: p.version,
              purl: p.purl,
              isDev: p.isDev,
              source: "sbom",
              evidence: c.sbom,
            });
            summary.packages++;
            if (p.isDev) summary.devPackages++;
          }
          if (bom.packages.length === 0) {
            warnings.push({ path: `${base}.sbom`, message: "照合できるパッケージ（PURL付き）がありません" });
            summary.skippedSbomComponents++;
          }
        }
      }
    }

    const watchTargets = [
      ...(c.image ? [{ purl: c.image.purl, evidence: c.image.evidence, path: `${base}.image` }] : []),
      ...(c.middleware ?? []).map((m, j) => ({ purl: m.purl, evidence: m.evidence, path: `${base}.middleware[${j}]` })),
    ];
    for (const t of watchTargets) {
      const w = resolveMiddlewarePurl(t.purl);
      if (!w) {
        // コンテナイメージそのものはウォッチリスト外でも問題ない（OSパッケージはSBOMで照合する）
        if (!t.path.endsWith(".image")) {
          warnings.push({ path: t.path, message: `「${t.purl}」はウォッチリスト外のため照合しません` });
        }
        continue;
      }
      packages.push({
        component: c.name,
        kind: "watch",
        ecosystem: "watchlist",
        name: w.productKey,
        version: w.version,
        purl: t.purl,
        isDev: false,
        source: w.source,
        evidence: t.evidence ?? null,
      });
      summary.watched++;
      if (!w.version) {
        warnings.push({
          path: t.path,
          message: `${getWatchlistProduct(w.productKey)?.label ?? w.productKey} のバージョンが unknown です。該当する脆弱性はB固定で通知します`,
        });
      }
    }

    (c.cdn_scripts ?? []).forEach((s, j) => {
      const r = resolveCdnScript(s.url);
      if (!r) {
        warnings.push({ path: `${base}.cdn_scripts[${j}]`, message: `「${s.url}」は対応表にないため照合しません` });
        return;
      }
      packages.push({
        component: c.name,
        kind: "package",
        ecosystem: r.ecosystem,
        name: r.name,
        version: r.version,
        purl: s.url,
        isDev: false,
        source: "cdn",
        evidence: s.evidence ?? null,
      });
      summary.cdn++;
      if (!r.version) {
        warnings.push({
          path: `${base}.cdn_scripts[${j}]`,
          message: `${r.label} は常に最新版を読み込むURLのためバージョンを特定できません。該当する脆弱性はB固定で通知します`,
        });
      }
    });
  });

  if (errors.length) return { ok: false, errors };
  return { ok: true, stack, packages, warnings, summary };
}
