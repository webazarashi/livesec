import { parsePurl, purlToOsv } from "./purl";

/** SBOM から抽出したパッケージ（照合の入力） */
export interface SbomPackage {
  purl: string;
  ecosystem: string;
  name: string;
  version: string;
  isDev: boolean;
}

export type SbomParseResult =
  | { ok: true; packages: SbomPackage[]; skipped: number; total: number }
  | { ok: false; error: string };

interface CdxComponent {
  purl?: unknown;
  scope?: unknown;
  properties?: unknown;
  components?: unknown;
}

const DEV_PROPERTY_RE = /(?:^|:)(?:development|dev|devDependency|dev_dependency)$/i;

function isDevComponent(c: CdxComponent): boolean {
  // cdxgen は開発用依存を scope: optional にし、cdx:npm:package:development などのプロパティを付ける
  if (c.scope === "optional" || c.scope === "excluded") return true;
  if (Array.isArray(c.properties)) {
    for (const p of c.properties as Array<{ name?: unknown; value?: unknown }>) {
      if (typeof p?.name === "string" && DEV_PROPERTY_RE.test(p.name) && String(p.value).toLowerCase() === "true") {
        return true;
      }
    }
  }
  return false;
}

const MAX_COMPONENTS = 100_000;

/**
 * CycloneDX JSON（bom.json）からPURLを抽出する。
 * ネストした components も辿る。照合対象（OSVのエコシステム）以外のPURLは数だけ数えて捨てる。
 */
export function parseCycloneDx(input: string | unknown): SbomParseResult {
  let doc: unknown = input;
  if (typeof input === "string") {
    try {
      doc = JSON.parse(input);
    } catch {
      return { ok: false, error: "JSONとして読めません" };
    }
  }
  if (!doc || typeof doc !== "object") return { ok: false, error: "CycloneDX JSON ではありません" };
  const bom = doc as { bomFormat?: unknown; specVersion?: unknown; components?: unknown };
  if (bom.bomFormat !== "CycloneDX") return { ok: false, error: 'bomFormat が "CycloneDX" ではありません' };
  if (typeof bom.specVersion !== "string") return { ok: false, error: "specVersion がありません" };

  const byKey = new Map<string, SbomPackage>();
  let total = 0;
  let skipped = 0;
  const stack: CdxComponent[] = Array.isArray(bom.components) ? [...(bom.components as CdxComponent[])] : [];
  while (stack.length) {
    const c = stack.pop()!;
    total++;
    if (total > MAX_COMPONENTS) return { ok: false, error: `components が多すぎます（${MAX_COMPONENTS}件まで）` };
    if (Array.isArray(c.components)) stack.push(...(c.components as CdxComponent[]));
    if (typeof c.purl !== "string") {
      skipped++;
      continue;
    }
    const purl = parsePurl(c.purl);
    const osv = purl ? purlToOsv(purl) : null;
    if (!purl || !osv || !osv.version) {
      skipped++;
      continue;
    }
    const pkg: SbomPackage = {
      purl: c.purl,
      ecosystem: osv.ecosystem,
      name: osv.name,
      version: osv.version,
      isDev: isDevComponent(c),
    };
    const key = `${pkg.ecosystem}\u0000${pkg.name}\u0000${pkg.version}`;
    const prev = byKey.get(key);
    // 同じパッケージが本番依存にも開発依存にも出る場合は本番扱い
    if (!prev) byKey.set(key, pkg);
    else if (prev.isDev && !pkg.isDev) byKey.set(key, pkg);
  }
  return { ok: true, packages: [...byKey.values()], skipped, total };
}
