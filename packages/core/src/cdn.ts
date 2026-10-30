/**
 * CDN の <script> で読み込むライブラリ（SBOMに出ない）を PURL に対応づける（3-4）。
 * stack.yaml の components[].cdn_scripts に書かれた URL を判定する。
 */
export interface CdnResolution {
  ecosystem: string;
  name: string;
  /** null は unknown（edge/2 のように常に最新を読み込む場合など）→ B固定 */
  version: string | null;
  label: string;
}

const PATTERNS: Array<{ re: RegExp; ecosystem: string; name: string; label: string; version: (m: RegExpExecArray) => string | null }> = [
  // https://static.line-scdn.net/liff/edge/versions/2.22.3/sdk.js
  {
    re: /^https:\/\/static\.line-scdn\.net\/liff\/edge\/versions\/(\d+\.\d+\.\d+)\/sdk(?:\.\w+)?\.js/i,
    ecosystem: "npm",
    name: "@line/liff",
    label: "LIFF SDK",
    version: (m) => m[1] ?? null,
  },
  // https://static.line-scdn.net/liff/edge/2/sdk.js（常に v2 の最新）
  {
    re: /^https:\/\/static\.line-scdn\.net\/liff\/edge\/\d+(?:\.\d+)?\/sdk(?:\.\w+)?\.js/i,
    ecosystem: "npm",
    name: "@line/liff",
    label: "LIFF SDK",
    version: () => null,
  },
  // https://cdn.jsdelivr.net/npm/<pkg>@<version>/...  /  https://unpkg.com/<pkg>@<version>/...
  {
    re: /^https:\/\/(?:cdn\.jsdelivr\.net\/npm|unpkg\.com)\/((?:@[^/@]+\/)?[^/@]+)(?:@([^/]+))?/i,
    ecosystem: "npm",
    name: "",
    label: "",
    version: (m) => (m[2] && /^\d+\.\d+\.\d+/.test(m[2]) ? m[2] : null),
  },
];

export function resolveCdnScript(url: string): CdnResolution | null {
  for (const p of PATTERNS) {
    const m = p.re.exec(url);
    if (!m) continue;
    const name = p.name || decodeURIComponent(m[1] ?? "");
    if (!name) continue;
    return { ecosystem: p.ecosystem, name, version: p.version(m), label: p.label || name };
  }
  return null;
}
