import { escapeHtml } from "./markdown";
import type { Rank } from "./scoring";
import { SITE } from "./site";

export interface CoverInput {
  cveId: string;
  packageLabel: string;
  headline: string;
  topicLabel: string;
  rank: Rank;
  fixed: string | null;
}

const RANK_COLORS: Record<Rank, { bg: string; fg: string; label: string }> = {
  S: { bg: "#b42318", fg: "#ffffff", label: "今すぐ対応" },
  A: { bg: "#c4540a", fg: "#ffffff", label: "24時間以内" },
  B: { bg: "#a37b00", fg: "#ffffff", label: "次の定期保守" },
  C: { bg: "#52606d", fg: "#ffffff", label: "記録のみ" },
};

function wrap(text: string, perLine: number, maxLines: number): string[] {
  const chars = [...text];
  const lines: string[] = [];
  for (let i = 0; i < chars.length && lines.length < maxLines; i += perLine) {
    lines.push(chars.slice(i, i + perLine).join(""));
  }
  if (chars.length > perLine * maxLines) {
    const last = [...lines[maxLines - 1]!];
    lines[maxLines - 1] = `${last.slice(0, -1).join("")}…`;
  }
  return lines;
}

/**
 * 記事のカバー画像（5-3 の5）。CVE番号・トピック・緊急度入りのテンプレートから生成する。1200×630。
 */
export function renderCoverSvg(input: CoverInput): string {
  const rank = RANK_COLORS[input.rank];
  const headline = wrap(input.headline, 22, 2);
  const badgeText = `緊急度 ${input.rank}｜${rank.label}`;
  // 全角は30px、半角は約17pxとして幅を見積もる
  const badgeWidth = 48 + [...badgeText].reduce((w, ch) => w + (/[\x20-\x7e]/.test(ch) ? 17 : 30), 0);
  const e = escapeHtml;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="${e(`${input.cveId} ${input.headline}`)}">
  <defs>
    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M40 0H0V40" fill="none" stroke="#1d3b4a" stroke-width="1"/>
    </pattern>
  </defs>
  <rect width="1200" height="630" fill="#0f2430"/>
  <rect width="1200" height="630" fill="url(#grid)" opacity="0.55"/>
  <rect x="0" y="0" width="12" height="630" fill="#2f8f6b"/>
  <g font-family="'Noto Sans JP','Hiragino Sans','Yu Gothic',sans-serif" fill="#e8f1ee">
    <text x="72" y="96" font-size="30" font-weight="700" letter-spacing="2">${e(SITE.name)}</text>
    <rect x="860" y="62" width="268" height="48" rx="24" fill="none" stroke="#5fb894" stroke-width="2"/>
    <text x="994" y="95" font-size="24" text-anchor="middle" fill="#9fd9c0">${e(input.topicLabel)}</text>
    <text x="72" y="200" font-size="34" fill="#9fd9c0" font-family="ui-monospace,Menlo,monospace">${e(input.packageLabel)}</text>
    <text x="72" y="290" font-size="84" font-weight="800" font-family="ui-monospace,Menlo,monospace">${e(input.cveId)}</text>
    ${headline.map((line, i) => `<text x="72" y="${370 + i * 56}" font-size="44" font-weight="700">${e(line)}</text>`).join("\n    ")}
    <rect x="72" y="500" width="${badgeWidth}" height="68" rx="10" fill="${rank.bg}"/>
    <text x="96" y="546" font-size="30" font-weight="800" fill="${rank.fg}">${e(badgeText)}</text>
    ${input.fixed ? `<text x="${72 + badgeWidth + 32}" y="546" font-size="30" fill="#e8f1ee">修正版 ${e(input.fixed)}</text>` : ""}
  </g>
</svg>`;
}
