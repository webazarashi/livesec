import { describe, expect, it } from "vitest";
import { ARTICLE_SEPARATOR, parseBulkArticles, splitArticleSections } from "../src/article";
import { verifyArticle } from "../src/gate";
import type { VulnFacts } from "../src/facts";
import { buildArticleGenerationPrompt, suggestSlug } from "../src/article-prompt";
import { renderArticleMarkdown } from "../src/markdown";

const facts: VulnFacts = {
  id: "CVE-2026-12345",
  aliases: ["GHSA-aaaa-bbbb-cccc"],
  packages: [{ purl: "pkg:npm/express", ecosystem: "npm", name: "express", affected: ">=4.0.0 <4.21.2", fixed: ["4.21.2"] }],
  cvss: { score: 7.5, version: "3.1", source: "nvd", vector: null },
  epss: 0.02,
  epssPercentile: 0.5,
  kev: false,
  kevAddedAt: null,
  poc: false,
  rank: "B",
  rankReasons: [],
  publishedAt: "2026-10-18T00:00:00Z",
  modifiedAt: "2026-10-20T00:00:00Z",
  references: [{ url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", tags: ["ADVISORY"] }],
};

function article(overrides: Record<string, string> = {}) {
  const fm = {
    cve_ids: '["CVE-2026-12345"]',
    affected: '">=4.0.0 <4.21.2"',
    fixed: '["4.21.2"]',
    cvss: "7.5",
    slug: '"express-cve-2026-12345"',
    ...overrides,
  };
  return `${ARTICLE_SEPARATOR}
---
cve_ids: ${fm.cve_ids}
title: "express CVE-2026-12345｜細工したURLでファイル読み出し｜4.21.2で修正"
slug: ${fm.slug}
topic: "npm"
packages: ["pkg:npm/express"]
affected: ${fm.affected}
fixed: ${fm.fixed}
cvss: ${fm.cvss}
why_read: "公開サーバで広く使われているためです。"
points: ["ポイント1", "ポイント2", "ポイント3"]
gains: ["得られること1", "2", "3"]
faq:
  - q: "質問"
    a: "回答"
sources:
  - title: "GitHub Advisory"
    url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
    note: "一次情報"
---
## 何が起きるか

細工したURLで、公開ディレクトリの外のファイルを読み出せます。影響は大きいです。

| 項目 | 内容 |
|---|---|
| 影響 | ファイル読み出し |

:::summary
この章のまとめです。
:::

## 自環境の確認コマンド

\`\`\`bash
npm ls express
\`\`\`

## まとめ

4.21.2 に更新してください。
`;
}

describe("まとめて貼り付け（10-1・10-3）", () => {
  it("区切りで分割して読む", () => {
    const r = parseBulkArticles(`${article()}\n${article({ slug: '"express-two"' })}\n`);
    expect(r.errors).toEqual([]);
    expect(r.articles).toHaveLength(2);
    expect(r.articles[1]!.frontMatter.slug).toBe("express-two");
  });
  it("壊れた1件があっても他は読む", () => {
    const r = parseBulkArticles(`${article()}\n${ARTICLE_SEPARATOR}\n---\ntitle: x\n---\nbody`);
    expect(r.articles).toHaveLength(1);
    expect(r.errors).toHaveLength(1);
  });
  it("コードフェンスで囲まれていても読む", () => {
    const r = parseBulkArticles("```markdown\n" + article().replace(`${ARTICLE_SEPARATOR}\n`, "") + "\n```");
    expect(r.articles).toHaveLength(1);
  });
  it("本文を専用ブロックに分ける", () => {
    const r = parseBulkArticles(article());
    const s = splitArticleSections(r.articles[0]!.body);
    expect(s.check).toContain("npm ls express");
    expect(s.summary).toContain("4.21.2");
    expect(s.main).toContain("## 何が起きるか");
    expect(s.main).not.toContain("npm ls");
  });
});

describe("機械照合ゲート（10-2）", () => {
  const fm = () => parseBulkArticles(article()).articles[0]!.frontMatter;
  it("一致すれば通す", () => {
    expect(verifyArticle(fm(), [facts])).toEqual({ ok: true, mismatches: [] });
  });
  it("表記の揺れは許す", () => {
    const f = parseBulkArticles(article({ affected: '"< 4.21.2, >= 4.0.0"', fixed: '["v4.21.2"]' })).articles[0]!.frontMatter;
    expect(verifyArticle(f, [facts]).ok).toBe(true);
  });
  it("影響バージョン・修正版・CVSSが違えば止める", () => {
    const f = parseBulkArticles(article({ affected: '">=4.0.0 <4.21.1"', fixed: '["4.21.1"]', cvss: "9.8" })).articles[0]!.frontMatter;
    const r = verifyArticle(f, [facts]);
    expect(r.ok).toBe(false);
    expect(r.mismatches.map((m) => m.field)).toEqual(["affected", "fixed", "cvss"]);
  });
  it("カタログにないCVEは止める", () => {
    const f = parseBulkArticles(article({ cve_ids: '["CVE-2026-99999"]' })).articles[0]!.frontMatter;
    expect(verifyArticle(f, [facts]).mismatches[0]!.field).toBe("cve_ids");
  });
  it("CVSS未算出なら null でないと止める", () => {
    const noCvss = { ...facts, cvss: null };
    expect(verifyArticle(fm(), [noCvss]).ok).toBe(false);
    const f = parseBulkArticles(article({ cvss: "null" })).articles[0]!.frontMatter;
    expect(verifyArticle(f, [noCvss]).ok).toBe(true);
  });
});

describe("記事生成プロンプト", () => {
  it("事実データとslugを含む", () => {
    const p = buildArticleGenerationPrompt([{ facts, topic: "npm", slug: suggestSlug(facts) }]);
    expect(suggestSlug(facts)).toBe("express-cve-2026-12345");
    expect(p).toContain('affected: ">=4.0.0 <4.21.2"');
    expect(p).toContain('fixed: ["4.21.2"]');
    expect(p).toContain("cvss: 7.5");
    expect(p).toContain(ARTICLE_SEPARATOR);
  });
});

describe("Markdown", () => {
  it("生HTMLをエスケープし、まとめボックスと目次を作る", () => {
    const r = renderArticleMarkdown("## 見出し\n\n<script>alert(1)</script>\n\n:::summary\nまとめ\n:::\n\n[x](javascript:alert(1)) [y](https://example.com)\n");
    expect(r.html).not.toContain("<script>");
    expect(r.html).toContain("&lt;script&gt;");
    expect(r.html).toContain('class="md-box md-box--summary"');
    expect(r.html).not.toContain("javascript:");
    expect(r.html).toContain('rel="noopener nofollow"');
    expect(r.toc).toEqual([{ id: "sec-1", text: "見出し", depth: 2 }]);
  });
  it("コードブロックにコピーボタンを付ける", () => {
    expect(renderArticleMarkdown("```bash\nnpm ls\n```").html).toContain("data-copy-code");
  });
});
