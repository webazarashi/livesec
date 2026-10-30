import { ARTICLE_SEPARATOR } from "./article";
import { cvssSourceLabel, factsAffected, factsFixed, type VulnFacts } from "./facts";
import { getTopic, type TopicKey } from "./topics";
import { RANK_LABELS } from "./scoring";

export interface ArticlePromptItem {
  facts: VulnFacts;
  topic: TopicKey;
  /** 提案するslug（ChatGPTはこのまま使う） */
  slug: string;
  /** 既存記事の書き直し。needs_update はソース更新による「要更新」 */
  regenerate?: "needs_update" | "rewrite";
}

/** 記事のslugの初期案：`<パッケージ名>-cve-2026-12345` */
export function suggestSlug(facts: VulnFacts): string {
  const pkg = facts.packages[0]?.name ?? "vuln";
  const base = pkg
    .toLowerCase()
    .replace(/^@/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return `${base || "vuln"}-${facts.id.toLowerCase()}`;
}

function yamlString(s: string): string {
  return JSON.stringify(s);
}

function factsBlock(item: ArticlePromptItem, n: number): string {
  const f = item.facts;
  const affected = factsAffected(f.packages);
  const fixed = factsFixed(f.packages);
  const refs = f.references.slice(0, 15).map((r) => `  - ${r.url}${r.tags.length ? `（${r.tags.join(", ")}）` : ""}`);
  return [
    `### ${n}. ${f.id}${item.regenerate === "needs_update" ? "（要更新：ソースが更新されたため書き直し。slug は変えない）" : item.regenerate === "rewrite" ? "（既存記事の書き直し。slug は変えない）" : ""}`,
    `- cve_ids: [${yamlString(f.id)}]`,
    `- slug: ${yamlString(item.slug)}`,
    `- topic: ${yamlString(item.topic)}（${getTopic(item.topic)?.name ?? item.topic}）`,
    `- packages: [${f.packages.map((p) => yamlString(p.purl)).join(", ")}]`,
    `- affected: ${yamlString(affected)}`,
    ...f.packages.map((p) => `  - ${p.purl}: 影響 ${p.affected} ／ 修正版 ${p.fixed.join(", ") || "なし"}`),
    `- fixed: [${fixed.map(yamlString).join(", ")}]`,
    `- cvss: ${f.cvss ? `${f.cvss.score.toFixed(1)}（${cvssSourceLabel(f.cvss)}）` : "null（未算出）"}`,
    `- EPSS: ${f.epss === null ? "不明" : f.epss.toFixed(4)}`,
    `- KEV: ${f.kev ? `掲載（${f.kevAddedAt ?? "日付不明"}）` : "未掲載"}`,
    `- PoC: ${f.poc ? "あり" : "確認できず"}`,
    `- 一般緊急度: ${f.rank}（${RANK_LABELS[f.rank].meaning}）`,
    `- 公開日: ${f.publishedAt?.slice(0, 10) ?? "不明"}`,
    `- 参照URL:`,
    ...(refs.length ? refs : ["  - （なし）"]),
  ].join("\n");
}

/**
 * 管理画面の「記事生成プロンプトをコピー」（10-1 の2）。
 * 事実データ＋記事テンプレート＋トーン指定をまとめてコピーし、ChatGPTに貼る。
 */
export function buildArticleGenerationPrompt(items: ArticlePromptItem[]): string {
  const header = `あなたは「一次対応まとめ」編集部のセキュリティ記者です。自社SaaSの開発チームに向けて、以下の${items.length}件の脆弱性について、それぞれ解説記事を書いてください。

# トーン
- 落ち着いた専門誌風。煽らない。誇張しない
- 「です・ます」調。一文を短く
- 読者は自社SaaSの開発者。「自社に関係あるか判定 → 直す → 説明する」ができる内容にする
- 事実データにないことは推測で書かない。分からないことは「公開情報では不明」と書く
- 悪用手順・攻撃コードは書かない

# 厳守すること（機械照合に通らないと公開されません）
- フロントマターの cve_ids・slug・topic・packages・affected・fixed・cvss は、下の「事実データ」の値を**一字一句そのまま**写す
- 1件ごとに、行頭に \`${ARTICLE_SEPARATOR}\` だけの行を置いて区切る
- 出力はMarkdownのテキストのみ。前置きや後書きは書かない
- タイトルは「製品名 CVE番号｜何が起きるか｜修正版」の型にする（例：express CVE-2026-12345｜細工したURLでサーバが停止｜4.21.2で修正）

# 出力形式（1件分）
${ARTICLE_SEPARATOR}
---
cve_ids: ["CVE-XXXX-XXXXX"]
title: "製品名 CVE番号｜何が起きるか｜修正版"
slug: "事実データのslug"
topic: "事実データのtopic"
packages: ["事実データのpackages"]
affected: "事実データのaffected"
fixed: ["事実データのfixed"]
cvss: 事実データのcvss（数値。nullならnull）
why_read: "なぜ読むべきか（1〜2文）"
points: ["この記事のポイント1", "ポイント2", "ポイント3"]
gains: ["この記事で得られること1", "2", "3"]
tags: ["タグ1", "タグ2"]
faq:
  - q: "よくある質問"
    a: "回答"
sources:
  - title: "参照元タイトル"
    url: "https://（事実データの参照URLから選ぶ）"
    note: "一言説明"
---
## 何が起きるか
（概要。表を1つ以上使う）

:::summary
この章のまとめ（1〜2文）
:::

## 影響を受ける条件
（影響バージョン・使い方の条件を表で）

:::summary
この章のまとめ
:::

## 自環境の確認コマンド
（コピーして実行できるコマンドをコードブロックで。npm ls / pip show / bundle exec gem list / composer show / go list -m / dpkg -l / apk info などから該当するもの）

## 対応手順
（優先順の番号付きリスト。修正版へのアップデート方法、すぐ更新できない場合の回避策）

:::summary
この章のまとめ
:::

## まとめ
（3〜4文）

# 本文の決まり
- 見出しはH2（##）とH3（###）だけ使う
- 章末のまとめボックスは \`:::summary\` と \`:::\` で囲む
- 「自環境の確認コマンド」と「まとめ」の見出し名は変えない
- HTMLタグは使わない
- FAQは3問程度。sources は参照URLから2〜5件

# 事実データ（一次対応まとめが機械照合済み）
`;
  return `${header}\n${items.map((item, i) => factsBlock(item, i + 1)).join("\n\n")}\n`;
}
