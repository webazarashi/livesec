/**
 * ローカル開発用のサンプルデータを入れる（本番では使わない）。
 * 使い方：
 *   pnpm --filter @ichiji/web exec wrangler d1 migrations apply ichiji-catalog --local
 *   pnpm --filter @ichiji/web exec wrangler d1 migrations apply ichiji-app --local
 *   pnpm --filter @ichiji/web seed:local
 *
 * CVE番号・パッケージはすべて架空のサンプルです（タイトルに【サンプル】を付けます）。
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";
import {
  ARTICLE_SEPARATOR,
  cvssLabel,
  extractWatchlistCpes,
  factsAffected,
  factsFixed,
  normalizeOsv,
  selectNvdCvss,
  suggestSlug,
  type NvdCve,
  type OsvRecord,
  type TopicKey,
  type VulnFacts,
} from "@ichiji/core";
import { CatalogRepo } from "@ichiji/db";
import { ShimD1 } from "../../../packages/db/test/d1-shim";
import { importArticles } from "../src/server/services";

const dir = join(import.meta.dirname, "../.wrangler/state/v3/d1/miniflare-D1DatabaseObject");
const files = readdirSync(dir).filter((f) => f.endsWith(".sqlite") && f !== "metadata.sqlite");
let catalogDb: ShimD1 | null = null;
for (const f of files) {
  const db = new ShimD1(join(dir, f));
  const hasVulns = db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='vulns'").get();
  if (hasVulns) catalogDb = db;
}
if (!catalogDb) throw new Error("ローカルのカタログDBが見つかりません。先にマイグレーションを適用してください");

const catalog = new CatalogRepo(catalogDb as unknown as D1Database);
const now = Date.now();
const daysAgo = (n: number) => new Date(now - n * 86_400_000).toISOString();
const windowStart = daysAgo(30);
await catalog.setMeta("window_start", windowStart);

const SAMPLE = "（ローカル開発用のサンプルデータ）";

const osv: OsvRecord[] = [
  {
    id: "GHSA-sample-0001-0001",
    modified: daysAgo(1),
    published: daysAgo(2),
    aliases: ["CVE-2026-90001"],
    summary: `%2F で公開ディレクトリの外のファイルを読める ${SAMPLE}`,
    affected: [{ package: { ecosystem: "npm", name: "@example/static-gate" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.4.2" }] }] }],
    references: [
      { type: "ADVISORY", url: "https://github.com/advisories/GHSA-sample-0001-0001" },
      { type: "WEB", url: "https://www.exploit-db.com/exploits/00000" },
    ],
    database_specific: { severity: "HIGH" },
  },
  {
    id: "GHSA-sample-0002-0002",
    modified: daysAgo(3),
    published: daysAgo(4),
    aliases: ["CVE-2026-90002"],
    summary: `信頼できないYAMLを読み込むと任意のコードが実行される ${SAMPLE}`,
    affected: [{ package: { ecosystem: "PyPI", name: "example-yaml-loader" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0.0" }, { fixed: "2.6.1" }] }] }],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-sample-0002-0002" }],
    database_specific: { severity: "CRITICAL" },
  },
  {
    id: "GHSA-sample-0003-0003",
    modified: daysAgo(5),
    published: daysAgo(6),
    aliases: ["CVE-2026-90003"],
    summary: `セッションIDの検証が不十分 ${SAMPLE}`,
    affected: [{ package: { ecosystem: "npm", name: "@example/session-kit" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.8.4" }] }] }],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-sample-0003-0003" }],
    database_specific: { severity: "MODERATE" },
  },
  {
    id: "DEBIAN-CVE-2026-90004",
    modified: daysAgo(7),
    published: daysAgo(9),
    upstream: ["CVE-2026-90004"],
    summary: `証明書の検証で境界外読み取り ${SAMPLE}`,
    affected: [{ package: { ecosystem: "Debian:12", name: "example-tls" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.2.3-1+deb12u1" }] }] }],
    references: [{ type: "ADVISORY", url: "https://security-tracker.debian.org/tracker/CVE-2026-90004" }],
  },
  {
    id: "GO-2026-90006",
    modified: daysAgo(10),
    published: daysAgo(11),
    aliases: ["CVE-2026-90006"],
    summary: `細工したパスでルーティングを回避できる ${SAMPLE}`,
    affected: [{ package: { ecosystem: "Go", name: "github.com/example/router" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.9.2" }] }] }],
    references: [{ type: "ADVISORY", url: "https://pkg.go.dev/vuln/GO-2026-90006" }],
  },
];
// 記事を作らずに残すサンプル（管理画面の「記事待ち」・緊急ページの「記事準備中」の確認用）
const pendingOsv: OsvRecord[] = [
  {
    id: "GHSA-sample-0007-0007",
    modified: daysAgo(0),
    published: daysAgo(0),
    aliases: ["CVE-2026-90007"],
    summary: `細工したJWTで署名の検証を回避できる ${SAMPLE}`,
    affected: [{ package: { ecosystem: "RubyGems", name: "example-jwt" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.8.1" }] }] }],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-sample-0007-0007" }],
    database_specific: { severity: "CRITICAL" },
  },
  {
    id: "GHSA-sample-0008-0008",
    modified: daysAgo(1),
    published: daysAgo(1),
    aliases: ["CVE-2026-90008"],
    summary: `アップロードしたファイル名でパスを操作できる ${SAMPLE}`,
    affected: [{ package: { ecosystem: "Packagist", name: "example/uploader" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.0.0" }, { fixed: "3.2.5" }] }] }],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-sample-0008-0008" }],
    database_specific: { severity: "MODERATE" },
  },
];
for (const r of [...osv, ...pendingOsv]) await catalog.upsertOsv(normalizeOsv(r), null);

const nvd: NvdCve[] = [
  {
    id: "CVE-2026-90001",
    published: daysAgo(2).replace("Z", ""),
    lastModified: daysAgo(1).replace("Z", ""),
    metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" } }] },
    references: [{ url: "https://www.exploit-db.com/exploits/00000", tags: ["Exploit"] }],
  },
  {
    id: "CVE-2026-90002",
    published: daysAgo(4).replace("Z", ""),
    lastModified: daysAgo(3).replace("Z", ""),
    metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 9.8, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] },
  },
  {
    id: "CVE-2026-90005",
    published: daysAgo(8).replace("Z", ""),
    lastModified: daysAgo(8).replace("Z", ""),
    descriptions: [{ lang: "en", value: `Sample: HTTP/2 request smuggling ${SAMPLE}` }],
    metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 8.2, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L" } }] },
    configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*", versionStartIncluding: "1.25.0", versionEndExcluding: "1.27.4" }] }] }],
  },
];
for (const c of nvd) await catalog.applyNvd(c, selectNvdCvss(c), extractWatchlistCpes(c), { createIfMissing: true });
await catalog.applyKev([{ cveId: "CVE-2026-90002", dateAdded: daysAgo(3).slice(0, 10) }]);
await catalog.applyEpss(
  [
    { cveId: "CVE-2026-90001", epss: 0.1234, percentile: 0.95 },
    { cveId: "CVE-2026-90002", epss: 0.6, percentile: 0.99 },
    { cveId: "CVE-2026-90003", epss: 0.004, percentile: 0.4 },
    { cveId: "CVE-2026-90005", epss: 0.02, percentile: 0.8 },
  ],
  [],
);
const ids = ["CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003", "CVE-2026-90004", "CVE-2026-90005", "CVE-2026-90006"];
await catalog.refreshDerived([...ids, "CVE-2026-90007", "CVE-2026-90008"], { windowStart });

// 記事（固定形式で作って、機械照合ゲートを通す）
const commands: Record<string, string> = {
  npm: "npm ls {name}\n# または\npnpm why {name}",
  pypi: "pip show {name}\n# または\npython -m pip freeze | grep -i {name}",
  os: "dpkg -l | grep {name}\n# コンテナの中で\ndocker run --rm <image> dpkg -l {name}",
  middleware: "nginx -v\n# コンテナの場合\ndocker exec <container> nginx -v",
  go: "go list -m all | grep {name}",
};

function article(f: VulnFacts & { topic: string | null; summary: string | null }, headline: string): string {
  const topic = f.topic as TopicKey;
  const pkg = f.packages[0]!;
  const fixed = factsFixed(f.packages);
  const name = pkg.ecosystem === "watchlist" ? "nginx" : pkg.name;
  const cmd = (commands[topic] ?? "echo 'バージョンを確認してください'").replaceAll("{name}", name);
  return `${ARTICLE_SEPARATOR}
---
cve_ids: ["${f.id}"]
title: "【サンプル】${name} ${f.id}｜${headline}｜${fixed.at(-1) ?? "修正版なし"}で修正"
slug: "${suggestSlug(f)}"
topic: "${topic}"
packages: [${f.packages.map((p) => `"${p.purl}"`).join(", ")}]
affected: "${factsAffected(f.packages)}"
fixed: [${fixed.map((v) => `"${v}"`).join(", ")}]
cvss: ${f.cvss ? f.cvss.score : "null"}
why_read: "${name} を使っている公開サービスでは、${headline}おそれがあります。影響範囲と確認方法、対応手順を短くまとめました。"
points: ["${factsAffected(f.packages)} が影響を受けます", "${fixed.at(-1) ?? "修正版"} に更新すると解消します", "一般緊急度は ${f.rank}（${cvssLabel(f.cvss)}）です"]
gains: ["自社が影響を受けるかの判断材料", "コピーして使える確認コマンド", "優先順の対応手順"]
tags: ["${name}", "サンプル"]
faq:
  - q: "開発用の依存として入っているだけでも対応が必要ですか？"
    a: "本番のビルドに含まれないなら優先度は下がります。ただし CI や開発環境でも外部の入力を扱う場合は更新をおすすめします。"
  - q: "すぐに更新できない場合は？"
    a: "対応手順の「すぐに更新できない場合」にある回避策を検討してください。"
sources:
  - title: "Advisory（サンプル）"
    url: "${f.references[0]?.url ?? "https://osv.dev/"}"
    note: "一次情報（サンプルのURL）"
---
## 何が起きるか

${name} の特定のバージョンで、${headline}問題があります。${SAMPLE}

| 項目 | 内容 |
|---|---|
| 影響 | ${headline} |
| 前提条件 | 該当機能が外部からの入力を受け付けていること |
| 影響バージョン | ${factsAffected(f.packages)} |

:::summary
外部からの入力を扱う構成で、影響バージョンを使っている場合は対応が必要です。
:::

## 影響を受ける条件

| 条件 | 影響 |
|---|---|
| 影響バージョンを使っている | 該当 |
| インターネットに公開している | 優先度が高い |
| 社内のみで使っている | 優先度は下がる |

:::summary
バージョン上の該当と、実際の使い方の両方を確認してください。
:::

## 自環境の確認コマンド

\`\`\`bash
${cmd}
\`\`\`

## 対応手順

1. 影響バージョンを使っているか、上のコマンドで確認する
2. ${fixed.at(-1) ?? "修正版"} 以降に更新する
3. すぐに更新できない場合は、該当機能を外部から使えないように制限する
4. 更新後にテストを流し、デプロイする

:::summary
まずは更新。更新できない場合は入力の制限で時間を稼ぎます。
:::

## まとめ

${name} の ${f.id} は、${headline}脆弱性です。影響バージョンを使っている場合は ${fixed.at(-1) ?? "修正版"} 以降に更新してください。
`;
}

const headlines: Record<string, string> = {
  "CVE-2026-90001": "%2Fでパス制限を回避してファイルを読み出せる",
  "CVE-2026-90002": "細工したYAMLで任意のコードが実行される",
  "CVE-2026-90003": "セッションIDの検証を回避できる",
  "CVE-2026-90004": "証明書の検証で境界外読み取りが起きる",
  "CVE-2026-90005": "HTTP/2でリクエストスマグリングが起きる",
  "CVE-2026-90006": "細工したパスでルーティングを回避できる",
};
// 何度実行しても同じ結果になるよう、記事がまだないCVEだけ取り込む
const missing: string[] = [];
for (const id of ids) if (!(await catalog.getArticleByCve(id))) missing.push(id);
const facts = await catalog.getFactsMany(missing);
const text = facts.map((f) => article(f, headlines[f.id]!)).join("\n");
const results = text ? await importArticles(catalog, text) : [];
for (const r of results) console.log(`${r.status}\t${r.slug}\t${r.url ?? ""}\t${(r.errors ?? []).join(" / ")}${(r.mismatches ?? []).map((m) => m.message).join(" / ")}`);
if (results.length) await catalog.setPinned(results.find((r) => r.status !== "rejected")?.slug ?? "", true);
console.log("seed done");
