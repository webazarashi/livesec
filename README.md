# 一次対応まとめ

CVEを「知る」で終わらせず、「自社に関係あるか判定 → 直す → 説明する」まで、**自分のAIで**できるようにするサービスです。
無料のセキュリティメディアと、有料の対応支援SaaS（MVPでは課金なし）で構成します。

- 仕様書：[docs/spec.md](docs/spec.md)（記事ページのモック：[docs/mock-article-page.webp](docs/mock-article-page.webp)）

## 構成

```
packages/
  core/   純粋なTypeScriptのドメインロジック（ブラウザ・Workers・Node 共通）
          緊急度判定（7章）・PURL・バージョン比較・stack.yaml/SBOM の検証・ウォッチリスト・
          OSV/NVD/KEV/EPSS の正規化・記事の固定形式・機械照合ゲート・Ask AI のプロンプト・Slack・暗号
  db/     D1 のスキーマ（migrations/catalog・migrations/app）とリポジトリ層
          CatalogRepo（CVEカタログ・記事）／TenantRepo（tenant_id 必須）／SystemRepo／突合（matcher）
apps/
  web/    Astro on Workers（メディア・会員画面・管理画面）＋ Hono（/api/*）＋ Better Auth
  jobs/   取り込み・突合・通知のワーカー（Cron Triggers → Queues → Workflows）。公開しない
```

| 仕様 | 実装 |
|---|---|
| メディア（5章） | `apps/web/src/pages`。記事ページは `[topic]/[slug].astro`、Ask AI は `components/AskAi.astro` ＋ `scripts/askai.ts` |
| エッジキャッシュとパージ（11章） | Astro のルートキャッシュ（`@astrojs/cloudflare/cache`）。メディアのページに `catalog` タグを付け、取り込み・記事公開時に `/api/internal/purge` でパージ |
| 会員・認証（4-2・12章） | Better Auth × D1。メール＋パスワード、TOTP の二要素認証、ログイン試行のレート制限（D1）、セッション失効 |
| 私の環境（6-4） | `user_profiles`。HTMLには埋め込まず、ログイン中だけ `/api/me/environment` から取得 |
| スタック登録（8章） | 画面 `/app/projects/:id/settings/`、CI は `POST /api/v1/stack`（プロジェクトごとのAPIトークン） |
| 突合（9章） | `packages/db/src/matcher.ts`。OSV querybatch（1000件ずつ・結果キャッシュ・停止時は前回のキャッシュ）＋ MW ウォッチリスト（NVD の CPE） |
| 緊急度（7章） | `packages/core/src/scoring.ts`。閾値は `scoring.config.json` で変更できる |
| 通知（7-1） | S・A は照合直後に即時、B・C は月曜09:00 JST の週次まとめ（`apps/jobs/src/notify.ts`） |
| 記事（10章） | 管理画面 `/admin/` で記事待ちCVEを選んでプロンプトをコピー → ChatGPT → `/admin/import/` にまとめて貼り付け → 機械照合ゲート → 公開／差し戻し |
| テナント分離（12章） | テナントの行はすべて `TenantRepo`（全SQLに `tenant_id = ?`）。他テナントを読めないことを `packages/db/test/tenant.test.ts` で検証 |
| 配布物（8-1・8-4） | `apps/web/public/schemas/stack.schema.json`・`templates/agent-prompt.md`・`templates/github-actions.yml`（公開URLから配布） |

## 必要なもの

- Node.js **22.23.4 以上**（Astro 7 の要件）
- pnpm 10

```bash
pnpm install
```

## テスト・型チェック

```bash
pnpm test
```

```bash
pnpm typecheck
```

## ローカルで動かす

```bash
cp apps/web/.dev.vars.example apps/web/.dev.vars
```

```bash
pnpm --filter @ichiji/web exec wrangler d1 migrations apply ichiji-catalog --local
```

```bash
pnpm --filter @ichiji/web exec wrangler d1 migrations apply ichiji-app --local
```

架空のサンプルCVE（タイトルに【サンプル】）を入れて、記事の取り込み（機械照合ゲート）まで通します。

```bash
pnpm --filter @ichiji/web seed:local
```

```bash
pnpm --filter @ichiji/web dev
```

`http://localhost:4321` を開きます。`.dev.vars` の `ADMIN_EMAILS` に書いたメールアドレスで会員登録すると管理画面に入れます。
ローカルでは jobs ワーカーが動かないので、スタック登録後の照合は次のコマンドで行います（OSV に問い合わせず、ローカルのカタログで照合します）。

```bash
pnpm --filter @ichiji/web match:local
```

## デプロイ（Cloudflare・workers.dev）

1. リソースを作り、出力された ID を `apps/web/wrangler.jsonc` と `apps/jobs/wrangler.jsonc` の `database_id` に書く

```bash
pnpm --filter @ichiji/web exec wrangler d1 create ichiji-catalog
```

```bash
pnpm --filter @ichiji/web exec wrangler d1 create ichiji-app
```

```bash
pnpm --filter @ichiji/web exec wrangler r2 bucket create ichiji-raw
```

```bash
pnpm --filter @ichiji/web exec wrangler queues create ichiji-jobs
```

2. マイグレーションを本番に適用する

```bash
pnpm --filter @ichiji/web exec wrangler d1 migrations apply ichiji-catalog --remote
```

```bash
pnpm --filter @ichiji/web exec wrangler d1 migrations apply ichiji-app --remote
```

3. 両方の `wrangler.jsonc` の `PUBLIC_BASE_URL` を web ワーカーの workers.dev のURLにし、web の `ADMIN_EMAILS` を設定する（Better Auth の `baseURL`・信頼するオリジンもこのURLになります）

4. シークレットを登録する（`WEBHOOK_ENC_KEY` と `INTERNAL_TOKEN` は web と jobs で同じ値にする）

| ワーカー | シークレット |
|---|---|
| web | `BETTER_AUTH_SECRET`（32文字以上のランダム）、`WEBHOOK_ENC_KEY`（`openssl rand -base64 32`）、`INTERNAL_TOKEN` |
| jobs | `WEBHOOK_ENC_KEY`、`INTERNAL_TOKEN`、`NVD_API_KEY`（任意・推奨）、`CF_ACCOUNT_ID`・`CF_ANALYTICS_TOKEN`（ランキング集計用。Analytics Engine の読み取り権限） |

```bash
pnpm --filter @ichiji/web exec wrangler secret put BETTER_AUTH_SECRET
```

5. デプロイする（jobs は web をサービスバインディングで呼ぶので、web を先に）

```bash
pnpm --filter @ichiji/web build && pnpm --filter @ichiji/web exec wrangler deploy
```

```bash
pnpm --filter @ichiji/jobs exec wrangler deploy
```

初回の取り込みは、次の Cron（3時間ごと）で始まります（掲載期間は初回取り込みの時点から30日遡ります）。

## 実装時に決めたこと（仕様書で「実装時に決定」とされていた点など）

| 項目 | 決めた値・方針 |
|---|---|
| 私の環境の文字数上限（6-4） | 500文字 |
| Ask AI の URL 長の上限（6-6） | 12,000文字。超える場合は本文抜粋を 600 → 300 → 120 → 0 文字と削り、それでも超えればコピー方式に切り替える |
| 本文抜粋の上限（6-5） | 600文字（見出しと各章の最初の一文） |
| 回答文系プリセット | 「顧客への回答」「全顧客へのお知らせ」「社内報告」の質問文に「日本語で」を入れた |
| カタログ（メディア）に入れるもの | CVE番号のあるものだけ。悪性パッケージ（`MAL-`）など CVE のないものは入れない（照合のアラートには出る） |
| OSパッケージの除外 | Linux カーネル（`linux`・`linux-*`）はコンテナの一次対応に関係しないため対象外（`packages/core/src/topics.ts`） |
| CVSS の代用 | NVD の v3.1 → v4.0 → v3.0 の順。NVD の Primary がなければ CNA のスコア。どれもなければ GHSA の深刻度 |
| 要更新の判定 | 記事本文に影響する事実（影響範囲・修正版・CVSS・KEV）が変わったときだけ。EPSS の日々の変動では立てない |
| 開発用依存の判別 | CycloneDX の `scope: optional / excluded`、または cdxgen の `cdx:*:development = true` |
| CDN の LIFF | `liff/edge/2/sdk.js`（常に最新）はバージョン不明として B 固定。`liff/edge/versions/x.y.z/` はそのバージョンで照合 |
| 管理者 | `ADMIN_EMAILS`（カンマ区切り）に書いたメールアドレス |
| カバー画像・OG画像 | テンプレートから SVG を生成。X・Facebook などは SVG の OG 画像を表示しないため、PNG 化は今後の課題 |
| ランキング | 記事の閲覧を Analytics Engine に記録し、毎時15分に D1 へ確定（集計前は新しい S・A・B の記事で代用） |

## 未決・今後の課題

- 仕様書15章の未決事項はMVPでは次の扱いにしています：私の環境はアカウントに1つ／ダッシュボードからの Ask AI は記事へのリンク（照合結果の差し込みはしない）／AI生成の明示はしていない／料金は課金機能と合わせて検討
- メールアドレスの確認・パスワード再設定メール（メール送信の手段が必要）
- お問い合わせ窓口のメールアドレス（`apps/web/src/pages/contact.astro` は仮の値）
- 利用規約・プライバシーポリシーは初期案。専門家の確認が必要
- 各AIサービスの URL 仕様（`chatgpt.com/?q=`・`claude.ai/new?q=`）は変わりうるため、定期的に動作確認する
- Debian の SBOM はソースパッケージ名（`upstream` 修飾子）がないと OSV で照合できない場合がある
