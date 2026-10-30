# 一次対応まとめ：stack.yaml と SBOM の作成プロンプト

> このプロンプトを、あなたのリポジトリで動く AI コーディングエージェント（Claude Code・Codex・Cursor など）にそのまま渡してください。
> 作られた `stack.yaml` と SBOM は、**必ず人がレビューしてから**一次対応まとめに送信してください。

---

あなたは、このリポジトリの脆弱性照合のために「一次対応まとめ」へ送る `stack.yaml` と SBOM（CycloneDX JSON）を作るエンジニアです。次の手順で作業してください。

## 1. 探索する

次のファイルを探し、サービスを構成するコンポーネント（API サーバ、フロントエンド、ワーカー、DB など）を洗い出してください。

- lockfile：`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` / `poetry.lock` / `uv.lock` / `requirements*.txt` / `Gemfile.lock` / `composer.lock` / `go.sum`
- `Dockerfile`・`docker-compose*.yml`
- IaC：Terraform（`*.tf`）・CloudFormation・Kubernetes マニフェスト・Helm
- CI 設定：`.github/workflows/*.yml` など
- HTML 内の `<script src="...">`（CDN から読み込んでいるライブラリ。LIFF SDK など）

## 2. SBOM を作る

[cdxgen](https://github.com/CycloneDX/cdxgen) で、コンポーネントごとに CycloneDX JSON を作ってください。

```bash
# 言語パッケージ（例：api-server）
npx @cyclonedx/cdxgen -o sbom/api-server.cdx.json ./apps/api-server
# コンテナイメージがある場合は OS パッケージも含める
npx @cyclonedx/cdxgen -t docker -o sbom/api-server-image.cdx.json <image>:<tag>
```

- 出力先は `sbom/<component名>.cdx.json` にし、`stack.yaml` の `components[].sbom` にそのパスを書く
- 開発用依存は除かずに含めてよい（一次対応まとめ側で判別して緊急度を1段階下げます）

## 3. バージョンは根拠ファイルから読む

- `image`・`middleware` のバージョンは、必ず根拠ファイル（`Dockerfile`・`docker-compose.yml`・`*.tf` など）から読み、`evidence` にファイル名を書く
- 読めない場合は推測せず `"unknown"` と書く（例：`pkg:generic/redis@unknown`）
- **バージョンは必ず文字列でクォートする**（`"1.0"`、`"16.4"`）

## 4. exposure を判定する

コンポーネントごとに `exposure` を次のどれかにし、判断の理由を `exposure_reason` に書いてください。

| 値 | 意味 |
|---|---|
| `internet` | インターネットから到達できる（ALB・CDN・公開ドメイン経由など） |
| `internal` | VPC・社内ネットワークからのみ到達できる |
| `offline` | ネットワークから到達できない（バッチ・ビルド専用など） |

マネージドサービス（RDS・Cloud SQL・ElastiCache など）でパッチ適用が提供元の場合は `managed: true` にしてください。

## 5. 書いてはいけないもの

- ホスト名・IP アドレス・URL（CDN の `cdn_scripts[].url` 以外）
- 環境変数の値・API キー・パスワード・トークンなどの秘密情報
- 顧客名・個人情報

## 6. 検証してレビューを依頼する

1. `stack.yaml` を JSON Schema（`/schemas/stack.schema.json`）で検証する
2. 変更内容を要約し、人のレビューを依頼する（**レビュー前に送信しない**）

## stack.yaml の例

```yaml
schema_version: "1.0"
generated_at: "2026-10-29T17:00:00+09:00"
generated_by: "claude-code"
service:
  name: "acme-crm"
  data_sensitivity: "high"        # high / medium / low

components:
  - name: "api-server"
    exposure: "internet"          # internet / internal / offline
    exposure_reason: "ALB経由で公開（infra/alb.tf）"
    managed: false
    sbom: "sbom/api-server.cdx.json"
    image:
      purl: "pkg:docker/node@20.18.1-bookworm-slim"
      evidence: "Dockerfile"
    middleware:
      - purl: "pkg:generic/nginx@1.27.3"
        evidence: "docker-compose.yml"

  - name: "web-liff"
    exposure: "internet"
    exposure_reason: "LINEミニアプリとして公開"
    managed: false
    sbom: "sbom/web-liff.cdx.json"
    cdn_scripts:                  # SBOMに出ないCDN読み込み
      - name: "LIFF SDK"
        url: "https://static.line-scdn.net/liff/edge/2/sdk.js"
        evidence: "src/index.html"

  - name: "main-db"
    exposure: "internal"
    exposure_reason: "VPC内のみ"
    managed: true                 # RDS等。パッチは提供元
    middleware:
      - purl: "pkg:generic/postgresql@16.4"
        evidence: "infra/rds.tf"
```

## middleware に書ける製品（ウォッチリスト）

nginx、Apache HTTP Server（`httpd`）、PostgreSQL、MySQL、MariaDB、Redis、MongoDB、Node.js、Python、Ruby、PHP、Go、OpenSSL、OpenSSH、curl、Docker Engine、Kubernetes。
`pkg:generic/<製品名>@<バージョン>` で書いてください。コンテナイメージ（`pkg:docker/node@20.18.1-bookworm-slim` など）からはランタイムのバージョンを読み取ります。
