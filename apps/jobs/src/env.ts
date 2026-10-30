/** jobs ワーカーのバインディング（wrangler.jsonc と対応） */
export interface Env {
  CATALOG_DB: D1Database;
  APP_DB: D1Database;
  /** ソースJSONの原本（11章） */
  RAW: R2Bucket;
  JOBS_QUEUE: Queue<JobMessage>;
  INGEST_WORKFLOW: Workflow<IngestParams>;
  MATCH_WORKFLOW: Workflow<MatchParams>;
  DIGEST_WORKFLOW: Workflow<Record<string, never>>;
  /** web ワーカー（キャッシュのパージ用） */
  WEB: Fetcher;
  PUBLIC_BASE_URL: string;
  /** NVD API キー（任意。あると30秒に50回まで） */
  NVD_API_KEY?: string;
  /** Slack Webhook URL の暗号鍵（base64・32バイト） */
  WEBHOOK_ENC_KEY: string;
  /** web ワーカーの内部APIの共有トークン */
  INTERNAL_TOKEN: string;
  /** Analytics Engine の SQL API（ランキング集計） */
  CF_ACCOUNT_ID?: string;
  CF_ANALYTICS_TOKEN?: string;
  ANALYTICS_DATASET?: string;
}

export type JobMessage =
  | { type: "ingest" }
  | { type: "digest" }
  | { type: "rankings" }
  | { type: "match-project"; tenantId: string; projectId: string };

export interface IngestParams {
  /** true なら取り込みのあとに全プロジェクトの再照会まで行う（3時間ごとの定期実行） */
  rematch: boolean;
}

export interface MatchParams {
  tenantId: string;
  projectId: string;
}
