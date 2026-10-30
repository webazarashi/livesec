/// <reference types="astro/client" />
/// <reference types="@astrojs/cloudflare/types.d.ts" />

interface Env {
  CATALOG_DB: D1Database;
  APP_DB: D1Database;
  RAW: R2Bucket;
  JOBS_QUEUE: Queue<{ type: "match-project"; tenantId: string; projectId: string }>;
  VIEWS?: AnalyticsEngineDataset;
  ASSETS: Fetcher;
  PUBLIC_BASE_URL: string;
  ADMIN_EMAILS?: string;
  BETTER_AUTH_SECRET: string;
  WEBHOOK_ENC_KEY: string;
  INTERNAL_TOKEN: string;
}

declare namespace App {
  interface Locals {
    user?: { id: string; email: string; name: string; twoFactorEnabled: boolean } | null;
    sessionId?: string | null;
    isAdmin?: boolean;
  }
}
