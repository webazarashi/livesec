import type { JobMessage } from "./env";

/** Cron Triggers（UTC）→ キューに積むメッセージ */
export const CRON_JOBS: Record<string, JobMessage> = {
  // 取り込み＋OSV再照会：3時間ごと
  "0 */3 * * *": { type: "ingest" },
  // 週次まとめ：月曜09:00 JST = 月曜00:00 UTC
  "0 0 * * 1": { type: "digest" },
  // 人気ランキングの確定：毎時15分
  "15 * * * *": { type: "rankings" },
};
