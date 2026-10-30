import { CatalogRepo } from "@ichiji/db";
import type { Env, JobMessage } from "./env";
import { computeRankings } from "./rankings";
import { CRON_JOBS } from "./cron";

export { IngestWorkflow, MatchWorkflow, DigestWorkflow } from "./workflows";
export { CRON_JOBS };

function instanceId(prefix: string): string {
  return `${prefix}-${new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14)}-${Math.random().toString(36).slice(2, 8)}`;
}

export async function handleMessage(message: JobMessage, env: Env): Promise<void> {
  switch (message.type) {
    case "ingest":
      await env.INGEST_WORKFLOW.create({ id: instanceId("ingest"), params: { rematch: true } });
      return;
    case "digest":
      await env.DIGEST_WORKFLOW.create({ id: instanceId("digest"), params: {} });
      return;
    case "match-project":
      await env.MATCH_WORKFLOW.create({
        id: instanceId(`match-${message.projectId}`.slice(0, 60)),
        params: { tenantId: message.tenantId, projectId: message.projectId },
      });
      return;
    case "rankings": {
      const r = await computeRankings(new CatalogRepo(env.CATALOG_DB), {
        accountId: env.CF_ACCOUNT_ID,
        token: env.CF_ANALYTICS_TOKEN,
        dataset: env.ANALYTICS_DATASET ?? "ichiji_article_views",
        fetch,
      });
      if (!r.ok) console.warn(`rankings skipped: ${r.reason}`);
      return;
    }
  }
}

export default {
  /** Cron Triggers → Queues（11章：Cron Triggers → Queues → Workflows） */
  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    const message = CRON_JOBS[controller.cron];
    if (!message) {
      console.warn(`unknown cron: ${controller.cron}`);
      return;
    }
    await env.JOBS_QUEUE.send(message);
  },

  /** Queues → Workflows */
  async queue(batch: MessageBatch<JobMessage>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      try {
        await handleMessage(msg.body, env);
        msg.ack();
      } catch (e) {
        console.error(`job failed: ${JSON.stringify(msg.body)}`, e);
        msg.retry({ delaySeconds: 60 });
      }
    }
  },

  /** 公開しない。ヘルスチェックのみ */
  async fetch(): Promise<Response> {
    return new Response("ok");
  },
} satisfies ExportedHandler<Env, JobMessage>;
