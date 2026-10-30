import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { NvdClient, OsvClient, randomId, WATCHLIST, type OsvRecord } from "@ichiji/core";
import {
  CatalogRepo,
  SystemRepo,
  TenantRepo,
  matchProject,
  refreshPackageVulns,
  chunk,
  type MatcherDeps,
} from "@ichiji/db";
import type { Env, IngestParams, MatchParams } from "./env";
import { notifyImmediate, sendDigest } from "./notify";
import {
  OSV_ECOSYSTEMS,
  ingestEpss,
  ingestKev,
  ingestOsvRecords,
  listOsvUpdates,
  nvdBacklog,
  nvdBackfillWatchlist,
  nvdIncrementalPage,
  type PipelineDeps,
} from "./pipeline";

const RETRY = { retries: { limit: 3, delay: "30 seconds", backoff: "exponential" }, timeout: "10 minutes" } as const;

function pipelineDeps(env: Env): PipelineDeps {
  return {
    catalog: new CatalogRepo(env.CATALOG_DB),
    fetch: (input, init) => fetch(input, init),
    saveRaw: async (key, body) => {
      await env.RAW.put(key, body, { httpMetadata: { contentType: "application/json" } });
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
}

function matcherDeps(env: Env, windowStart: string): MatcherDeps {
  return {
    catalog: new CatalogRepo(env.CATALOG_DB),
    system: new SystemRepo(env.APP_DB),
    osv: new OsvClient(),
    saveRaw: async (record: OsvRecord) => {
      const key = `osv/api/${record.id.replace(/[^A-Za-z0-9._:-]/g, "_")}@${record.modified.replace(/[^0-9TZ:.-]/g, "_")}.json`;
      await env.RAW.put(key, JSON.stringify(record), { httpMetadata: { contentType: "application/json" } });
      return key;
    },
    newId: () => randomId(),
    window: { windowStart },
    maxDetailFetch: 300,
  };
}

/** CVE更新時にメディアのキャッシュをパージする（11章） */
async function purgeMediaCache(env: Env, tags: string[]): Promise<void> {
  await env.WEB.fetch("https://web.internal/api/internal/purge", {
    method: "POST",
    headers: { authorization: `Bearer ${env.INTERNAL_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ tags }),
  });
}

async function matchAndNotify(env: Env, step: WorkflowStep, windowStart: string, refs: Array<{ projectId: string; tenantId: string }>): Promise<void> {
  for (const ref of refs) {
    await step.do(`match:${ref.projectId}`, RETRY, async () => {
      const repo = new TenantRepo(env.APP_DB, ref.tenantId);
      const r = await matchProject(matcherDeps(env, windowStart), repo, ref.projectId);
      return { created: r.created.map((a) => a.id), resolved: r.resolved };
    });
    await step.do(`notify:${ref.projectId}`, RETRY, async () => {
      const repo = new TenantRepo(env.APP_DB, ref.tenantId);
      // 未通知の S・A をまとめて送る（前のステップの再試行で作られたものも拾う）
      const pending = (await repo.listAlerts(ref.projectId, { statuses: ["open"] })).filter((a) => !a.notified_at && (a.rank === "S" || a.rank === "A"));
      const r = await notifyImmediate(
        { catalog: new CatalogRepo(env.CATALOG_DB), baseUrl: env.PUBLIC_BASE_URL, encKey: env.WEBHOOK_ENC_KEY, fetch },
        repo,
        ref.projectId,
        pending,
      );
      return r;
    });
  }
}

/**
 * 3時間ごとの取り込み（11章の全体図）。
 * OSV / NVD / KEV / EPSS → 原本をR2へ → 正規化してD1（カタログ）→ 一般緊急度 → 記事の要更新 → キャッシュのパージ → 再照会 → 通知
 */
export class IngestWorkflow extends WorkflowEntrypoint<Env, IngestParams> {
  override async run(event: Readonly<WorkflowEvent<IngestParams>>, step: WorkflowStep): Promise<unknown> {
    const env = this.env;
    const windowStart = await step.do("window", async () => new CatalogRepo(env.CATALOG_DB).ensureWindowStart());
    const touched = new Set<string>();

    // OSV（エコシステムごと）
    for (const eco of OSV_ECOSYSTEMS) {
      const list = await step.do(`osv:list:${eco}`, RETRY, async () => {
        const deps = pipelineDeps(env);
        const state = await deps.catalog.getIngestState(`osv:${eco}`);
        return listOsvUpdates(deps, eco, state?.cursor ?? windowStart);
      });
      const parts = chunk(list.ids, 100);
      for (const [i, part] of parts.entries()) {
        const ids = await step.do(`osv:fetch:${eco}:${i}`, RETRY, () => ingestOsvRecords(pipelineDeps(env), eco, part));
        ids.forEach((id) => touched.add(id));
      }
      if (list.newest) {
        await step.do(`osv:cursor:${eco}`, async () => {
          await new CatalogRepo(env.CATALOG_DB).setIngestState(`osv:${eco}`, list.newest, `${list.ids.length}件`);
          return true;
        });
      }
    }

    // NVD（ウォッチリストのCPE・CVSS）
    const nvdState = await step.do("nvd:state", async () => (await new CatalogRepo(env.CATALOG_DB).getIngestState("nvd"))?.cursor ?? null);
    const nvdUntil = await step.do("nvd:until", async () => new Date().toISOString());
    const nvd = new NvdClient(env.NVD_API_KEY);
    if (!nvdState) {
      const total = WATCHLIST.flatMap((p) => p.cpes).length;
      for (let i = 0; i < total; i++) {
        const r = await step.do(`nvd:backfill:${i}`, RETRY, () => nvdBackfillWatchlist(pipelineDeps(env), nvd, { windowStart }, i));
        r.touched.forEach((id) => touched.add(id));
        await step.sleep(`nvd:backfill:wait:${i}`, nvd.minIntervalMs);
      }
    } else {
      let index: number | null = 0;
      for (let page = 0; index !== null && page < 30; page++) {
        const from: number = index;
        const r: { touched: string[]; nextIndex: number | null } = await step.do(`nvd:page:${page}`, RETRY, () =>
          nvdIncrementalPage(pipelineDeps(env), nvd, new Date(nvdState), new Date(nvdUntil), from),
        );
        r.touched.forEach((id) => touched.add(id));
        index = r.nextIndex;
        if (index !== null) await step.sleep(`nvd:page:wait:${page}`, nvd.minIntervalMs);
      }
    }
    await step.do("nvd:cursor", async () => {
      await new CatalogRepo(env.CATALOG_DB).setIngestState("nvd", nvdUntil);
      return true;
    });
    const backlog = await step.do("nvd:backlog", RETRY, () => nvdBacklog(pipelineDeps(env), nvd, env.NVD_API_KEY ? 40 : 8));
    backlog.forEach((id) => touched.add(id));

    // KEV・EPSS
    (await step.do("kev", RETRY, () => ingestKev(pipelineDeps(env)))).forEach((id) => touched.add(id));
    (await step.do("epss", RETRY, () => ingestEpss(pipelineDeps(env)))).forEach((id) => touched.add(id));

    // 一般緊急度・掲載対象・要更新
    let changed = 0;
    for (const [i, part] of chunk([...touched], 400).entries()) {
      const r = await step.do(`derive:${i}`, RETRY, async () => new CatalogRepo(env.CATALOG_DB).refreshDerived(part, { windowStart }));
      changed += r.changed.length;
    }
    if (changed > 0) {
      await step.do("purge", RETRY, async () => {
        await purgeMediaCache(env, ["catalog"]);
        return true;
      });
    }

    if (event.payload?.rematch !== false) {
      // OSV 再照会（全テナントの「パッケージ＋バージョン」を重複排除）
      const keys = await step.do("osv:distinct", async () => new SystemRepo(env.APP_DB).distinctPackages());
      for (const [i, part] of chunk(keys, 1000).entries()) {
        await step.do(`osv:requery:${i}`, RETRY, async () => {
          const r = await refreshPackageVulns(matcherDeps(env, windowStart), part);
          return { queried: r.queried, fetched: r.fetched, osvError: r.osvError };
        });
      }
      const refs = await step.do("projects", async () => new SystemRepo(env.APP_DB).listProjectRefs());
      await matchAndNotify(env, step, windowStart, refs);
    }
    return { touched: touched.size, changed };
  }
}

/** スタックの新規登録・更新時に、そのプロジェクト分だけ即時に照会する（9-1） */
export class MatchWorkflow extends WorkflowEntrypoint<Env, MatchParams> {
  override async run(event: Readonly<WorkflowEvent<MatchParams>>, step: WorkflowStep): Promise<unknown> {
    const env = this.env;
    const { tenantId, projectId } = event.payload;
    const windowStart = await step.do("window", async () => new CatalogRepo(env.CATALOG_DB).ensureWindowStart());
    await step.do("osv:query", RETRY, async () => {
      const repo = new TenantRepo(env.APP_DB, tenantId);
      const pkgs = (await repo.listPackages(projectId)).filter((p) => p.kind === "package" && p.version);
      const keys = [...new Map(pkgs.map((p) => [`${p.ecosystem}\u0000${p.name}\u0000${p.version}`, { ecosystem: p.ecosystem, name: p.name, version: p.version! }])).values()];
      let fetched = 0;
      for (const part of chunk(keys, 1000)) fetched += (await refreshPackageVulns(matcherDeps(env, windowStart), part)).fetched;
      return { keys: keys.length, fetched };
    });
    await matchAndNotify(env, step, windowStart, [{ tenantId, projectId }]);
    return { projectId };
  }
}

/** 週次まとめ（毎週月曜09:00 JST） */
export class DigestWorkflow extends WorkflowEntrypoint<Env, Record<string, never>> {
  override async run(_event: Readonly<WorkflowEvent<Record<string, never>>>, step: WorkflowStep): Promise<unknown> {
    const env = this.env;
    const refs = await step.do("projects", async () => new SystemRepo(env.APP_DB).listProjectRefs());
    let sent = 0;
    for (const ref of refs) {
      const r = await step.do(`digest:${ref.projectId}`, RETRY, () =>
        sendDigest(
          { catalog: new CatalogRepo(env.CATALOG_DB), baseUrl: env.PUBLIC_BASE_URL, encKey: env.WEBHOOK_ENC_KEY, fetch },
          new TenantRepo(env.APP_DB, ref.tenantId),
          ref.projectId,
        ),
      );
      if (r.sent) sent++;
    }
    return { projects: refs.length, sent };
  }
}
