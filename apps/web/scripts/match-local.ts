/**
 * ローカル開発用：登録済みのプロジェクトを照合する（本番は jobs ワーカーが3時間ごと・登録時に実行する）。
 * OSV には問い合わせず、ローカルのカタログの影響範囲から querybatch の結果を作る（オフラインで動かすため）。
 *   pnpm --filter @ichiji/web match:local
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { satisfiesRange, randomId, type OsvQuery } from "@ichiji/core";
import { CatalogRepo, SystemRepo, TenantRepo, matchProject, refreshPackageVulns } from "@ichiji/db";
import { ShimD1 } from "../../../packages/db/test/d1-shim";

const dir = join(import.meta.dirname, "../.wrangler/state/v3/d1/miniflare-D1DatabaseObject");
let catalogDb: ShimD1 | null = null;
let appDb: ShimD1 | null = null;
for (const f of readdirSync(dir).filter((x) => x.endsWith(".sqlite") && x !== "metadata.sqlite")) {
  const db = new ShimD1(join(dir, f));
  const has = (t: string) => db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(t);
  if (has("vulns")) catalogDb = db;
  if (has("tenants")) appDb = db;
}
if (!catalogDb || !appDb) throw new Error("ローカルのD1が見つかりません");

const catalog = new CatalogRepo(catalogDb as unknown as D1Database);
const system = new SystemRepo(appDb as unknown as D1Database);

/** カタログの vuln_packages から querybatch を模擬する */
const osv = {
  async queryBatch(queries: OsvQuery[]) {
    return queries.map((q) => {
      const rows = catalogDb!.raw
        .prepare("SELECT source, affected FROM vuln_packages WHERE ecosystem = ? AND name = ?")
        .all(q.package.ecosystem, q.package.name) as Array<{ source: string; affected: string }>;
      return rows.filter((r) => satisfiesRange(q.version, r.affected)).map((r) => ({ id: r.source, modified: "" }));
    });
  },
  async getVuln() {
    return null;
  },
};

const windowStart = (await catalog.getMeta("window_start")) ?? new Date(Date.now() - 30 * 86_400_000).toISOString();
const deps = { catalog, system, osv, newId: () => randomId(), window: { windowStart } };
const r = await refreshPackageVulns(deps, await system.distinctPackages());
console.log(`querybatch: ${r.queried}件`);
for (const ref of await system.listProjectRefs()) {
  const m = await matchProject(deps, new TenantRepo(appDb as unknown as D1Database, ref.tenantId), ref.projectId);
  console.log(`${ref.projectId}: 該当 ${m.matched}件 ／ 新規 ${m.created.length}件 ／ 解消 ${m.resolved}件`);
  for (const a of m.created) console.log(`  ${a.rank}（一般${a.general_rank}）${a.vuln_id} ${a.package_label} ${a.installed_version ?? "unknown"} @${a.component}`);
}
