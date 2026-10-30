import type { CatalogRepo } from "@ichiji/db";

/**
 * 人気ランキング（24時間・月間）。Workers Analytics Engine の SQL API で集計し、D1 に確定する（11章）。
 * web ワーカーが記事の閲覧ごとに blob1 = slug で書き込んでいる。
 */
export async function computeRankings(
  catalog: CatalogRepo,
  options: { accountId?: string; token?: string; dataset: string; fetch: typeof fetch },
): Promise<{ ok: boolean; reason?: string }> {
  if (!options.accountId || !options.token) return { ok: false, reason: "CF_ACCOUNT_ID / CF_ANALYTICS_TOKEN が未設定" };
  if (!/^[A-Za-z0-9_]+$/.test(options.dataset)) return { ok: false, reason: "dataset 名が不正" };
  for (const [period, interval] of [
    ["24h", "1' DAY"],
    ["30d", "30' DAY"],
  ] as const) {
    const sql = `SELECT blob1 AS slug, SUM(_sample_interval) AS views FROM ${options.dataset} WHERE timestamp > NOW() - INTERVAL '${interval} GROUP BY slug ORDER BY views DESC LIMIT 20`;
    const res = await options.fetch(`https://api.cloudflare.com/client/v4/accounts/${options.accountId}/analytics_engine/sql`, {
      method: "POST",
      headers: { authorization: `Bearer ${options.token}` },
      body: sql,
    });
    if (!res.ok) return { ok: false, reason: `Analytics Engine ${res.status}` };
    const json = (await res.json()) as { data?: Array<{ slug: string; views: number | string }> };
    await catalog.saveRankings(
      period,
      (json.data ?? []).map((r) => ({ slug: r.slug, views: Number(r.views) })),
    );
  }
  return { ok: true };
}
