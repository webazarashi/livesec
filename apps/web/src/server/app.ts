import { randomId } from "@ichiji/core";
import { AccountRepo, TenantRepo } from "@ichiji/db";
import { getEnv } from "./env";

/** ログイン中のユーザーのテナントのリポジトリ（12章：テナントのデータは必ずこれを通す） */
export async function tenantRepoFor(locals: App.Locals): Promise<TenantRepo> {
  const user = locals.user;
  if (!user) throw new Error("not signed in");
  const env = getEnv();
  const tenantId = await new AccountRepo(env.APP_DB).ensureTenant(user.id, user.email, () => randomId());
  return new TenantRepo(env.APP_DB, tenantId);
}
