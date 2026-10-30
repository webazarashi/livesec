import type { AstroGlobal } from "astro";
import { CatalogRepo } from "@ichiji/db";
import { getEnv } from "./env";

/**
 * メディアのページはエッジキャッシュする（11章）。CVE更新・記事公開時に "catalog" タグでパージする。
 * 個人の情報（ログイン状態・私の環境）はHTMLに入れず、ブラウザ側でAPIから取得する（6-4・12章）。
 */
export function cacheMediaPage(astro: Pick<AstroGlobal, "cache">, maxAge = 300): void {
  try {
    astro.cache.set({ maxAge, swr: 3600, tags: ["catalog"] });
  } catch {
    // キャッシュ未設定の環境（開発時など）
  }
}

export function catalog(): CatalogRepo {
  return new CatalogRepo(getEnv().CATALOG_DB);
}

export function pageParam(url: URL): number {
  const n = Number.parseInt(url.searchParams.get("page") ?? "1", 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 500) : 1;
}
