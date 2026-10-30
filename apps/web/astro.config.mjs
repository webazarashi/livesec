// @ts-check
import { defineConfig } from "astro/config";
import cloudflare from "@astrojs/cloudflare";
import { cacheCloudflare } from "@astrojs/cloudflare/cache";

export default defineConfig({
  output: "server",
  adapter: cloudflare({ imageService: "passthrough" }),
  // Astro のセッションは使わない（認証は Better Auth）
  session: false,
  // SSR＋エッジキャッシュ。CVE更新時に "catalog" タグでパージする（11章）
  cache: { provider: cacheCloudflare() },
  trailingSlash: "ignore",
  build: { format: "directory" },
  security: { checkOrigin: true },
  vite: {
    ssr: { noExternal: ["@ichiji/core", "@ichiji/db"] },
  },
});
