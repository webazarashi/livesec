import { defineConfig } from "vitest/config";

// サーバ側のロジック（services.ts）だけを Node で検証する。Astro・workerd は使わない
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
