import { env as cfEnv } from "cloudflare:workers";

/** Cloudflare のバインディング（Astro 6 以降は cloudflare:workers から読む） */
export function getEnv(): Env {
  return cfEnv as unknown as Env;
}
