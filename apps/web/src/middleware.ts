import { defineMiddleware } from "astro:middleware";
import { getEnv } from "./server/env";
import { getSessionUser, isAdminEmail } from "./server/auth";

/**
 * - /app/*（会員）と /admin/*（管理者）はログイン必須。キャッシュさせない
 * - 全ページにセキュリティヘッダーを付ける
 */
export const onRequest = defineMiddleware(async (context, next) => {
  const path = context.url.pathname;
  const isApp = path === "/app" || path.startsWith("/app/");
  const isAdmin = path === "/admin" || path.startsWith("/admin/");

  if (isApp || isAdmin) {
    const env = getEnv();
    const s = await getSessionUser(env, context.request.headers);
    if (!s) return context.redirect(`/login/?next=${encodeURIComponent(path + context.url.search)}`, 302);
    context.locals.user = s.user;
    context.locals.sessionId = s.sessionId;
    context.locals.isAdmin = isAdminEmail(env, s.user.email);
    if (isAdmin && !context.locals.isAdmin) return new Response("権限がありません", { status: 403 });
  }

  const response = await next();
  const headers = response.headers;
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("x-frame-options", "DENY");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  if (isApp || isAdmin) headers.set("cache-control", "private, no-store");
  return response;
});
