import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { randomId, SITE } from "@ichiji/core";
import { AccountRepo } from "@ichiji/db";

/**
 * Better Auth（メールアドレス＋パスワード）× D1。
 * 12章：MFA（TOTP）・ログイン試行のレート制限・セッション失効を初日から入れる。
 */
function create(env: Env) {
  return betterAuth({
    appName: SITE.name,
    baseURL: env.PUBLIC_BASE_URL,
    basePath: "/api/auth",
    secret: env.BETTER_AUTH_SECRET,
    // workers.dev の公開URLだけを信頼する（11章）
    trustedOrigins: [env.PUBLIC_BASE_URL],
    database: env.APP_DB,
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 10,
      maxPasswordLength: 128,
      autoSignIn: true,
      // パスワード再設定時は他のセッションを失効させる
      revokeSessionsOnPasswordReset: true,
    },
    session: {
      expiresIn: 60 * 60 * 24 * 14,
      updateAge: 60 * 60 * 24,
      freshAge: 60 * 15,
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 60,
      customRules: {
        "/sign-in/email": { window: 300, max: 5 },
        "/sign-up/email": { window: 3600, max: 5 },
        "/two-factor/verify-totp": { window: 300, max: 5 },
        "/two-factor/verify-backup-code": { window: 300, max: 5 },
        "/change-password": { window: 300, max: 5 },
      },
    },
    advanced: {
      ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] },
      useSecureCookies: env.PUBLIC_BASE_URL.startsWith("https://"),
    },
    plugins: [twoFactor({ issuer: SITE.name })],
    databaseHooks: {
      user: {
        create: {
          // 会員登録したらテナントを作る（1アカウント = 1テナント）
          after: async (user) => {
            await new AccountRepo(env.APP_DB).ensureTenant(user.id, user.email, () => randomId());
          },
        },
      },
    },
  });
}

export type Auth = ReturnType<typeof create>;

let cached: { env: Env; auth: Auth } | null = null;

export function getAuth(env: Env): Auth {
  if (cached?.env !== env) cached = { env, auth: create(env) };
  return cached.auth;
}

export function isAdminEmail(env: Env, email: string | undefined | null): boolean {
  if (!email) return false;
  return (env.ADMIN_EMAILS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .includes(email.toLowerCase());
}

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  twoFactorEnabled: boolean;
}

export async function getSessionUser(env: Env, headers: Headers): Promise<{ user: SessionUser; sessionId: string } | null> {
  const session = await getAuth(env).api.getSession({ headers });
  if (!session) return null;
  const u = session.user as typeof session.user & { twoFactorEnabled?: boolean | null };
  return {
    user: { id: u.id, email: u.email, name: u.name, twoFactorEnabled: Boolean(u.twoFactorEnabled) },
    sessionId: session.session.id,
  };
}
