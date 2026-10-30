import { Hono, type Context } from "hono";
import {
  buildArticleGenerationPrompt,
  encryptSecret,
  decryptSecret,
  generateApiToken,
  isAlertStatus,
  isSlackWebhookUrl,
  MY_ENVIRONMENT_MAX_CHARS,
  postSlack,
  randomId,
  sha256Hex,
  suggestSlug,
  SITE,
  isTopicKey,
  type TopicKey,
} from "@ichiji/core";
import { AccountRepo, CatalogRepo, SystemRepo, TenantRepo } from "@ichiji/db";
import { getAuth, getSessionUser, isAdminEmail, type SessionUser } from "./auth";
import { importArticles, processStackUpload, readStackUpload } from "./services";

/** Astro のキャッシュ（ルートキャッシュ）を無効化する口 */
export interface CacheInvalidator {
  invalidate(options: { tags?: string | string[]; path?: string }): Promise<void>;
}

type Bindings = { E: Env; CACHE: CacheInvalidator | null };
type Variables = { user: SessionUser; tenantId: string };
type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>().basePath("/api");

// APIの応答はキャッシュさせない
app.use("*", async (c, next) => {
  await next();
  c.header("cache-control", "no-store");
});

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: "サーバでエラーが発生しました" }, 500);
});

// ---------- 認証（Better Auth） ----------

app.on(["GET", "POST"], "/auth/*", (c) => getAuth(c.env.E).handler(c.req.raw));

// ---------- セッション必須のミドルウェア ----------

const requireUser = async (c: AppContext, next: () => Promise<void>) => {
  const s = await getSessionUser(c.env.E, c.req.raw.headers);
  if (!s) return c.json({ error: "ログインが必要です" }, 401);
  const tenantId = await new AccountRepo(c.env.E.APP_DB).ensureTenant(s.user.id, s.user.email, () => randomId());
  c.set("user", s.user);
  c.set("tenantId", tenantId);
  await next();
};

const requireAdmin = async (c: AppContext, next: () => Promise<void>) => {
  const s = await getSessionUser(c.env.E, c.req.raw.headers);
  if (!s) return c.json({ error: "ログインが必要です" }, 401);
  if (!isAdminEmail(c.env.E, s.user.email)) return c.json({ error: "権限がありません" }, 403);
  c.set("user", s.user);
  await next();
};

const tenant = (c: AppContext) => new TenantRepo(c.env.E.APP_DB, c.get("tenantId"));
const pid = (c: AppContext) => c.req.param("id") ?? "";

// ---------- 会員 ----------

app.get("/me", async (c) => {
  const s = await getSessionUser(c.env.E, c.req.raw.headers);
  if (!s) return c.json({ user: null });
  return c.json({ user: { email: s.user.email, name: s.user.name, twoFactorEnabled: s.user.twoFactorEnabled }, isAdmin: isAdminEmail(c.env.E, s.user.email) });
});

/** 私の環境（6-4）。記事ページはキャッシュされるので、ログイン中だけここから取得する */
app.get("/me/environment", requireUser, async (c) => {
  const env = await new AccountRepo(c.env.E.APP_DB).getMyEnvironment(c.get("user").id);
  return c.json({ text: env.text, updatedAt: env.updatedAt, maxChars: MY_ENVIRONMENT_MAX_CHARS });
});

app.put("/me/environment", requireUser, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { text?: unknown } | null;
  if (!body || typeof body.text !== "string") return c.json({ error: "text がありません" }, 400);
  if ([...body.text].length > MY_ENVIRONMENT_MAX_CHARS) return c.json({ error: `${MY_ENVIRONMENT_MAX_CHARS}文字までです` }, 400);
  await new AccountRepo(c.env.E.APP_DB).setMyEnvironment(c.get("user").id, body.text);
  return c.json({ ok: true });
});

// ---------- 閲覧数（ランキング用。Analytics Engine） ----------

app.post("/views", async (c) => {
  const body = (await c.req.json().catch(() => null)) as { slug?: unknown; topic?: unknown } | null;
  const slug = typeof body?.slug === "string" ? body.slug : "";
  const topic = typeof body?.topic === "string" ? body.topic : "";
  if (!/^[a-z0-9-]{3,120}$/.test(slug) || !isTopicKey(topic)) return c.body(null, 204);
  c.env.E.VIEWS?.writeDataPoint({ blobs: [slug, topic], indexes: [slug] });
  return c.body(null, 204);
});

// ---------- プロジェクト ----------

app.get("/projects", requireUser, async (c) => {
  const repo = tenant(c);
  const projects = await repo.listProjects();
  return c.json({ projects: await Promise.all(projects.map(async (p) => ({ ...p, counts: await repo.alertCounts(p.id) }))) });
});

app.post("/projects", requireUser, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { name?: unknown } | null;
  const name = typeof body?.name === "string" ? body.name.trim() : "";
  if (!name || name.length > 100) return c.json({ error: "プロジェクト名を100文字以内で入力してください" }, 400);
  const project = await tenant(c).createProject({ id: randomId(12), name });
  return c.json({ project }, 201);
});

app.patch("/projects/:id", requireUser, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { name?: unknown } | null;
  const name = typeof body?.name === "string" ? body.name.trim() : "";
  if (!name || name.length > 100) return c.json({ error: "プロジェクト名を100文字以内で入力してください" }, 400);
  const ok = await tenant(c).renameProject(pid(c), name);
  return ok ? c.json({ ok }) : c.json({ error: "見つかりません" }, 404);
});

app.delete("/projects/:id", requireUser, async (c) => {
  const ok = await tenant(c).deleteProject(pid(c));
  return ok ? c.json({ ok }) : c.json({ error: "見つかりません" }, 404);
});

/** プロジェクトごとのAPIトークンを発行し直す。トークンはこの応答でだけ返す */
app.post("/projects/:id/token", requireUser, async (c) => {
  const t = await generateApiToken();
  const ok = await tenant(c).setApiToken(pid(c), t.hash, t.hint);
  return ok ? c.json({ token: t.token, hint: t.hint }) : c.json({ error: "見つかりません" }, 404);
});

/** Slack Incoming Webhook（暗号化して保存。12章） */
app.put("/projects/:id/slack", requireUser, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { webhookUrl?: unknown } | null;
  const url = body?.webhookUrl;
  const repo = tenant(c);
  const projectId = pid(c);
  if (url === null || url === "") {
    const ok = await repo.setSlackWebhook(projectId, null);
    return ok ? c.json({ ok }) : c.json({ error: "見つかりません" }, 404);
  }
  if (typeof url !== "string" || !isSlackWebhookUrl(url)) return c.json({ error: "Slack の Incoming Webhook URL を入力してください" }, 400);
  const enc = await encryptSecret(url.trim(), c.env.E.WEBHOOK_ENC_KEY, `${repo.tenantId}:${projectId}`);
  const ok = await repo.setSlackWebhook(projectId, enc);
  return ok ? c.json({ ok }) : c.json({ error: "見つかりません" }, 404);
});

app.post("/projects/:id/slack/test", requireUser, async (c) => {
  const repo = tenant(c);
  const projectId = pid(c);
  const enc = await repo.getSlackWebhookEnc(projectId);
  if (!enc) return c.json({ error: "Webhook が未設定です" }, 400);
  const url = await decryptSecret(enc, c.env.E.WEBHOOK_ENC_KEY, `${repo.tenantId}:${projectId}`);
  try {
    await postSlack(url, { text: `${SITE.name}：テスト通知です。`, blocks: [{ type: "section", text: { type: "mrkdwn", text: `*${SITE.name}* からのテスト通知です。S・Aは即時、B以下は毎週月曜09:00にまとめて届きます。` } }] });
    await repo.logNotification({ id: randomId(), projectId, kind: "test", ok: true });
    return c.json({ ok: true });
  } catch (e) {
    await repo.logNotification({ id: randomId(), projectId, kind: "test", ok: false, detail: String(e) });
    return c.json({ error: "送信に失敗しました。URLを確認してください" }, 502);
  }
});

/** 画面からのスタック登録 */
app.post("/projects/:id/stack", requireUser, async (c) => {
  const upload = await readStackUpload(c.req.raw);
  if ("error" in upload) return c.json({ ok: false, errors: [{ path: "", message: upload.error }] }, 400);
  const r = await processStackUpload(c.env.E, tenant(c), pid(c), upload, "ui");
  return c.json(r, r.ok ? 200 : 400);
});

app.get("/projects/:id/alerts", requireUser, async (c) => {
  const alerts = await tenant(c).listAlerts(pid(c), { includeResolved: c.req.query("resolved") === "1" });
  return c.json({ alerts });
});

app.patch("/projects/:id/alerts/:alertId", requireUser, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { status?: unknown } | null;
  const status = typeof body?.status === "string" ? body.status : "";
  if (!isAlertStatus(status)) return c.json({ error: "状態が不正です" }, 400);
  const ok = await tenant(c).updateAlertStatus(pid(c), (c.req.param("alertId") ?? ""), status, c.get("user").id);
  return ok ? c.json({ ok }) : c.json({ error: "見つかりません" }, 404);
});

// ---------- CI からのスタック登録（プロジェクトごとのAPIトークン） ----------

app.post("/v1/stack", async (c) => {
  const auth = c.req.header("authorization") ?? "";
  const m = /^Bearer\s+(\S+)$/i.exec(auth);
  if (!m) return c.json({ ok: false, errors: [{ path: "", message: "Authorization: Bearer <APIトークン> が必要です" }] }, 401);
  const ref = await new SystemRepo(c.env.E.APP_DB).findProjectByTokenHash(await sha256Hex(m[1]!));
  if (!ref) return c.json({ ok: false, errors: [{ path: "", message: "APIトークンが無効です" }] }, 401);
  const upload = await readStackUpload(c.req.raw);
  if ("error" in upload) return c.json({ ok: false, errors: [{ path: "", message: upload.error }] }, 400);
  const r = await processStackUpload(c.env.E, new TenantRepo(c.env.E.APP_DB, ref.tenantId), ref.projectId, upload, "api");
  return c.json(r, r.ok ? 200 : 400);
});

// ---------- 管理画面（10章） ----------

app.post("/admin/prompt", requireAdmin, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { cveIds?: unknown } | null;
  const ids = Array.isArray(body?.cveIds) ? body.cveIds.filter((x): x is string => typeof x === "string").slice(0, 30) : [];
  if (!ids.length) return c.json({ error: "CVEを選んでください" }, 400);
  const catalog = new CatalogRepo(c.env.E.CATALOG_DB);
  const facts = await catalog.getFactsMany(ids);
  const items = [];
  for (const id of ids) {
    const f = facts.find((x) => x.id === id);
    if (!f) continue;
    const existing = await catalog.getArticleByCve(id);
    const topic = (existing?.topic ?? f.topic) as TopicKey | null;
    if (!topic || !isTopicKey(topic)) continue;
    items.push({ facts: f, topic, slug: existing?.slug ?? suggestSlug(f), regenerate: Boolean(existing) });
  }
  return c.json({ prompt: buildArticleGenerationPrompt(items), count: items.length });
});

app.post("/admin/import", requireAdmin, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { text?: unknown; correctionNote?: unknown } | null;
  if (typeof body?.text !== "string" || !body.text.trim()) return c.json({ error: "貼り付けたテキストがありません" }, 400);
  if (body.text.length > 2_000_000) return c.json({ error: "一度に貼り付けられるのは2MBまでです" }, 400);
  const results = await importArticles(new CatalogRepo(c.env.E.CATALOG_DB), body.text, {
    correctionNote: typeof body.correctionNote === "string" ? body.correctionNote : undefined,
  });
  if (results.some((r) => r.status !== "rejected")) await c.env.CACHE?.invalidate({ tags: ["catalog"] }).catch(() => {});
  return c.json({ results });
});

app.post("/admin/pin", requireAdmin, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { slug?: unknown; pinned?: unknown } | null;
  if (typeof body?.slug !== "string") return c.json({ error: "slug がありません" }, 400);
  await new CatalogRepo(c.env.E.CATALOG_DB).setPinned(body.slug, body.pinned === true);
  await c.env.CACHE?.invalidate({ tags: ["catalog"] }).catch(() => {});
  return c.json({ ok: true });
});

app.get("/admin/drafts/:id", requireAdmin, async (c) => {
  const draft = await new CatalogRepo(c.env.E.CATALOG_DB).getDraft(Number(pid(c)));
  return draft ? c.json(draft) : c.json({ error: "見つかりません" }, 404);
});

app.delete("/admin/drafts/:id", requireAdmin, async (c) => {
  await new CatalogRepo(c.env.E.CATALOG_DB).deleteDraft(Number(pid(c)));
  return c.json({ ok: true });
});

// ---------- 内部（jobs ワーカーからのキャッシュのパージ） ----------

app.post("/internal/purge", async (c) => {
  const token = c.req.header("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  const expected = c.env.E.INTERNAL_TOKEN;
  if (!expected || token.length !== expected.length || (await sha256Hex(token)) !== (await sha256Hex(expected))) {
    return c.json({ error: "forbidden" }, 403);
  }
  const body = (await c.req.json().catch(() => null)) as { tags?: unknown } | null;
  const tags = Array.isArray(body?.tags) ? body.tags.filter((t): t is string => typeof t === "string") : ["catalog"];
  await c.env.CACHE?.invalidate({ tags });
  return c.json({ ok: true, tags });
});

app.notFound((c) => c.json({ error: "not found" }, 404));

export function handleApi(request: Request, env: Env, cache: CacheInvalidator | null, ctx?: ExecutionContext): Response | Promise<Response> {
  return app.fetch(request, { E: env, CACHE: cache }, ctx);
}
