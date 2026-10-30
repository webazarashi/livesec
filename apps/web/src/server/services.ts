import {
  buildExcerpt,
  combineFacts,
  factsHash,
  fnv1a64,
  markdownToPlainText,
  parseBulkArticles,
  readingMinutes,
  renderArticleMarkdown,
  splitArticleSections,
  verifyArticle,
  randomId,
  type GateMismatch,
  type TopicKey,
} from "@ichiji/core";
import { buildStackInput, CatalogRepo, type StackBuildResult, type TenantRepo } from "@ichiji/db";

// ---------- スタック登録（8章） ----------

export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

export interface StackUploadResult {
  ok: boolean;
  errors?: Array<{ path: string; message: string }>;
  warnings?: Array<{ path: string; message: string }>;
  summary?: unknown;
}

/** multipart（stack と SBOM ファイル）または JSON から stack.yaml と bom.json を取り出す */
export async function readStackUpload(request: Request): Promise<{ stackYaml: string; boms: Record<string, string> } | { error: string }> {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > MAX_UPLOAD_BYTES) return { error: "アップロードが大きすぎます（20MBまで）" };
  const type = request.headers.get("content-type") ?? "";
  if (type.includes("multipart/form-data")) {
    const form = await request.formData();
    let stackYaml: string | null = null;
    const boms: Record<string, string> = {};
    for (const [key, value] of form.entries()) {
      const text = typeof value === "string" ? value : await value.text();
      if (key === "stack" || key === "stack.yaml") stackYaml = text;
      else boms[key === "bom" && typeof value !== "string" && value.name ? value.name : key] = text;
    }
    if (!stackYaml) return { error: "stack（stack.yaml）がありません" };
    return { stackYaml, boms };
  }
  if (type.includes("application/json")) {
    const body = (await request.json().catch(() => null)) as { stack_yaml?: unknown; boms?: Record<string, unknown> } | null;
    if (!body || typeof body.stack_yaml !== "string") return { error: "stack_yaml がありません" };
    const boms: Record<string, string> = {};
    for (const [k, v] of Object.entries(body.boms ?? {})) boms[k] = typeof v === "string" ? v : JSON.stringify(v);
    return { stackYaml: body.stack_yaml, boms };
  }
  return { error: "multipart/form-data または application/json で送ってください" };
}

/** 検証 → 原本をR2へ → D1を入れ替え → そのプロジェクトだけ即時照会（キューへ） */
export async function processStackUpload(
  env: Env,
  repo: TenantRepo,
  projectId: string,
  upload: { stackYaml: string; boms: Record<string, string> },
  via: "api" | "ui",
): Promise<StackUploadResult> {
  const project = await repo.getProject(projectId);
  if (!project) return { ok: false, errors: [{ path: "", message: "プロジェクトが見つかりません" }] };
  const built: StackBuildResult = buildStackInput(upload);
  if (!built.ok) return { ok: false, errors: built.errors };

  const uploadId = randomId(12);
  const prefix = `uploads/${repo.tenantId}/${projectId}/${new Date().toISOString().replace(/[:.]/g, "-")}-${uploadId}`;
  await env.RAW.put(`${prefix}/stack.yaml`, upload.stackYaml, { httpMetadata: { contentType: "text/yaml" } });
  for (const [path, body] of Object.entries(upload.boms)) {
    await env.RAW.put(`${prefix}/boms/${path.replace(/[^A-Za-z0-9._/-]/g, "_").replace(/\.\.+/g, "_")}`, body, {
      httpMetadata: { contentType: "application/json" },
    });
  }

  await repo.replaceStack(projectId, {
    serviceName: built.stack.service.name,
    dataSensitivity: built.stack.service.data_sensitivity,
    components: built.stack.components.map((c) => ({
      name: c.name,
      exposure: c.exposure,
      exposureReason: c.exposure_reason ?? null,
      managed: c.managed,
    })),
    packages: built.packages,
  });
  await repo.recordUpload({ id: uploadId, projectId, via, r2Prefix: prefix, summary: { ...built.summary, warnings: built.warnings.length } });
  await env.JOBS_QUEUE.send({ type: "match-project", tenantId: repo.tenantId, projectId });
  return { ok: true, warnings: built.warnings, summary: built.summary };
}

// ---------- 記事の取り込み（10章） ----------

export interface ImportItemResult {
  index: number;
  slug: string | null;
  cveIds: string[];
  status: "published" | "updated" | "rejected";
  url?: string;
  errors?: string[];
  mismatches?: GateMismatch[];
}

/** まとめて貼り付けた記事を分割 → 機械照合ゲート → 通ったものだけ公開。不一致は差し戻し */
export async function importArticles(catalog: CatalogRepo, text: string, options: { correctionNote?: string } = {}): Promise<ImportItemResult[]> {
  const parsed = parseBulkArticles(text);
  const results: ImportItemResult[] = [];

  for (const err of parsed.errors) {
    await catalog.saveDraftRejection({ slug: err.hint, cveIds: [], raw: err.raw, errors: err.errors });
    results.push({ index: err.index, slug: err.hint, cveIds: [], status: "rejected", errors: err.errors });
  }

  for (const a of parsed.articles) {
    const fm = a.frontMatter;
    const facts = await catalog.getFactsMany(fm.cve_ids);
    const gate = verifyArticle(fm, facts);
    const errors: string[] = [];
    const notInScope = facts.filter((f) => !f.inScope).map((f) => f.id);
    if (notInScope.length) errors.push(`対象範囲外のCVEです：${notInScope.join(", ")}`);
    const existing = await catalog.getArticleBySlug(fm.slug);
    if (existing && existing.primary_cve !== fm.cve_ids[0]) errors.push(`slug「${fm.slug}」は別のCVEの記事で使われています`);
    for (const id of fm.cve_ids) {
      const other = await catalog.getArticleByCve(id);
      if (other && other.slug !== fm.slug) errors.push(`${id} はすでに記事「${other.slug}」があります。同じslugで再生成してください`);
    }

    if (!gate.ok || errors.length) {
      const all = [...errors, ...gate.mismatches.map((m) => `${m.message}（期待：${m.expected} ／ 記事：${m.actual}）`)];
      await catalog.saveDraftRejection({ slug: fm.slug, cveIds: fm.cve_ids, raw: a.raw, errors: all });
      results.push({ index: a.index, slug: fm.slug, cveIds: fm.cve_ids, status: "rejected", errors, mismatches: gate.mismatches });
      continue;
    }

    const sections = splitArticleSections(a.body);
    const main = renderArticleMarkdown(sections.main, { idPrefix: "sec" });
    const check = sections.check ? renderArticleMarkdown(sections.check, { idPrefix: "chk" }) : null;
    const summary = sections.summary ? renderArticleMarkdown(sections.summary, { idPrefix: "sum" }) : null;
    const ordered = fm.cve_ids.map((id) => facts.find((f) => f.id === id)!);
    const primary = ordered[0]!;
    const hash = ordered.length === 1 ? factsHash(primary) : fnv1a64(JSON.stringify(combineFacts(ordered)));
    const toc = [
      ...main.toc,
      ...(check ? [{ id: "check-commands", text: "自環境の確認コマンド", depth: 2 }] : []),
      ...(summary ? [{ id: "summary", text: "まとめ", depth: 2 }] : []),
    ];
    const tags = [...new Set([...(fm.tags ?? []), ...primary.packages.slice(0, 2).map((p) => p.name)])].slice(0, 10);
    const r = await catalog.publishArticle({
      slug: fm.slug,
      topic: fm.topic as TopicKey,
      title: fm.title,
      whyRead: fm.why_read,
      points: fm.points,
      gains: fm.gains,
      faq: fm.faq,
      sources: fm.sources,
      tags,
      bodyMd: a.body,
      bodyHtml: main.html,
      checkHtml: check?.html ?? null,
      summaryHtml: summary?.html ?? null,
      toc,
      excerpt: buildExcerpt(a.body),
      description: markdownToPlainText(fm.why_read, 160),
      readingMinutes: readingMinutes(a.body),
      cveIds: fm.cve_ids,
      rank: primary.rank,
      factsHash: hash,
      revisionKind: existing && existing.needs_update ? "update" : "correction",
      revisionNote:
        existing && existing.needs_update
          ? "ソースデータの更新にあわせて内容を更新しました"
          : options.correctionNote?.trim() || "記事の内容を訂正しました",
    });
    results.push({
      index: a.index,
      slug: fm.slug,
      cveIds: fm.cve_ids,
      status: r.created ? "published" : "updated",
      url: `/${fm.topic}/${fm.slug}/`,
    });
  }
  return results.sort((x, y) => x.index - y.index);
}
