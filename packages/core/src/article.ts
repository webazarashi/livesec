import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { TOPIC_KEYS } from "./topics";

/** まとめて貼り付けたときの1件ごとの区切り（10-3） */
export const ARTICLE_SEPARATOR = "=====ARTICLE=====";

const cveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/, "CVE番号の形式ではありません（例：CVE-2026-12345）");

export const articleFrontMatterSchema = z
  .object({
    cve_ids: z.array(cveId).min(1).max(20),
    title: z.string().min(5).max(200),
    slug: z
      .string()
      .min(3)
      .max(120)
      .regex(/^[a-z0-9][a-z0-9-]*[a-z0-9]$/, "slug は英小文字・数字・ハイフンのみ使えます"),
    topic: z.enum(TOPIC_KEYS as [string, ...string[]]),
    packages: z.array(z.string().startsWith("pkg:")).min(1).max(50),
    affected: z.string().min(1).max(2000),
    fixed: z.array(z.coerce.string()).max(100),
    cvss: z.number().min(0).max(10).nullable(),
    why_read: z.string().min(1).max(600),
    points: z.array(z.string().min(1).max(300)).min(1).max(5),
    gains: z.array(z.string().min(1).max(300)).min(1).max(10),
    faq: z
      .array(z.object({ q: z.string().min(1).max(300), a: z.string().min(1).max(2000) }))
      .max(10)
      .default([]),
    sources: z
      .array(
        z.object({
          title: z.string().min(1).max(300),
          url: z.string().url().refine((u) => /^https?:\/\//.test(u), "http(s) のURLのみ使えます"),
          note: z.string().max(300).optional(),
        }),
      )
      .min(1)
      .max(30),
    tags: z.array(z.string().min(1).max(40)).max(10).optional(),
  })
  .passthrough();

export type ArticleFrontMatter = z.infer<typeof articleFrontMatterSchema>;

export interface ParsedArticle {
  index: number;
  frontMatter: ArticleFrontMatter;
  body: string;
  raw: string;
}

export interface ArticleParseError {
  index: number;
  /** 区切りの直後から推定したslug（エラー表示用） */
  hint: string | null;
  errors: string[];
  raw: string;
}

export interface BulkParseResult {
  articles: ParsedArticle[];
  errors: ArticleParseError[];
}

/** まとめて貼り付けたテキストを1件ずつに分割する */
export function splitBulkArticles(text: string): string[] {
  const normalized = text.replace(/\r\n?/g, "\n");
  return normalized
    .split(new RegExp(`^\\s*${ARTICLE_SEPARATOR}\\s*$`, "m"))
    .map((chunk) => chunk.trim())
    .filter((chunk) => chunk.length > 0)
    .map(stripCodeFence);
}

/** ChatGPT が ```markdown ... ``` で囲んで出力した場合に外す */
function stripCodeFence(chunk: string): string {
  const m = /^```[a-z]*\n([\s\S]*?)\n```$/i.exec(chunk);
  return m ? m[1]!.trim() : chunk;
}

export function parseArticle(chunk: string, index = 0): ParsedArticle | ArticleParseError {
  const m = /^---\n([\s\S]*?)\n---\n?([\s\S]*)$/.exec(chunk.trim());
  const hint = /^slug:\s*"?([^"\n]+)"?/m.exec(chunk)?.[1] ?? null;
  if (!m) return { index, hint, errors: ["先頭に `---` で囲んだフロントマターがありません"], raw: chunk };
  let data: unknown;
  try {
    data = parseYaml(m[1]!, { maxAliasCount: 10 });
  } catch (e) {
    return { index, hint, errors: [`フロントマターをYAMLとして読めません：${(e as Error).message}`], raw: chunk };
  }
  const result = articleFrontMatterSchema.safeParse(data);
  if (!result.success) {
    return {
      index,
      hint,
      errors: result.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`),
      raw: chunk,
    };
  }
  const body = m[2]!.trim();
  if (body.length < 50) return { index, hint, errors: ["本文が短すぎます"], raw: chunk };
  if (body.length > 100_000) return { index, hint, errors: ["本文が長すぎます（10万文字まで）"], raw: chunk };
  return { index, frontMatter: result.data, body, raw: chunk };
}

export function parseBulkArticles(text: string): BulkParseResult {
  const result: BulkParseResult = { articles: [], errors: [] };
  splitBulkArticles(text).forEach((chunk, i) => {
    const parsed = parseArticle(chunk, i);
    if ("errors" in parsed) result.errors.push(parsed);
    else result.articles.push(parsed);
  });
  return result;
}

export function isParseError(v: ParsedArticle | ArticleParseError): v is ArticleParseError {
  return "errors" in v;
}

/** 本文の見出しのうち、専用ブロックに出すもの（5-3 の12・13） */
export const SPECIAL_SECTIONS = {
  check: ["自環境の確認コマンド", "確認コマンド"],
  summary: ["まとめ"],
} as const;

export interface ArticleSections {
  main: string;
  check: string | null;
  summary: string | null;
}

/** 本文を「本文」「自環境の確認コマンド」「まとめ」に分ける。見出しはH2で判定する */
export function splitArticleSections(body: string): ArticleSections {
  const lines = body.replace(/\r\n?/g, "\n").split("\n");
  const sections: Array<{ heading: string | null; lines: string[] }> = [{ heading: null, lines: [] }];
  let inFence = false;
  for (const line of lines) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
    const h2 = !inFence ? /^##\s+(.+?)\s*#*\s*$/.exec(line) : null;
    if (h2) sections.push({ heading: h2[1]!.trim(), lines: [] });
    else sections[sections.length - 1]!.lines.push(line);
  }
  const isOf = (heading: string | null, names: readonly string[]) =>
    heading !== null && names.some((n) => heading.replace(/[\s　]/g, "").startsWith(n));
  const main: string[] = [];
  let check: string | null = null;
  let summary: string | null = null;
  for (const s of sections) {
    const text = s.lines.join("\n").trim();
    if (isOf(s.heading, SPECIAL_SECTIONS.check)) check = text;
    else if (isOf(s.heading, SPECIAL_SECTIONS.summary)) summary = text;
    else main.push(s.heading ? `## ${s.heading}\n\n${text}` : text);
  }
  return { main: main.join("\n\n").trim(), check, summary };
}

/** 読了時間（日本語は1分あたり約600字） */
export function readingMinutes(body: string): number {
  const text = body.replace(/```[\s\S]*?```/g, "").replace(/[#>*_`|\-\[\]()]/g, "");
  return Math.max(1, Math.round(text.length / 600));
}
