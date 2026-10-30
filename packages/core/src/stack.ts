import { parse as parseYaml, YAMLParseError } from "yaml";
import { z } from "zod";
import { parsePurl } from "./purl";

/**
 * stack.yaml（8-3）のスキーマ。
 * 照合・通知に使う文脈情報。パッケージの事実は bom.json（CycloneDX）に分ける。
 */
const evidence = z.string().min(1).max(500).describe("根拠ファイル（例：Dockerfile）");

const purlString = z
  .string()
  .min(5)
  .max(2000)
  .refine((v) => parsePurl(v) !== null, { message: "PURL（pkg:type/name@version）の形式ではありません" });

export const stackComponentSchema = z
  .object({
    name: z
      .string()
      .min(1)
      .max(100)
      .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "英数字・ドット・ハイフン・アンダースコアのみ使えます"),
    exposure: z.enum(["internet", "internal", "offline"]),
    exposure_reason: z.string().max(500).optional(),
    managed: z.boolean().default(false),
    sbom: z.string().min(1).max(500).optional().describe("CycloneDX JSON のパス"),
    image: z.object({ purl: purlString, evidence: evidence.optional() }).strict().optional(),
    middleware: z.array(z.object({ purl: purlString, evidence: evidence.optional() }).strict()).max(200).optional(),
    cdn_scripts: z
      .array(
        z
          .object({
            name: z.string().min(1).max(200),
            url: z.string().url().max(2000),
            evidence: evidence.optional(),
          })
          .strict(),
      )
      .max(200)
      .optional(),
  })
  .strict();

export const stackSchema = z
  .object({
    schema_version: z.literal("1.0", {
      error: 'schema_version は文字列 "1.0" をクォートして書いてください',
    }),
    generated_at: z.string().max(64).optional(),
    generated_by: z.string().max(200).optional(),
    service: z
      .object({
        name: z.string().min(1).max(200),
        data_sensitivity: z.enum(["high", "medium", "low"]),
      })
      .strict(),
    components: z.array(stackComponentSchema).min(1).max(500),
  })
  .strict()
  .superRefine((stack, ctx) => {
    const seen = new Set<string>();
    stack.components.forEach((c, i) => {
      if (seen.has(c.name)) {
        ctx.addIssue({ code: "custom", path: ["components", i, "name"], message: `component名 "${c.name}" が重複しています` });
      }
      seen.add(c.name);
    });
  });

export type Stack = z.infer<typeof stackSchema>;
export type StackComponent = z.infer<typeof stackComponentSchema>;

export interface StackIssue {
  path: string;
  message: string;
}

export type StackParseResult =
  | { ok: true; stack: Stack; warnings: StackIssue[] }
  | { ok: false; errors: StackIssue[] };

function pathToString(path: ReadonlyArray<PropertyKey>): string {
  return path.reduce<string>((acc, seg) => {
    if (typeof seg === "number") return `${acc}[${seg}]`;
    return acc ? `${acc}.${String(seg)}` : String(seg);
  }, "");
}

/**
 * YAML を読んでスキーマ検証する。
 * バージョンは文字列でのクォートが必須なので、YAMLのコア型（数値の自動変換あり）で読み、
 * 数値になったバージョンはスキーマで弾く。
 */
export function parseStackYaml(source: string): StackParseResult {
  if (source.length > 1_000_000) {
    return { ok: false, errors: [{ path: "", message: "stack.yaml が大きすぎます（1MBまで）" }] };
  }
  let raw: unknown;
  try {
    raw = parseYaml(source, { maxAliasCount: 50, uniqueKeys: true });
  } catch (e) {
    const message = e instanceof YAMLParseError ? e.message : String(e);
    return { ok: false, errors: [{ path: "", message: `YAMLとして読めません：${message}` }] };
  }
  const result = stackSchema.safeParse(raw);
  if (!result.success) {
    return {
      ok: false,
      errors: result.error.issues.map((i) => ({ path: pathToString(i.path), message: i.message })),
    };
  }
  return { ok: true, stack: result.data, warnings: lintStack(result.data) };
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const SECRET_RE = /(?:api[_-]?key|secret|token|password|passwd|bearer|AKIA[0-9A-Z]{16}|xox[baprs]-|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})/i;
const URL_RE = /https?:\/\/[^\s)]+/i;

/**
 * 書いてはいけない情報（8-4 の5）の簡易チェック。
 * ホスト名・IP・URL（CDN以外）・秘密情報らしき文字列を警告する。
 */
export function lintStack(stack: Stack): StackIssue[] {
  const warnings: StackIssue[] = [];
  const check = (path: string, value: string | undefined, allowUrl = false) => {
    if (!value) return;
    if (IPV4_RE.test(value) && !/^pkg:/.test(value)) {
      warnings.push({ path, message: "IPアドレスらしき値が含まれています。削除してください" });
    }
    if (!allowUrl && URL_RE.test(value)) {
      warnings.push({ path, message: "URLが含まれています。CDN以外のURLは書かないでください" });
    }
    if (SECRET_RE.test(value)) {
      warnings.push({ path, message: "秘密情報らしき文字列が含まれています。削除してください" });
    }
  };
  check("service.name", stack.service.name);
  stack.components.forEach((c, i) => {
    const base = `components[${i}]`;
    check(`${base}.exposure_reason`, c.exposure_reason);
    c.middleware?.forEach((m, j) => check(`${base}.middleware[${j}].evidence`, m.evidence));
    c.cdn_scripts?.forEach((s, j) => {
      check(`${base}.cdn_scripts[${j}].url`, s.url, true);
      check(`${base}.cdn_scripts[${j}].evidence`, s.evidence);
    });
    if (!c.sbom && !c.image && !c.middleware?.length && !c.cdn_scripts?.length) {
      warnings.push({ path: base, message: "sbom・image・middleware・cdn_scripts のいずれもありません。照合対象がありません" });
    }
  });
  return warnings;
}

/** 配布用の JSON Schema（schemas/stack.schema.json の生成元） */
export function stackJsonSchema(): Record<string, unknown> {
  const schema = z.toJSONSchema(stackSchema, { target: "draft-2020-12", io: "input", unrepresentable: "any" });
  return {
    $id: "urn:ichiji-matome:schema:stack:1.0",
    title: "一次対応まとめ stack.yaml",
    description: "照合・通知のための文脈情報。パッケージの事実は CycloneDX JSON（bom.json）に記載する。バージョンは必ず文字列でクォートする。",
    ...schema,
  };
}
