import { Marked, type Tokens } from "marked";

export interface TocItem {
  id: string;
  text: string;
  depth: number;
}

export interface RenderedMarkdown {
  html: string;
  toc: TocItem[];
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeHref(href: string): string | null {
  const h = href.trim();
  if (/^https?:\/\//i.test(h) || h.startsWith("/") || h.startsWith("#")) return h;
  return null;
}

const CONTAINER_LABELS: Record<string, string> = {
  summary: "この章のまとめ",
  note: "補足",
  warning: "注意",
};

/**
 * 記事本文の Markdown を HTML にする。
 * - 生のHTMLは使わせない（エスケープして表示）。ChatGPTの出力を貼るため
 * - `:::summary` 〜 `:::` を章末のまとめボックスにする
 * - 見出しにIDを振り、目次を作る
 * - コードブロックにコピーボタンを付ける
 */
export function renderArticleMarkdown(markdown: string, options: { idPrefix?: string } = {}): RenderedMarkdown {
  const toc: TocItem[] = [];
  const used = new Map<string, number>();
  const prefix = options.idPrefix ?? "sec";

  const marked = new Marked({ gfm: true, breaks: false, async: false });
  marked.use({
    extensions: [
      {
        name: "container",
        level: "block",
        start(src: string) {
          return src.match(/^:::/m)?.index;
        },
        tokenizer(src: string) {
          const m = /^:::\s*([a-z]+)[^\n]*\n([\s\S]*?)\n:::[ \t]*(?:\n|$)/.exec(src);
          if (!m) return undefined;
          const token = {
            type: "container",
            raw: m[0],
            kind: m[1]!,
            tokens: [] as Tokens.Generic[],
          };
          this.lexer.blockTokens(m[2]!, token.tokens);
          return token;
        },
        renderer(token) {
          const kind = CONTAINER_LABELS[token.kind as string] ? (token.kind as string) : "note";
          const body = this.parser.parse(token.tokens ?? []);
          return `<aside class="md-box md-box--${kind}"><p class="md-box__label">${CONTAINER_LABELS[kind]}</p>${body}</aside>\n`;
        },
      },
    ],
    renderer: {
      html({ text }) {
        return escapeHtml(text);
      },
      heading({ tokens, depth }) {
        const text = this.parser.parseInline(tokens);
        const plain = text.replace(/<[^>]+>/g, "").replace(/&[a-z#0-9]+;/gi, "").trim();
        if (depth > 3) return `<h${depth}>${text}</h${depth}>\n`;
        const n = (used.get(prefix) ?? 0) + 1;
        used.set(prefix, n);
        const id = `${prefix}-${n}`;
        toc.push({ id, text: plain, depth });
        return `<h${depth} id="${id}">${text}</h${depth}>\n`;
      },
      code({ text, lang }) {
        const language = (lang ?? "").split(/\s+/)[0] ?? "";
        const cls = language ? ` class="language-${escapeHtml(language)}"` : "";
        return `<div class="codeblock"><div class="codeblock__bar"><span class="codeblock__lang">${escapeHtml(language || "text")}</span><button type="button" class="codeblock__copy" data-copy-code>コピー</button></div><pre><code${cls}>${escapeHtml(text)}</code></pre></div>\n`;
      },
      table(token) {
        const head = token.header.map((c) => `<th${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</th>`).join("");
        const rows = token.rows
          .map((r) => `<tr>${r.map((c) => `<td${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</td>`).join("")}</tr>`)
          .join("");
        return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>\n`;
      },
      link({ href, title, tokens }) {
        const text = this.parser.parseInline(tokens);
        const safe = safeHref(href);
        if (!safe) return text;
        const external = /^https?:\/\//i.test(safe);
        return `<a href="${escapeHtml(safe)}"${title ? ` title="${escapeHtml(title)}"` : ""}${external ? ' rel="noopener nofollow" target="_blank"' : ""}>${text}</a>`;
      },
      image({ text }) {
        // 外部画像は読み込まない
        return escapeHtml(text);
      },
    },
  });

  const html = marked.parse(markdown, { async: false }) as string;
  return { html, toc };
}

/** Markdown からプレーンテキストを取り出す（説明文・RSS用） */
export function markdownToPlainText(markdown: string, max = 200): string {
  const text = markdown
    .replace(/```[\s\S]*?```/g, "")
    .replace(/^:::.*$/gm, "")
    .replace(/^#+\s+/gm, "")
    .replace(/\|/g, " ")
    .replace(/[*_`>]/g, "")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
  return [...text].length > max ? `${[...text].slice(0, max - 1).join("")}…` : text;
}
