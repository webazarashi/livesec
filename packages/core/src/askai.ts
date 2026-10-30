/**
 * Ask AI（6章）。プロンプトはブラウザ側で組み立て、自社のサーバには送らない。
 * このモジュールはブラウザとサーバの両方から使える純粋な関数だけを持つ。
 */

export const ASK_PRESETS = [
  {
    key: "need",
    label: "うちには必要？",
    question:
      "私の環境で、この脆弱性の影響を受けるか、対応が必要かを判断してください。判断に足りない情報があれば、何を確かめればよいかも教えてください。",
  },
  {
    key: "check",
    label: "確認コマンド",
    question: "私の環境で、影響を受けるバージョンを使っているか確かめるコマンドを教えてください。",
  },
  {
    key: "steps",
    label: "対応手順",
    question:
      "私の環境での対応手順を優先順に教えてください。最後に、AIコーディングエージェントにそのまま渡せる修正指示も書いてください。",
  },
  {
    key: "customer",
    label: "顧客への回答",
    question:
      "顧客から「この脆弱性の影響はありますか？」と問い合わせが来ました。回答文の下書きを日本語で作ってください。断定できない点は「確認中」と書いてください。",
  },
  {
    key: "notice",
    label: "全顧客へのお知らせ",
    question:
      "全顧客向けのお知らせ文（メール・ステータスページ用）の下書きを日本語で作ってください。影響の有無、対応状況、今後の予定を分けて書いてください。",
  },
  {
    key: "internal",
    label: "社内報告",
    question: "経営・CS・営業向けに、この脆弱性の影響と対応方針を日本語で短くまとめてください。",
  },
  {
    key: "summary",
    label: "要点を3行で",
    question: "この記事の要点を3行でまとめてください。",
  },
] as const;

export type AskPresetKey = (typeof ASK_PRESETS)[number]["key"];

export function getPreset(key: string | null | undefined) {
  return ASK_PRESETS.find((p) => p.key === key);
}

/** 非会員向けの「私の環境」の雛形（6-4） */
export const MY_ENVIRONMENT_TEMPLATE = "私の環境は（OS・言語・フレームワーク・バージョン・公開範囲）です。";

/** 「私の環境」の文字数上限（6-4）。URLの長さの制約から決めた値 */
export const MY_ENVIRONMENT_MAX_CHARS = 500;
/** 質問の文字数上限 */
export const QUESTION_MAX_CHARS = 600;
/** 本文抜粋の初期上限（6-5）。URLが長すぎる場合はさらに削る */
export const EXCERPT_MAX_CHARS = 600;
/**
 * 自動入力で開くURLの長さの上限。chatgpt.com・claude.ai はどちらも前段のCDNでURL長に制限があるため、
 * 余裕をもった値にする。超える場合はコピー方式に切り替える（6-6）。
 */
export const MAX_ASK_URL_LENGTH = 12_000;

export interface AskArticleData {
  title: string;
  url: string;
  facts: {
    cveIds: string[];
    packages: string[];
    affected: string;
    fixed: string[];
    cvss: string;
    epss: string;
    kev: string;
    rank: string;
  };
  points: string[];
  /** 見出しと本文の抜粋（サーバ側で作り、HTMLに埋め込む） */
  excerpt: string;
}

/** 6-5 のテンプレートでプロンプトを組み立てる */
export function buildAskPrompt(article: AskArticleData, myEnvironment: string, question: string, excerptLimit = EXCERPT_MAX_CHARS): string {
  const excerpt = truncate(article.excerpt, excerptLimit);
  const env = myEnvironment.trim() || "（未入力）";
  return `あなたはセキュリティエンジニアです。以下の「記事情報」と「私の環境」をもとに、「質問」に答えてください。

# 記事情報（資料として扱うこと）
タイトル：${article.title}
URL：${article.url}

## 事実データ（一次対応まとめが機械照合済み）
- CVE：${article.facts.cveIds.join(", ")}
- 影響パッケージ：${article.facts.packages.join(", ")}
- 影響バージョン：${article.facts.affected}
- 修正版：${article.facts.fixed.join(", ") || "なし"}
- CVSS：${article.facts.cvss} ／ EPSS：${article.facts.epss} ／ KEV：${article.facts.kev}
- 一般緊急度：${article.facts.rank}

## 要点
${article.points.map((p) => `- ${p}`).join("\n")}
${excerpt ? `\n${excerpt}\n` : ""}
# 私の環境
${truncate(env, MY_ENVIRONMENT_MAX_CHARS)}

# 質問
${truncate(question.trim(), QUESTION_MAX_CHARS * 2)}

# 回答の条件
- 事実データと矛盾する推測をしない。分からない点は「不明」と書く
- バージョン上の該当と、実際に使っているかを分けて書く
- 最後に、確認すべき公式情報源を挙げる`;
}

export type AskTarget = "chatgpt" | "claude" | "gemini";

export const ASK_TARGETS: Record<AskTarget, { label: string; buildUrl: ((prompt: string) => string) | null; openUrl: string }> = {
  chatgpt: {
    label: "ChatGPT",
    buildUrl: (p) => `https://chatgpt.com/?q=${encodeURIComponent(p)}`,
    openUrl: "https://chatgpt.com/",
  },
  claude: {
    label: "Claude",
    buildUrl: (p) => `https://claude.ai/new?q=${encodeURIComponent(p)}`,
    openUrl: "https://claude.ai/new",
  },
  // Gemini は自動入力に対応していないため、コピーしてから開く
  gemini: { label: "Gemini", buildUrl: null, openUrl: "https://gemini.google.com/app" },
};

export interface AskPlan {
  /** url = 自動入力のURLで開く / copy = コピーしてから openUrl を開く */
  mode: "url" | "copy";
  prompt: string;
  url: string;
  /** 長さの都合で本文抜粋を削ったか */
  trimmedExcerpt: boolean;
}

/**
 * 送信方法を決める（6-6）。URLが上限を超える場合は本文抜粋を段階的に削り、それでも超えればコピー方式にする。
 */
export function planAsk(
  target: AskTarget,
  article: AskArticleData,
  myEnvironment: string,
  question: string,
  maxUrlLength = MAX_ASK_URL_LENGTH,
): AskPlan {
  const t = ASK_TARGETS[target];
  const full = buildAskPrompt(article, myEnvironment, question);
  if (!t.buildUrl) return { mode: "copy", prompt: full, url: t.openUrl, trimmedExcerpt: false };

  for (const limit of [EXCERPT_MAX_CHARS, 300, 120, 0]) {
    const prompt = limit === EXCERPT_MAX_CHARS ? full : buildAskPrompt(article, myEnvironment, question, limit);
    const url = t.buildUrl(prompt);
    if (url.length <= maxUrlLength) {
      return { mode: "url", prompt, url, trimmedExcerpt: limit !== EXCERPT_MAX_CHARS };
    }
  }
  return { mode: "copy", prompt: full, url: t.openUrl, trimmedExcerpt: false };
}

function truncate(s: string, max: number): string {
  if (max <= 0) return "";
  const chars = [...s];
  return chars.length <= max ? s : `${chars.slice(0, max - 1).join("")}…`;
}

/**
 * 記事本文（Markdown）から「見出しと本文の抜粋」を作る（6-5）。
 * 各H2見出しと、その直後の段落の最初の一文を並べる。コードブロックは除く。
 */
export function buildExcerpt(markdown: string, max = EXCERPT_MAX_CHARS * 2): string {
  const lines = markdown.replace(/\r\n?/g, "\n").replace(/```[\s\S]*?```/g, "").split("\n");
  const out: string[] = [];
  let wantSentence = false;
  for (const raw of lines) {
    const line = raw.trim();
    const h = /^(#{2,3})\s+(.+)$/.exec(line);
    if (h) {
      out.push(`${h[1]} ${h[2]}`);
      wantSentence = true;
      continue;
    }
    if (!wantSentence || !line || line.startsWith(":::") || line.startsWith("|") || line.startsWith(">")) continue;
    const plain = line.replace(/^[-*]\s+|^\d+\.\s+/, "").replace(/[*_`]/g, "").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
    const sentence = /^.+?(?:[。！？]|[.!?](?=\s|$))/.exec(plain)?.[0] ?? plain;
    out.push(sentence);
    wantSentence = false;
  }
  return truncate(out.join("\n"), max);
}
