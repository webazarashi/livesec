/** メディアのトピック（5-1）。URL は `/{key}/` 、記事は `/{key}/{slug}/`。 */
export const TOPICS = [
  {
    key: "npm",
    label: "npm",
    name: "npm（Node.js / TypeScript）",
    description: "Node.js・TypeScript のパッケージ。フロントエンドとサーバの両方で使われる依存が対象です。",
  },
  {
    key: "pypi",
    label: "PyPI",
    name: "PyPI（Python）",
    description: "Python のパッケージ。Webフレームワーク、データ処理、SDK などが対象です。",
  },
  {
    key: "rubygems",
    label: "RubyGems",
    name: "RubyGems（Ruby）",
    description: "Ruby の gem。Rails とその周辺ライブラリが中心です。",
  },
  {
    key: "packagist",
    label: "Packagist",
    name: "Packagist（PHP）",
    description: "PHP の Composer パッケージ。Laravel・Symfony 系のライブラリなどが対象です。",
  },
  {
    key: "go",
    label: "Go",
    name: "Go モジュール",
    description: "Go のモジュール。標準ライブラリ以外の依存が対象です。",
  },
  {
    key: "os",
    label: "OS",
    name: "OS（Debian・Alpine）",
    description: "コンテナイメージに含まれる Debian・Alpine などのOSパッケージです。",
  },
  {
    key: "middleware",
    label: "Middleware",
    name: "ミドルウェア",
    description: "nginx、PostgreSQL、Redis、OpenSSL など厳選したミドルウェアと基盤ソフトウェアです。",
  },
  {
    key: "runtime",
    label: "Runtime",
    name: "ランタイム",
    description: "Node.js・Python・Ruby・PHP・Go の言語ランタイム本体です。",
  },
  {
    key: "line",
    label: "LINE",
    name: "LINE SDK・LIFF",
    description: "LIFF SDK と各言語の LINE Messaging API SDK。注目トピックとして扱います。",
  },
] as const;

export type TopicKey = (typeof TOPICS)[number]["key"];
export type Topic = (typeof TOPICS)[number];

export const TOPIC_KEYS = TOPICS.map((t) => t.key) as readonly TopicKey[];

export function isTopicKey(value: string): value is TopicKey {
  return (TOPIC_KEYS as readonly string[]).includes(value);
}

export function getTopic(key: string): Topic | undefined {
  return TOPICS.find((t) => t.key === key);
}

/** LINE SDK・LIFF として扱うパッケージ（3-4）。ecosystem はOSVの名前。 */
export const LINE_PACKAGES: ReadonlyArray<{ ecosystem: string; name: string; label: string }> = [
  { ecosystem: "npm", name: "@line/liff", label: "LIFF SDK" },
  { ecosystem: "npm", name: "@line/bot-sdk", label: "LINE Messaging API SDK（Node.js）" },
  { ecosystem: "PyPI", name: "line-bot-sdk", label: "LINE Messaging API SDK（Python）" },
  { ecosystem: "RubyGems", name: "line-bot-api", label: "LINE Messaging API SDK（Ruby）" },
  { ecosystem: "Packagist", name: "linecorp/line-bot-sdk", label: "LINE Messaging API SDK（PHP）" },
  // Go はメジャーバージョン付きパス（/v7, /v8 …）も含めて前方一致で判定する
  { ecosystem: "Go", name: "github.com/line/line-bot-sdk-go", label: "LINE Messaging API SDK（Go）" },
];

export function isLinePackage(ecosystem: string, name: string): boolean {
  const eco = baseEcosystem(ecosystem);
  return LINE_PACKAGES.some((p) => {
    if (p.ecosystem !== eco) return false;
    if (eco === "Go") return name === p.name || name.startsWith(`${p.name}/`);
    return name.toLowerCase() === p.name.toLowerCase();
  });
}

/** 言語パッケージのOSVエコシステム（3-1） */
export const LANGUAGE_ECOSYSTEMS = ["npm", "PyPI", "RubyGems", "Packagist", "Go"] as const;
/** OSパッケージのOSVエコシステム（3-2）。`Debian:12` のようにバージョン付きで来るので接頭辞で判定する */
export const OS_ECOSYSTEMS = ["Debian", "Alpine", "Ubuntu"] as const;

/** `Debian:12` → `Debian` */
export function baseEcosystem(ecosystem: string): string {
  const idx = ecosystem.indexOf(":");
  return idx === -1 ? ecosystem : ecosystem.slice(0, idx);
}

export function isTargetEcosystem(ecosystem: string): boolean {
  const base = baseEcosystem(ecosystem);
  return (
    (LANGUAGE_ECOSYSTEMS as readonly string[]).includes(base) ||
    (OS_ECOSYSTEMS as readonly string[]).includes(base)
  );
}

/**
 * OSパッケージのうち、コンテナでは使われないため対象外にするソースパッケージ。
 * カーネルのCVEは件数が非常に多く、コンテナの一次対応には関係しないため除外する。
 */
export const OS_PACKAGE_EXCLUDES: ReadonlyArray<RegExp> = [/^linux$/, /^linux-/];

export function topicForPackage(ecosystem: string, name: string): TopicKey | null {
  if (isLinePackage(ecosystem, name)) return "line";
  switch (baseEcosystem(ecosystem)) {
    case "npm":
      return "npm";
    case "PyPI":
      return "pypi";
    case "RubyGems":
      return "rubygems";
    case "Packagist":
      return "packagist";
    case "Go":
      return "go";
    case "Debian":
    case "Alpine":
    case "Ubuntu":
      return OS_PACKAGE_EXCLUDES.some((re) => re.test(name)) ? null : "os";
    default:
      return null;
  }
}

/** 複数のトピックに該当するときの優先順（注目トピック → 言語 → MW/ランタイム → OS） */
const TOPIC_PRIORITY: TopicKey[] = [
  "line",
  "npm",
  "pypi",
  "rubygems",
  "packagist",
  "go",
  "middleware",
  "runtime",
  "os",
];

export function primaryTopic(topics: Iterable<TopicKey>): TopicKey | null {
  const set = new Set(topics);
  return TOPIC_PRIORITY.find((t) => set.has(t)) ?? null;
}
