import { parsePurl } from "./purl";
import type { TopicKey } from "./topics";
import { inInterval, parseVersion } from "./version";

/**
 * ミドルウェア・ランタイムの厳選ウォッチリスト（3-3）。
 * stack.yaml の middleware / image を固定の別名表で NVD の CPE（vendor:product）に対応づける（9-2）。
 */
export interface WatchlistProduct {
  key: string;
  label: string;
  topic: Extract<TopicKey, "middleware" | "runtime">;
  category: "webserver" | "database" | "runtime" | "infra";
  /** NVD の CPE の vendor:product。ベンダー名の変更（nginx → f5 など）に備えて複数持つ */
  cpes: string[];
  /** stack.yaml の pkg:generic/<name> で受け付ける別名 */
  aliases: string[];
  /** pkg:docker/<image> の公式イメージ名 */
  dockerImages: string[];
}

export const WATCHLIST: readonly WatchlistProduct[] = [
  {
    key: "nginx",
    label: "nginx",
    topic: "middleware",
    category: "webserver",
    cpes: ["f5:nginx", "f5:nginx_open_source", "nginx:nginx"],
    aliases: ["nginx"],
    dockerImages: ["nginx", "nginxinc/nginx-unprivileged"],
  },
  {
    key: "apache-httpd",
    label: "Apache HTTP Server",
    topic: "middleware",
    category: "webserver",
    cpes: ["apache:http_server"],
    aliases: ["apache-httpd", "httpd", "apache", "apache2", "apache-http-server"],
    dockerImages: ["httpd"],
  },
  {
    key: "postgresql",
    label: "PostgreSQL",
    topic: "middleware",
    category: "database",
    cpes: ["postgresql:postgresql"],
    aliases: ["postgresql", "postgres", "pg"],
    dockerImages: ["postgres"],
  },
  {
    key: "mysql",
    label: "MySQL",
    topic: "middleware",
    category: "database",
    cpes: ["oracle:mysql", "oracle:mysql_server"],
    aliases: ["mysql", "mysql-server"],
    dockerImages: ["mysql"],
  },
  {
    key: "mariadb",
    label: "MariaDB",
    topic: "middleware",
    category: "database",
    cpes: ["mariadb:mariadb"],
    aliases: ["mariadb"],
    dockerImages: ["mariadb"],
  },
  {
    key: "redis",
    label: "Redis",
    topic: "middleware",
    category: "database",
    cpes: ["redis:redis", "redislabs:redis"],
    aliases: ["redis"],
    dockerImages: ["redis"],
  },
  {
    key: "mongodb",
    label: "MongoDB",
    topic: "middleware",
    category: "database",
    cpes: ["mongodb:mongodb"],
    aliases: ["mongodb", "mongo"],
    dockerImages: ["mongo"],
  },
  {
    key: "nodejs",
    label: "Node.js",
    topic: "runtime",
    category: "runtime",
    cpes: ["nodejs:node.js"],
    aliases: ["nodejs", "node", "node.js"],
    dockerImages: ["node"],
  },
  {
    key: "python",
    label: "Python",
    topic: "runtime",
    category: "runtime",
    cpes: ["python:python"],
    aliases: ["python", "cpython", "python3"],
    dockerImages: ["python"],
  },
  {
    key: "ruby",
    label: "Ruby",
    topic: "runtime",
    category: "runtime",
    cpes: ["ruby-lang:ruby"],
    aliases: ["ruby"],
    dockerImages: ["ruby"],
  },
  {
    key: "php",
    label: "PHP",
    topic: "runtime",
    category: "runtime",
    cpes: ["php:php"],
    aliases: ["php"],
    dockerImages: ["php"],
  },
  {
    key: "go",
    label: "Go",
    topic: "runtime",
    category: "runtime",
    cpes: ["golang:go"],
    aliases: ["go", "golang"],
    dockerImages: ["golang"],
  },
  {
    key: "openssl",
    label: "OpenSSL",
    topic: "middleware",
    category: "infra",
    cpes: ["openssl:openssl"],
    aliases: ["openssl"],
    dockerImages: [],
  },
  {
    key: "openssh",
    label: "OpenSSH",
    topic: "middleware",
    category: "infra",
    cpes: ["openbsd:openssh"],
    aliases: ["openssh", "sshd"],
    dockerImages: [],
  },
  {
    key: "curl",
    label: "curl",
    topic: "middleware",
    category: "infra",
    cpes: ["haxx:curl", "haxx:libcurl"],
    aliases: ["curl", "libcurl"],
    dockerImages: ["curlimages/curl"],
  },
  {
    key: "docker-engine",
    label: "Docker Engine",
    topic: "middleware",
    category: "infra",
    cpes: ["docker:docker", "docker:engine", "mobyproject:moby"],
    aliases: ["docker", "docker-engine", "moby", "dockerd"],
    dockerImages: ["docker"],
  },
  {
    key: "kubernetes",
    label: "Kubernetes",
    topic: "middleware",
    category: "infra",
    cpes: ["kubernetes:kubernetes"],
    aliases: ["kubernetes", "k8s", "kube-apiserver", "kubelet"],
    dockerImages: [],
  },
];

export function getWatchlistProduct(key: string): WatchlistProduct | undefined {
  return WATCHLIST.find((p) => p.key === key);
}

/** CPE 2.3 の文字列から vendor:product を取り出す */
export function cpeVendorProduct(criteria: string): string | null {
  const parts = criteria.split(":");
  // cpe:2.3:a:vendor:product:version:...
  if (parts.length < 6 || parts[0] !== "cpe") return null;
  return `${parts[3]}:${parts[4]}`;
}

export function cpeVersion(criteria: string): string | null {
  const v = criteria.split(":")[5];
  if (!v || v === "*" || v === "-") return null;
  return v.replace(/\\/g, "");
}

export function watchlistProductForCpe(criteria: string): WatchlistProduct | undefined {
  const vp = cpeVendorProduct(criteria);
  if (!vp) return undefined;
  return WATCHLIST.find((p) => p.cpes.includes(vp));
}

export interface WatchedComponent {
  productKey: string;
  /** null は unknown（7-4 の1：B固定） */
  version: string | null;
  sourcePurl: string;
  source: "middleware" | "image";
}

function normalizeVersion(v: string | null): string | null {
  if (!v) return null;
  const t = v.trim();
  if (!t || t.toLowerCase() === "unknown" || t.toLowerCase() === "latest") return null;
  return parseVersion(t) ? t : null;
}

/** stack.yaml の middleware の PURL（pkg:generic/nginx@1.27.3）をウォッチリストに対応づける */
export function resolveMiddlewarePurl(input: string): WatchedComponent | null {
  const p = parsePurl(input);
  if (!p) return null;
  const name = (p.namespace ? `${p.namespace}/${p.name}` : p.name).toLowerCase();
  const product =
    p.type === "docker"
      ? WATCHLIST.find((w) => w.dockerImages.includes(name) || w.dockerImages.includes(name.replace(/^library\//, "")))
      : WATCHLIST.find((w) => w.aliases.includes(name) || w.aliases.includes(p.name.toLowerCase()));
  if (!product) return null;
  return {
    productKey: product.key,
    version: p.type === "docker" ? dockerTagVersion(p.version) : normalizeVersion(p.version),
    sourcePurl: input,
    source: p.type === "docker" ? "image" : "middleware",
  };
}

/**
 * コンテナイメージのタグからバージョンを取り出す。
 * `20.18.1-bookworm-slim` → `20.18.1`。`20` や `latest` のようにメジャーだけ・不定のものは unknown。
 */
export function dockerTagVersion(tag: string | null): string | null {
  if (!tag) return null;
  const m = /^v?(\d+(?:\.\d+)+)/.exec(tag);
  return m ? m[1]! : null;
}

export interface CpeRange {
  exact?: string | null;
  startIncluding?: string | null;
  startExcluding?: string | null;
  endIncluding?: string | null;
  endExcluding?: string | null;
}

export function cpeRangeMatches(version: string, range: CpeRange): boolean {
  return inInterval(version, range);
}

export function describeCpeRange(range: CpeRange): string {
  if (range.exact) return `=${range.exact}`;
  const parts: string[] = [];
  if (range.startIncluding) parts.push(`>=${range.startIncluding}`);
  if (range.startExcluding) parts.push(`>${range.startExcluding}`);
  if (range.endIncluding) parts.push(`<=${range.endIncluding}`);
  if (range.endExcluding) parts.push(`<${range.endExcluding}`);
  return parts.length ? parts.join(" ") : "*";
}
