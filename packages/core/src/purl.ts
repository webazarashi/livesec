/**
 * Package URL（PURL）の最小限のパーサ。識別子はPURLで統一する（8-1）。
 * https://github.com/package-url/purl-spec
 */
export interface Purl {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  qualifiers: Record<string, string>;
  subpath: string | null;
}

export function parsePurl(input: string): Purl | null {
  let s = input.trim();
  if (!s.toLowerCase().startsWith("pkg:")) return null;
  s = s.slice(4).replace(/^\/+/, "");

  let subpath: string | null = null;
  const hash = s.indexOf("#");
  if (hash !== -1) {
    subpath = safeDecode(s.slice(hash + 1)).replace(/^\/+|\/+$/g, "") || null;
    s = s.slice(0, hash);
  }

  const qualifiers: Record<string, string> = {};
  const q = s.indexOf("?");
  if (q !== -1) {
    for (const pair of s.slice(q + 1).split("&")) {
      if (!pair) continue;
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      const key = pair.slice(0, eq).toLowerCase();
      const value = safeDecode(pair.slice(eq + 1));
      if (value) qualifiers[key] = value;
    }
    s = s.slice(0, q);
  }

  const slash = s.indexOf("/");
  if (slash === -1) return null;
  const type = s.slice(0, slash).toLowerCase();
  let rest = s.slice(slash + 1).replace(/\/+$/, "");

  let version: string | null = null;
  const at = rest.lastIndexOf("@");
  if (at !== -1) {
    version = safeDecode(rest.slice(at + 1)) || null;
    rest = rest.slice(0, at);
  }

  const segments = rest.split("/").filter(Boolean).map(safeDecode);
  const name = segments.pop();
  if (!type || !name) return null;
  const namespace = segments.length ? segments.join("/") : null;

  return { type, namespace, name, version, qualifiers, subpath };
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function encodeSegment(s: string): string {
  return encodeURIComponent(s).replace(/%3A/gi, ":");
}

export function formatPurl(p: Omit<Purl, "qualifiers" | "subpath"> & Partial<Pick<Purl, "qualifiers" | "subpath">>): string {
  const ns = p.namespace ? `${p.namespace.split("/").map(encodeSegment).join("/")}/` : "";
  const version = p.version ? `@${encodeSegment(p.version)}` : "";
  const quals = Object.entries(p.qualifiers ?? {})
    .filter(([, v]) => v)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${encodeSegment(v)}`)
    .join("&");
  return `pkg:${p.type}/${ns}${encodeSegment(p.name)}${version}${quals ? `?${quals}` : ""}${p.subpath ? `#${p.subpath}` : ""}`;
}

/** バージョンと修飾子を除いたPURL（記事の `packages` や画面表示で使う） */
export function purlWithoutVersion(input: string): string {
  const p = parsePurl(input);
  if (!p) return input;
  return formatPurl({ type: p.type, namespace: p.namespace, name: p.name, version: null });
}

export interface OsvPackageRef {
  ecosystem: string;
  name: string;
  version: string | null;
}

/**
 * PURL を OSV の（エコシステム, パッケージ名, バージョン）に変換する。
 * 対象外のタイプは null。
 */
export function purlToOsv(input: string | Purl): OsvPackageRef | null {
  const p = typeof input === "string" ? parsePurl(input) : input;
  if (!p) return null;
  const version = p.version && p.version.toLowerCase() !== "unknown" ? p.version : null;
  switch (p.type) {
    case "npm":
      return { ecosystem: "npm", name: p.namespace ? `${p.namespace}/${p.name}` : p.name, version };
    case "pypi":
      return { ecosystem: "PyPI", name: normalizePypiName(p.name), version };
    case "gem":
      return { ecosystem: "RubyGems", name: p.name, version };
    case "composer":
      return {
        ecosystem: "Packagist",
        name: (p.namespace ? `${p.namespace}/${p.name}` : p.name).toLowerCase(),
        version: version?.replace(/^v(?=\d)/, "") ?? null,
      };
    case "golang":
      return {
        ecosystem: "Go",
        name: p.namespace ? `${p.namespace}/${p.name}` : p.name,
        version: version?.replace(/^v(?=\d)/, "") ?? null,
      };
    case "deb": {
      // OSV の Debian はソースパッケージ名で登録されている。cdxgen/syft は upstream 修飾子にソース名を入れる
      const name = sourcePackageName(p) ?? p.name;
      const distro = (p.qualifiers.distro ?? "").toLowerCase();
      const vendor = (p.namespace ?? "debian").toLowerCase();
      if (vendor === "ubuntu") {
        const m = /(\d+\.\d+)/.exec(distro);
        return { ecosystem: m ? `Ubuntu:${m[1]}` : "Ubuntu", name, version };
      }
      const m = /debian-(\d+)/.exec(distro) ?? /^(\d+)/.exec(distro);
      return { ecosystem: m ? `Debian:${m[1]}` : "Debian", name, version };
    }
    case "apk": {
      const name = sourcePackageName(p) ?? p.name;
      const distro = (p.qualifiers.distro ?? "").toLowerCase();
      const m = /(\d+)\.(\d+)/.exec(distro);
      return { ecosystem: m ? `Alpine:v${m[1]}.${m[2]}` : "Alpine", name, version };
    }
    default:
      return null;
  }
}

function sourcePackageName(p: Purl): string | null {
  const upstream = p.qualifiers.upstream ?? p.qualifiers.source;
  if (!upstream) return null;
  // `openssl@3.0.15-1` や `openssl (3.0.15)` の形式からパッケージ名だけ取り出す
  return upstream.split(/[@\s(]/)[0] || null;
}

export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/** OSV のエコシステム名 → PURL のタイプ */
export function ecosystemToPurlType(ecosystem: string): string | null {
  const base = ecosystem.split(":")[0];
  switch (base) {
    case "npm":
      return "npm";
    case "PyPI":
      return "pypi";
    case "RubyGems":
      return "gem";
    case "Packagist":
      return "composer";
    case "Go":
      return "golang";
    case "Debian":
    case "Ubuntu":
      return "deb";
    case "Alpine":
      return "apk";
    default:
      return null;
  }
}

/** OSV の（エコシステム, 名前）からバージョンなしのPURLを作る */
export function osvToPurl(ecosystem: string, name: string): string {
  const type = ecosystemToPurlType(ecosystem);
  if (!type) return `pkg:generic/${encodeSegment(name)}`;
  const [base, release] = ecosystem.split(":");
  if (type === "deb") {
    const vendor = base === "Ubuntu" ? "ubuntu" : "debian";
    return formatPurl({
      type,
      namespace: vendor,
      name,
      version: null,
      qualifiers: release ? { distro: `${vendor}-${release}` } : {},
    });
  }
  if (type === "apk") {
    return formatPurl({
      type,
      namespace: "alpine",
      name,
      version: null,
      qualifiers: release ? { distro: `alpine-${release.replace(/^v/, "")}` } : {},
    });
  }
  const idx = name.lastIndexOf("/");
  if (idx === -1) return formatPurl({ type, namespace: null, name, version: null });
  return formatPurl({ type, namespace: name.slice(0, idx), name: name.slice(idx + 1), version: null });
}
