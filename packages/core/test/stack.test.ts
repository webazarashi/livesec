import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseStackYaml, stackJsonSchema } from "../src/stack";
import { parseCycloneDx } from "../src/sbom";
import { dockerTagVersion, resolveMiddlewarePurl } from "../src/watchlist";
import { resolveCdnScript } from "../src/cdn";

const sample = readFileSync(new URL("./fixtures/stack.sample.yaml", import.meta.url), "utf8");

describe("stack.yaml（8-3）", () => {
  it("仕様書のサンプルが通る", () => {
    const r = parseStackYaml(sample);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.stack.components).toHaveLength(3);
    expect(r.stack.components[2]!.managed).toBe(true);
    expect(r.warnings).toEqual([]);
  });
  it("schema_version をクォートしないと弾く", () => {
    const r = parseStackYaml(sample.replace('schema_version: "1.0"', "schema_version: 1.0"));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errors[0]!.path).toBe("schema_version");
  });
  it("未知のキー・不正な exposure を弾く", () => {
    expect(parseStackYaml(sample.replace('exposure: "internal"', 'exposure: "dmz"')).ok).toBe(false);
    expect(parseStackYaml(sample.replace("managed: true ", "managed: true\n    hostname: db.local ")).ok).toBe(false);
  });
  it("component名の重複を弾く", () => {
    expect(parseStackYaml(sample.replace('name: "web-liff"', 'name: "api-server"')).ok).toBe(false);
  });
  it("IP・URL・秘密情報を警告する", () => {
    const r = parseStackYaml(sample.replace("ALB経由で公開（infra/alb.tf）", "10.0.1.5 https://internal.example.com token=abc"));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.warnings.map((w) => w.message).join("\n")).toMatch(/IP.*\n.*URL.*\n.*秘密/s);
  });
  it("YAMLの構文エラー", () => {
    expect(parseStackYaml("service: [").ok).toBe(false);
  });
  it("JSON Schema を出力できる", () => {
    const s = stackJsonSchema();
    expect(s.type).toBe("object");
    expect(JSON.stringify(s)).toContain("data_sensitivity");
  });
});

describe("ウォッチリスト・CDN", () => {
  it("middleware の PURL を対応づける", () => {
    expect(resolveMiddlewarePurl("pkg:generic/nginx@1.27.3")).toMatchObject({ productKey: "nginx", version: "1.27.3" });
    expect(resolveMiddlewarePurl("pkg:generic/postgresql@16.4")).toMatchObject({ productKey: "postgresql", version: "16.4" });
    expect(resolveMiddlewarePurl("pkg:generic/redis@unknown")).toMatchObject({ productKey: "redis", version: null });
    expect(resolveMiddlewarePurl("pkg:generic/unknown-thing@1.0")).toBeNull();
  });
  it("コンテナイメージからランタイムを対応づける", () => {
    expect(resolveMiddlewarePurl("pkg:docker/node@20.18.1-bookworm-slim")).toMatchObject({
      productKey: "nodejs",
      version: "20.18.1",
      source: "image",
    });
    expect(dockerTagVersion("20")).toBeNull();
    expect(dockerTagVersion("latest")).toBeNull();
  });
  it("LIFF の CDN を判定する", () => {
    expect(resolveCdnScript("https://static.line-scdn.net/liff/edge/2/sdk.js")).toMatchObject({ name: "@line/liff", version: null });
    expect(resolveCdnScript("https://static.line-scdn.net/liff/edge/versions/2.22.3/sdk.js")).toMatchObject({
      name: "@line/liff",
      version: "2.22.3",
    });
    expect(resolveCdnScript("https://cdn.jsdelivr.net/npm/@line/liff@2.24.0/dist/lib/index.js")).toMatchObject({
      name: "@line/liff",
      version: "2.24.0",
    });
  });
});

describe("CycloneDX", () => {
  it("ネストしたcomponentsと開発用依存を読む", () => {
    const bom = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      metadata: { component: { purl: "pkg:npm/acme-crm@1.0.0" } },
      components: [
        { purl: "pkg:npm/express@4.17.1", scope: "required" },
        { purl: "pkg:npm/vitest@1.0.0", scope: "optional" },
        {
          purl: "pkg:npm/%40line/liff@2.24.0",
          properties: [{ name: "cdx:npm:package:development", value: "false" }],
          components: [{ purl: "pkg:npm/eslint@9.0.0", properties: [{ name: "cdx:npm:package:development", value: "true" }] }],
        },
        { purl: "pkg:maven/org.example/foo@1.0" },
        { name: "no-purl" },
      ],
    };
    const r = parseCycloneDx(JSON.stringify(bom));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const byName = Object.fromEntries(r.packages.map((p) => [p.name, p]));
    expect(byName.express!.isDev).toBe(false);
    expect(byName.vitest!.isDev).toBe(true);
    expect(byName.eslint!.isDev).toBe(true);
    expect(byName["@line/liff"]!.isDev).toBe(false);
    expect(r.skipped).toBe(2);
  });
  it("CycloneDX でなければ弾く", () => {
    expect(parseCycloneDx('{"spdxVersion":"SPDX-2.3"}').ok).toBe(false);
    expect(parseCycloneDx("not json").ok).toBe(false);
  });
});
