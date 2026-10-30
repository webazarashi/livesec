import { describe, expect, it } from "vitest";
import { ARTICLE_SEPARATOR, normalizeOsv, randomId } from "@ichiji/core";
import { AccountRepo, CatalogRepo, TenantRepo } from "@ichiji/db";
import { createAppDb, createCatalogDb, insertUser } from "../../../packages/db/test/d1-shim";
import { importArticles, processStackUpload, readStackUpload } from "../src/server/services";
import { readFileSync } from "node:fs";

const stackYaml = readFileSync(new URL("../../../packages/core/test/fixtures/stack.sample.yaml", import.meta.url), "utf8");

async function catalogWithOneCve() {
  const catalog = new CatalogRepo(createCatalogDb());
  const windowStart = new Date(Date.now() - 30 * 86_400_000).toISOString();
  await catalog.upsertOsv(
    normalizeOsv({
      id: "GHSA-test-test-test",
      modified: new Date().toISOString(),
      published: new Date().toISOString(),
      aliases: ["CVE-2026-91000"],
      affected: [{ package: { ecosystem: "npm", name: "@example/static-gate" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.4.2" }] }] }],
      database_specific: { severity: "HIGH" },
    }),
    null,
  );
  await catalog.refreshDerived(["CVE-2026-91000"], { windowStart });
  return catalog;
}

const article = (affected: string) => `${ARTICLE_SEPARATOR}
---
cve_ids: ["CVE-2026-91000"]
title: "static-gate CVE-2026-91000｜パス制限の回避｜3.4.2で修正"
slug: "static-gate-cve-2026-91000"
topic: "npm"
packages: ["pkg:npm/%40example/static-gate"]
affected: "${affected}"
fixed: ["3.4.2"]
cvss: 7.0
why_read: "公開サーバで使われるためです。"
points: ["a", "b", "c"]
gains: ["x"]
sources:
  - title: "advisory"
    url: "https://github.com/advisories/GHSA-test-test-test"
---
## 何が起きるか

細工したURLで公開ディレクトリの外のファイルを読めます。影響は大きいです。

:::summary
まとめ
:::

## 自環境の確認コマンド

\`\`\`bash
npm ls @example/static-gate
\`\`\`

## まとめ

3.4.2 に更新してください。
`;

describe("記事の取り込み（10章）", () => {
  it("照合が通れば公開し、通らなければ差し戻す", async () => {
    const catalog = await catalogWithOneCve();
    const bad = await importArticles(catalog, article("<3.4.1"));
    expect(bad[0]).toMatchObject({ status: "rejected" });
    expect((await catalog.listDrafts()).length).toBe(1);

    const ok = await importArticles(catalog, article("<3.4.2"));
    expect(ok[0]).toMatchObject({ status: "published", url: "/npm/static-gate-cve-2026-91000/" });
    const row = await catalog.getArticleBySlug("static-gate-cve-2026-91000");
    expect(row?.check_html).toContain("npm ls @example/static-gate");
    expect(row?.body_html).not.toContain("npm ls");
    expect(JSON.parse(row!.toc).map((t: { text: string }) => t.text)).toEqual(["何が起きるか", "自環境の確認コマンド", "まとめ"]);

    // 同じslugで再取り込みすると更新になり、訂正履歴が残る
    const again = await importArticles(catalog, article("<3.4.2"), { correctionNote: "表現を修正しました" });
    expect(again[0]!.status).toBe("updated");
    expect((await catalog.listRevisions(row!.id))[0]).toMatchObject({ kind: "correction", note: "表現を修正しました" });
  });
});

describe("スタック登録（8章）", () => {
  it("multipart を読み、検証して原本をR2へ保存し、照合をキューに積む", async () => {
    const app = createAppDb();
    insertUser(app, "u", "u@example.com");
    const tenantId = await new AccountRepo(app).ensureTenant("u", "A", () => "t1");
    const repo = new TenantRepo(app, tenantId);
    await repo.createProject({ id: "p1", name: "acme" });

    const form = new FormData();
    form.append("stack", new Blob([stackYaml]), "stack.yaml");
    const bom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ purl: "pkg:npm/express@4.17.1" }] });
    form.append("sbom/api-server.cdx.json", new Blob([bom]), "api-server.cdx.json");
    form.append("sbom/web-liff.cdx.json", new Blob([bom]), "web-liff.cdx.json");
    const upload = await readStackUpload(new Request("https://x/api/v1/stack", { method: "POST", body: form }));
    expect("error" in upload).toBe(false);
    if ("error" in upload) return;

    const puts: string[] = [];
    const sent: unknown[] = [];
    const env = {
      RAW: { put: async (key: string) => void puts.push(key) },
      JOBS_QUEUE: { send: async (m: unknown) => void sent.push(m) },
    } as unknown as Env;
    const r = await processStackUpload(env, repo, "p1", upload, "api");
    expect(r.ok).toBe(true);
    expect(puts.some((k) => k.endsWith("/stack.yaml"))).toBe(true);
    expect(puts.filter((k) => k.includes("/boms/"))).toHaveLength(2);
    expect(sent).toEqual([{ type: "match-project", tenantId, projectId: "p1" }]);
    expect((await repo.getProject("p1"))?.service_name).toBe("acme-crm");
    expect(await repo.listComponents("p1")).toHaveLength(3);

    // 他テナントのプロジェクトには登録できない
    const other = new TenantRepo(app, randomId());
    expect((await processStackUpload(env, other, "p1", upload, "api")).ok).toBe(false);
  });
});
