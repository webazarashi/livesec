import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { normalizeOsv, type OsvRecord, type NvdCve, extractWatchlistCpes, selectNvdCvss, renderArticleMarkdown, factsHash } from "@ichiji/core";
import { CatalogRepo } from "../src/catalog";
import { AccountRepo } from "../src/account";
import { TenantRepo } from "../src/tenant";
import { SystemRepo } from "../src/system";
import { buildStackInput } from "../src/stack-ingest";
import { matchProject, refreshPackageVulns } from "../src/matcher";
import { createAppDb, createCatalogDb, insertUser } from "./d1-shim";

const stackYaml = readFileSync(new URL("../../core/test/fixtures/stack.sample.yaml", import.meta.url), "utf8");

const ghsa: OsvRecord = {
  id: "GHSA-aaaa-bbbb-cccc",
  modified: "2026-10-20T00:00:00Z",
  published: "2026-10-18T00:00:00Z",
  aliases: ["CVE-2026-12345"],
  affected: [{ package: { ecosystem: "npm", name: "express" }, ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.21.2" }] }] }],
  references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" }],
  database_specific: { severity: "HIGH" },
};

const liffVuln: OsvRecord = {
  id: "GHSA-liff-liff-liff",
  modified: "2026-10-21T00:00:00Z",
  published: "2026-10-21T00:00:00Z",
  aliases: ["CVE-2026-20000"],
  affected: [{ package: { ecosystem: "npm", name: "@line/liff" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.25.0" }] }] }],
  database_specific: { severity: "MODERATE" },
};

const nginxCve: NvdCve = {
  id: "CVE-2026-30000",
  published: "2026-10-15T00:00:00.000",
  lastModified: "2026-10-16T00:00:00.000",
  metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 9.8, vectorString: "CVSS:3.1/x" } }] },
  configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionStartIncluding: "1.25.0", versionEndExcluding: "1.27.4" }] }] }],
};

const pgCve: NvdCve = {
  id: "CVE-2026-40000",
  published: "2026-10-12T00:00:00.000",
  lastModified: "2026-10-13T00:00:00.000",
  metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 8.8, vectorString: "CVSS:3.1/y" } }] },
  configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", versionStartIncluding: "16.0", versionEndExcluding: "16.5" }] }] }],
  cisaExploitAdd: "2026-10-14",
};

const bom = (components: Array<Record<string, unknown>>) => JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", components });

let seq = 0;
const newId = () => `id-${++seq}`;

async function setup() {
  const app = createAppDb();
  const catalogDb = createCatalogDb();
  const catalog = new CatalogRepo(catalogDb);
  const window = { windowStart: "2026-09-30T00:00:00.000Z" };
  await catalog.setMeta("window_start", window.windowStart);

  // 取り込み（OSV・NVD）
  for (const r of [ghsa, liffVuln]) await catalog.upsertOsv(normalizeOsv(r), null);
  for (const c of [nginxCve, pgCve]) await catalog.applyNvd(c, selectNvdCvss(c), extractWatchlistCpes(c), { createIfMissing: true });
  await catalog.refreshDerived(["CVE-2026-12345", "CVE-2026-20000", "CVE-2026-30000", "CVE-2026-40000"], window);

  insertUser(app, "user-a", "a@example.com");
  const tenantId = await new AccountRepo(app).ensureTenant("user-a", "A社", newId);
  const repo = new TenantRepo(app, tenantId);
  await repo.createProject({ id: "proj", name: "acme-crm" });
  return { app, catalog, catalogDb, repo, window };
}

describe("カタログ", () => {
  it("取り込み後に一般緊急度・トピック・掲載対象を計算する", async () => {
    const { catalog } = await setup();
    const express = await catalog.getFacts("CVE-2026-12345");
    expect(express).toMatchObject({ rank: "B", cvss: { score: 7.0, source: "ghsa" } });
    expect((await catalog.getVulnRow("CVE-2026-12345"))).toMatchObject({ in_scope: 1, topic: "npm" });
    expect((await catalog.getVulnRow("CVE-2026-20000"))).toMatchObject({ topic: "line" });
    expect((await catalog.getVulnRow("CVE-2026-30000"))).toMatchObject({ topic: "middleware", general_rank: "A" });
    const pg = await catalog.getFacts("CVE-2026-40000");
    expect(pg).toMatchObject({ rank: "S", kev: true });
    expect(pg!.packages[0]).toMatchObject({ purl: "pkg:generic/postgresql", affected: ">=16.0 <16.5", fixed: ["16.5"] });
  });

  it("記事を公開し、ソースが更新されたら要更新にする", async () => {
    const { catalog, window } = await setup();
    const facts = (await catalog.getFacts("CVE-2026-12345"))!;
    const rendered = renderArticleMarkdown("## 何が起きるか\n\n本文");
    await catalog.publishArticle({
      slug: "express-cve-2026-12345",
      topic: "npm",
      title: "express CVE-2026-12345｜x｜4.21.2で修正",
      whyRead: "w",
      points: ["a"],
      gains: ["b"],
      faq: [],
      sources: [],
      tags: ["express"],
      bodyMd: "## 何が起きるか\n\n本文",
      bodyHtml: rendered.html,
      checkHtml: null,
      summaryHtml: null,
      toc: rendered.toc,
      excerpt: "",
      description: "",
      readingMinutes: 1,
      cveIds: ["CVE-2026-12345"],
      rank: facts.rank,
      factsHash: factsHash(facts),
    });
    expect(await catalog.countPendingCves()).toBe(3);
    // NVD が CVSS を付けた → 事実が変わる
    await catalog.applyNvd(
      { id: "CVE-2026-12345", published: "2026-10-18T00:00:00.000", lastModified: "2026-10-25T00:00:00.000", metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 7.5, vectorString: "v" } }] } },
      { score: 7.5, version: "3.1", source: "nvd", vector: "v" },
      [],
      { createIfMissing: false },
    );
    const r = await catalog.refreshDerived(["CVE-2026-12345"], window);
    expect(r.needsUpdate).toEqual(["CVE-2026-12345"]);
    const article = await catalog.getArticleBySlug("express-cve-2026-12345");
    expect(article?.needs_update).toBe(1);
    expect(await catalog.countPendingCves()).toBe(4);
    expect((await catalog.searchArticles("express")).map((a) => a.slug)).toEqual(["express-cve-2026-12345"]);
  });
});

describe("スタック登録と突合（8・9章）", () => {
  it("仕様書のサンプルで照合し、個別緊急度を付ける", async () => {
    const { app, catalog, repo, window } = await setup();
    const built = buildStackInput({
      stackYaml,
      boms: {
        "sbom/api-server.cdx.json": bom([
          { purl: "pkg:npm/express@4.17.1" },
          { purl: "pkg:npm/vitest@1.0.0", scope: "optional" },
        ]),
        "sbom/web-liff.cdx.json": bom([{ purl: "pkg:npm/react@18.3.1" }]),
      },
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.summary).toMatchObject({ packages: 3, devPackages: 1, watched: 3, cdn: 1 });
    await repo.replaceStack("proj", {
      serviceName: built.stack.service.name,
      dataSensitivity: built.stack.service.data_sensitivity,
      components: built.stack.components.map((c) => ({ name: c.name, exposure: c.exposure, exposureReason: c.exposure_reason ?? null, managed: c.managed })),
      packages: built.packages,
    });

    const osvCalls: string[][] = [];
    const deps = {
      catalog,
      system: new SystemRepo(app),
      osv: {
        async queryBatch(queries: Array<{ package: { name: string }; version: string }>) {
          osvCalls.push(queries.map((q) => `${q.package.name}@${q.version}`));
          return queries.map((q) => (q.package.name === "express" ? [{ id: "GHSA-aaaa-bbbb-cccc", modified: "x" }] : []));
        },
        async getVuln() {
          return null;
        },
      },
      newId,
      window,
    };
    const keys = await deps.system.distinctPackages();
    await refreshPackageVulns(deps, keys);
    expect(osvCalls[0]).toEqual(expect.arrayContaining(["express@4.17.1", "react@18.3.1", "vitest@1.0.0"]));

    const r = await matchProject(deps, repo, "proj");
    const alerts = await repo.listAlerts("proj");
    const byVuln = Object.fromEntries(alerts.map((a) => [a.vuln_id, a]));
    expect(r.created).toHaveLength(4);
    // express：一般B（GHSA High=7.0）→ internet・high で A
    expect(byVuln["CVE-2026-12345"]).toMatchObject({ rank: "A", general_rank: "B", installed_version: "4.17.1", component: "api-server" });
    // nginx 1.27.3：一般A（CVSS 9.8）→ internet・high（上限A）で A
    expect(byVuln["CVE-2026-30000"]).toMatchObject({ rank: "A", package_label: "nginx" });
    // PostgreSQL（KEV, managed）：S → internal で A → managed で上限B（判定例3）
    expect(byVuln["CVE-2026-40000"]).toMatchObject({ rank: "B", component: "main-db" });
    // LIFF（CDN edge/2 = バージョン不明）→ B固定
    expect(byVuln["CVE-2026-20000"]).toMatchObject({ rank: "B", version_unknown: 1 });

    // 2回目は新規なし
    const again = await matchProject(deps, repo, "proj");
    expect(again.created).toHaveLength(0);
  });

  it("SBOMが添付されていなければ弾く", () => {
    const r = buildStackInput({ stackYaml, boms: {} });
    expect(r.ok).toBe(false);
  });

  it("OSVが止まっていても前回のキャッシュで照合する", async () => {
    const { app, catalog, window } = await setup();
    const system = new SystemRepo(app);
    await system.putCachedVulns([{ ecosystem: "npm", name: "express", version: "4.17.1", vulnIds: ["GHSA-aaaa-bbbb-cccc"] }]);
    const r = await refreshPackageVulns(
      {
        catalog,
        system,
        osv: {
          async queryBatch() {
            throw new Error("OSV 503");
          },
          async getVuln() {
            return null;
          },
        },
        newId,
        window,
      },
      [{ ecosystem: "npm", name: "express", version: "4.17.1" }],
    );
    expect(r.osvError).toContain("503");
    const cached = await system.getCachedVulns([{ ecosystem: "npm", name: "express", version: "4.17.1" }]);
    expect([...cached.values()][0]!.vulnIds).toEqual(["GHSA-aaaa-bbbb-cccc"]);
  });
});
