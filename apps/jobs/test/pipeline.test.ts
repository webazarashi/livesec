import { describe, expect, it } from "vitest";
import { CatalogRepo, TenantRepo, AccountRepo } from "@ichiji/db";
import { encryptSecret } from "@ichiji/core";
import { createAppDb, createCatalogDb, insertUser } from "../../../packages/db/test/d1-shim";
import { ingestOsvRecords, listOsvUpdates, ingestKev, type PipelineDeps } from "../src/pipeline";
import { notifyImmediate, sendDigest } from "../src/notify";
import { CRON_JOBS } from "../src/cron";

const record = {
  id: "GHSA-aaaa-bbbb-cccc",
  modified: "2026-10-20T00:00:00Z",
  published: "2026-10-18T00:00:00Z",
  aliases: ["CVE-2026-12345"],
  affected: [{ package: { ecosystem: "npm", name: "express" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.21.2" }] }] }],
};
const kernel = {
  id: "DEBIAN-CVE-2026-9999",
  modified: "2026-10-20T00:00:00Z",
  affected: [{ package: { ecosystem: "Debian:12", name: "linux" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "6.1.1" }] }] }],
};

function deps(catalog: CatalogRepo, saved: string[]): PipelineDeps {
  return {
    catalog,
    saveRaw: async (key) => {
      saved.push(key);
    },
    sleep: async () => {},
    fetch: async (url: string) => {
      if (url.endsWith("/npm/modified_id.csv")) {
        return new Response("2026-10-20T00:00:00Z,GHSA-aaaa-bbbb-cccc\n2026-10-19T00:00:00Z,MAL-2026-1\n2026-09-01T00:00:00Z,GHSA-old\n");
      }
      if (url.endsWith("/npm/GHSA-aaaa-bbbb-cccc.json")) return Response.json(record);
      if (url.endsWith("/Debian/DEBIAN-CVE-2026-9999.json")) return Response.json(kernel);
      if (url.includes("known_exploited")) return Response.json({ vulnerabilities: [{ cveID: "CVE-2026-12345", dateAdded: "2026-10-21" }] });
      return new Response("not found", { status: 404 });
    },
  };
}

describe("取り込み", () => {
  it("OSV の更新一覧を読み、MAL- と古いものを除き、取り込む", async () => {
    const catalog = new CatalogRepo(createCatalogDb());
    const saved: string[] = [];
    const d = deps(catalog, saved);
    const list = await listOsvUpdates(d, "npm", "2026-09-30T00:00:00Z");
    expect(list.ids.map((x) => x.id)).toEqual(["GHSA-aaaa-bbbb-cccc"]);
    expect(list.newest).toBe("2026-10-20T00:00:00Z");
    const touched = await ingestOsvRecords(d, "npm", list.ids);
    expect(touched).toEqual(["CVE-2026-12345"]);
    expect(saved[0]).toMatch(/^osv\/npm\/GHSA-aaaa-bbbb-cccc@/);
    // 2回目は取り込み済みなので対象外
    expect((await listOsvUpdates(d, "npm", "2026-09-30T00:00:00Z")).ids).toEqual([]);
    // カーネル（対象外のOSパッケージ）は入れない
    expect(await ingestOsvRecords(d, "Debian", [{ id: "DEBIAN-CVE-2026-9999", modified: "x" }])).toEqual([]);
    // KEV
    expect(await ingestKev(d)).toEqual(["CVE-2026-12345"]);
    await catalog.refreshDerived(["CVE-2026-12345"], { windowStart: "2026-09-30T00:00:00Z" });
    expect((await catalog.getVulnRow("CVE-2026-12345"))?.general_rank).toBe("S");
  });

  it("Cron の式とジョブの対応（11章）", () => {
    expect(CRON_JOBS["0 */3 * * *"]).toEqual({ type: "ingest" });
    expect(CRON_JOBS["0 0 * * 1"]).toEqual({ type: "digest" });
  });
});

describe("通知", () => {
  const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(3)));

  async function setup() {
    const app = createAppDb();
    insertUser(app, "u", "u@example.com");
    const tenantId = await new AccountRepo(app).ensureTenant("u", "A社", () => "tenant-1");
    const repo = new TenantRepo(app, tenantId);
    await repo.createProject({ id: "p1", name: "acme-crm" });
    await repo.setSlackWebhook("p1", await encryptSecret("https://hooks.slack.com/services/T0/B0/xyz", key, `${tenantId}:p1`));
    const base = {
      vulnId: "CVE-2026-12345",
      component: "api-server",
      packageLabel: "pkg:npm/express",
      installedVersion: "4.17.1",
      versionUnknown: false,
      isDev: false,
      generalRank: "B" as const,
      steps: [],
      notes: [],
      fixed: ["4.21.2"],
    };
    const { created } = await repo.applyMatches("p1", [
      { ...base, id: "a1", packageKey: "package:npm:express", rank: "A" },
      { ...base, id: "a2", vulnId: "CVE-2026-2", packageKey: "package:npm:qs", rank: "C" },
    ]);
    const catalog = new CatalogRepo(createCatalogDb());
    return { repo, created, catalog };
  }

  it("S・A は即時、B・C は週次まとめ", async () => {
    const { repo, created, catalog } = await setup();
    const posts: Array<{ url: string; body: string }> = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      posts.push({ url, body: String(init?.body) });
      return new Response("ok");
    }) as typeof fetch;
    const deps = { catalog, baseUrl: "https://ichiji.example.workers.dev", encKey: key, fetch: fetchFn };

    expect(await notifyImmediate(deps, repo, "p1", created)).toEqual({ sent: 1 });
    expect(posts[0]!.url).toBe("https://hooks.slack.com/services/T0/B0/xyz");
    expect(posts[0]!.body).toContain("CVE-2026-12345");
    expect(posts[0]!.body).not.toContain("CVE-2026-2");
    expect((await repo.getAlert("p1", "a1"))?.notified_at).not.toBeNull();

    const digest = await sendDigest(deps, repo, "p1", new Date("2026-11-02T00:00:00Z"));
    expect(digest).toEqual({ sent: true, items: 1 });
    expect(posts[1]!.body).toContain("CVE-2026-2");
    expect(posts[1]!.body).toContain("週次まとめ（2026年11月2日）");
    // 2回目は送らない
    expect((await sendDigest(deps, repo, "p1")).items).toBe(0);
  });
});
