import { describe, expect, it } from "vitest";
import { AccountRepo } from "../src/account";
import { TenantRepo } from "../src/tenant";
import { SystemRepo } from "../src/system";
import { createAppDb, insertUser } from "./d1-shim";

let seq = 0;
const newId = () => `id-${++seq}`;

async function setup() {
  const db = createAppDb();
  insertUser(db, "user-a", "a@example.com");
  insertUser(db, "user-b", "b@example.com");
  const accounts = new AccountRepo(db);
  const tenantA = await accounts.ensureTenant("user-a", "A社", newId);
  const tenantB = await accounts.ensureTenant("user-b", "B社", newId);
  const a = new TenantRepo(db, tenantA);
  const b = new TenantRepo(db, tenantB);
  const project = await a.createProject({ id: "proj-a", name: "acme-crm" });
  await a.replaceStack(project.id, {
    serviceName: "acme-crm",
    dataSensitivity: "high",
    components: [{ name: "api-server", exposure: "internet", exposureReason: null, managed: false }],
    packages: [
      { component: "api-server", kind: "package", ecosystem: "npm", name: "express", version: "4.17.1", purl: "pkg:npm/express@4.17.1", isDev: false, source: "sbom" },
    ],
  });
  await a.applyMatches(project.id, [
    {
      id: "alert-a",
      vulnId: "CVE-2026-12345",
      component: "api-server",
      packageKey: "package:npm:express",
      packageLabel: "pkg:npm/express",
      installedVersion: "4.17.1",
      versionUnknown: false,
      isDev: false,
      generalRank: "B",
      rank: "A",
      steps: [],
      notes: [],
      fixed: ["4.21.2"],
    },
  ]);
  return { db, accounts, a, b, tenantA, tenantB };
}

describe("テナント分離（12章）", () => {
  it("tenantId なしでは作れない", () => {
    expect(() => new TenantRepo(createAppDb(), "")).toThrow();
  });

  it("他テナントのプロジェクト・アラート・パッケージを読めない", async () => {
    const { a, b } = await setup();
    expect(await a.getProject("proj-a")).not.toBeNull();
    expect(await b.getProject("proj-a")).toBeNull();
    expect(await b.listProjects()).toEqual([]);
    expect(await b.listAlerts("proj-a")).toEqual([]);
    expect(await b.getAlert("proj-a", "alert-a")).toBeNull();
    expect(await b.listPackages("proj-a")).toEqual([]);
    expect(await b.listComponents("proj-a")).toEqual([]);
    expect(await b.alertCounts("proj-a")).toMatchObject({ total: 0 });
    expect(await b.getSlackWebhookEnc("proj-a")).toBeNull();
  });

  it("他テナントのデータを書き換え・削除できない", async () => {
    const { a, b } = await setup();
    expect(await b.updateAlertStatus("proj-a", "alert-a", "done", "user-b")).toBe(false);
    expect(await b.setSlackWebhook("proj-a", "v1.x.y")).toBe(false);
    expect(await b.setApiToken("proj-a", "hash", "hint")).toBe(false);
    expect(await b.renameProject("proj-a", "pwned")).toBe(false);
    expect(await b.deleteProject("proj-a")).toBe(false);
    await expect(
      b.replaceStack("proj-a", { serviceName: "x", dataSensitivity: "low", components: [], packages: [] }),
    ).rejects.toThrow();
    const alert = await a.getAlert("proj-a", "alert-a");
    expect(alert?.status).toBe("open");
    expect((await a.getProject("proj-a"))?.name).toBe("acme-crm");
    expect(await a.listPackages("proj-a")).toHaveLength(1);
  });

  it("自テナントでは状態を変更できる", async () => {
    const { a } = await setup();
    expect(await a.updateAlertStatus("proj-a", "alert-a", "in_progress", "user-a")).toBe(true);
    expect((await a.getAlert("proj-a", "alert-a"))?.status).toBe("in_progress");
  });

  it("APIトークンはハッシュで解決し、得たテナントのリポジトリだけ使う", async () => {
    const { db, a, tenantA } = await setup();
    await a.setApiToken("proj-a", "hash-1", "ichiji_xxx…");
    const ref = await new SystemRepo(db).findProjectByTokenHash("hash-1");
    expect(ref).toEqual({ projectId: "proj-a", tenantId: tenantA });
    expect(await new SystemRepo(db).findProjectByTokenHash("nope")).toBeNull();
  });

  it("私の環境は上限文字数で切る", async () => {
    const { accounts } = await setup();
    await accounts.setMyEnvironment("user-a", "あ".repeat(600));
    expect([...(await accounts.getMyEnvironment("user-a")).text]).toHaveLength(500);
    expect((await accounts.getMyEnvironment("user-b")).text).toBe("");
  });

  it("照合で該当しなくなったアラートは解消し、再び該当したら戻す", async () => {
    const { a } = await setup();
    const r1 = await a.applyMatches("proj-a", []);
    expect(r1.resolved).toBe(1);
    expect(await a.listAlerts("proj-a")).toHaveLength(0);
    const r2 = await a.applyMatches("proj-a", [
      {
        id: "alert-new",
        vulnId: "CVE-2026-12345",
        component: "api-server",
        packageKey: "package:npm:express",
        packageLabel: "pkg:npm/express",
        installedVersion: "4.17.1",
        versionUnknown: false,
        isDev: false,
        generalRank: "B",
        rank: "A",
        steps: [],
        notes: [],
        fixed: [],
      },
    ]);
    expect(r2.created).toHaveLength(0);
    expect(await a.listAlerts("proj-a")).toHaveLength(1);
  });
});
