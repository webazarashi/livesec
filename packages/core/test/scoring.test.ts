import { describe, expect, it } from "vitest";
import { generalRank, individualRank, type IndividualContext } from "../src/scoring";

const base: IndividualContext = {
  versionMatched: true,
  versionUnknown: false,
  exposure: "internet",
  dataSensitivity: "medium",
  isDev: false,
  managed: false,
  kev: false,
};

describe("一般緊急度（7-3）", () => {
  it("KEV掲載は S", () => {
    expect(generalRank({ cvss: 5, epss: 0, kev: true, poc: false }).rank).toBe("S");
  });
  it("PoCあり かつ CVSS 9.0以上は S", () => {
    expect(generalRank({ cvss: 9.0, epss: 0, kev: false, poc: true }).rank).toBe("S");
    expect(generalRank({ cvss: 8.9, epss: 0, kev: false, poc: true }).rank).toBe("A");
  });
  it("EPSS 0.5以上 かつ CVSS 7.0以上は S", () => {
    expect(generalRank({ cvss: 7.0, epss: 0.5, kev: false, poc: false }).rank).toBe("S");
    expect(generalRank({ cvss: 6.9, epss: 0.9, kev: false, poc: false }).rank).toBe("B");
  });
  it("CVSS 9.0以上は悪用の兆候がなければ A（Sにはしない）", () => {
    expect(generalRank({ cvss: 9.8, epss: 0.01, kev: false, poc: false }).rank).toBe("A");
  });
  it("CVSS 7.0以上 かつ（PoC または EPSS 0.1以上）は A", () => {
    expect(generalRank({ cvss: 7.5, epss: 0.1, kev: false, poc: false }).rank).toBe("A");
    expect(generalRank({ cvss: 7.5, epss: 0, kev: false, poc: true }).rank).toBe("A");
  });
  it("CVSS 7.0以上は B", () => {
    expect(generalRank({ cvss: 7.5, epss: 0.01, kev: false, poc: false }).rank).toBe("B");
  });
  it("CVSS 4.0以上 かつ（PoC または EPSS 0.1以上）は B", () => {
    expect(generalRank({ cvss: 4.0, epss: 0.2, kev: false, poc: false }).rank).toBe("B");
    expect(generalRank({ cvss: 4.0, epss: 0.01, kev: false, poc: false }).rank).toBe("C");
  });
  it("CVSS未算出は C", () => {
    expect(generalRank({ cvss: null, epss: null, kev: false, poc: false }).rank).toBe("C");
  });
});

describe("個別緊急度（7-4）と判定例（7-5）", () => {
  it("例1：B・internet・high → A", () => {
    expect(individualRank("B", { ...base, dataSensitivity: "high" }).rank).toBe("A");
  });
  it("例2：S（KEV）・internal → A（下限A）", () => {
    const r = individualRank("S", { ...base, exposure: "internal", kev: true });
    expect(r.rank).toBe("A");
  });
  it("例3：S（KEV）の PostgreSQL・managed → B（上限B）", () => {
    const r = individualRank("S", { ...base, exposure: "internal", managed: true, kev: true });
    expect(r.rank).toBe("B");
    expect(r.notes.join()).toContain("提供元");
  });
  it("例4：A・offline → C", () => {
    expect(individualRank("A", { ...base, exposure: "offline" }).rank).toBe("C");
  });
  it("該当バージョンを使っていなければ通知しない", () => {
    expect(individualRank("S", { ...base, versionMatched: false }).rank).toBeNull();
  });
  it("バージョン unknown は B 固定", () => {
    const r = individualRank("S", { ...base, versionMatched: false, versionUnknown: true, kev: true });
    expect(r.rank).toBe("B");
    expect(r.notes).toContain("バージョン確認が必要です");
  });
  it("個別の調整で S に上がることはない", () => {
    expect(individualRank("A", { ...base, dataSensitivity: "high" }).rank).toBe("A");
  });
  it("S のまま internet・high なら S（上げも下げもしない）", () => {
    expect(individualRank("S", { ...base, dataSensitivity: "high" }).rank).toBe("S");
  });
  it("開発用依存・low で下げ、C より下にはならない", () => {
    expect(individualRank("B", { ...base, isDev: true, dataSensitivity: "low" }).rank).toBe("C");
    expect(individualRank("C", { ...base, isDev: true }).rank).toBe("C");
  });
  it("KEV かつ managed: false は開発用依存でも下限A", () => {
    expect(individualRank("S", { ...base, exposure: "offline", isDev: true, kev: true }).rank).toBe("A");
  });
});
