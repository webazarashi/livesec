import { describe, expect, it } from "vitest";
import { compareVersions, intervalsToRange, normalizeRange, rangesEqual, satisfiesRange, inInterval } from "../src/version";

describe("compareVersions", () => {
  it("数字ドット区切りで比較する", () => {
    expect(compareVersions("1.27.3", "1.27.10")).toBeLessThan(0);
    expect(compareVersions("16.4", "16.4.0")).toBe(0);
    expect(compareVersions("v2.0.0", "1.9.9")).toBeGreaterThan(0);
  });
  it("英字の接尾辞・プレリリース", () => {
    expect(compareVersions("1.1.1", "1.1.1w")).toBeLessThan(0);
    expect(compareVersions("1.1.1a", "1.1.1w")).toBeLessThan(0);
    expect(compareVersions("1.0.0-rc1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("9.8p1", "9.9")).toBeLessThan(0);
  });
});

describe("範囲", () => {
  it("区間を正規の文字列にする", () => {
    expect(intervalsToRange([{ introduced: "4.0.0", fixed: "4.21.2" }, { introduced: "0", fixed: "3.0.1" }])).toBe(
      "<3.0.1 || >=4.0.0 <4.21.2",
    );
    expect(intervalsToRange([{ introduced: "0" }])).toBe("*");
  });
  it("表記の揺れを吸収して比較する", () => {
    expect(rangesEqual(">= 4.0.0, < 4.21.2", ">=4.0.0 <4.21.2")).toBe(true);
    expect(rangesEqual("<4.21.2 >=4.0.0", ">=4.0.0 <4.21.2")).toBe(true);
    expect(rangesEqual(">=5.0.0 <5.0.1 || >=4.0.0 <4.21.2", ">=4.0.0 <4.21.2 || >=5.0.0 <5.0.1")).toBe(true);
    expect(rangesEqual(">=4.0.0 <4.21.1", ">=4.0.0 <4.21.2")).toBe(false);
    expect(normalizeRange("v1.2.3")).toBe("1.2.3");
  });
  it("バージョンが範囲に入るか", () => {
    expect(satisfiesRange("4.18.0", ">=4.0.0 <4.21.2")).toBe(true);
    expect(satisfiesRange("4.21.2", ">=4.0.0 <4.21.2")).toBe(false);
    expect(satisfiesRange("2.0.0", "<3.0.1 || >=4.0.0 <4.21.2")).toBe(true);
    expect(inInterval("1.27.3", { startIncluding: "1.25.0", endExcluding: "1.27.4" })).toBe(true);
    expect(inInterval("1.27.4", { startIncluding: "1.25.0", endExcluding: "1.27.4" })).toBe(false);
    expect(inInterval("16.4", { endIncluding: "16.4" })).toBe(true);
  });
});
