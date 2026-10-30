import { describe, expect, it } from "vitest";
import { canonicalVulnId, diffIds, normalizeOsv, OsvClient, type OsvRecord } from "../src/osv";
import { selectNvdCvss, extractWatchlistCpes, type NvdCve } from "../src/nvd";
import { hasPoc, parseEpss, parseKev } from "../src/signals";

const ghsa: OsvRecord = {
  id: "GHSA-aaaa-bbbb-cccc",
  modified: "2026-10-20T00:00:00Z",
  published: "2026-10-18T00:00:00Z",
  aliases: ["CVE-2026-12345"],
  summary: "path traversal",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
  affected: [
    {
      package: { ecosystem: "npm", name: "static-gate" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.4.2" }] }],
    },
    {
      package: { ecosystem: "npm", name: "static-gate" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.0.3" }] }],
    },
    { package: { ecosystem: "Maven", name: "org.example:ignored" }, ranges: [] },
  ],
  references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" }],
  database_specific: { severity: "HIGH" },
};

describe("OSV の正規化", () => {
  it("CVE番号を正規IDにして範囲をまとめる", () => {
    const n = normalizeOsv(ghsa);
    expect(n.vulnId).toBe("CVE-2026-12345");
    expect(n.isCve).toBe(true);
    expect(n.aliases).toContain("GHSA-aaaa-bbbb-cccc");
    expect(n.ghsaSeverity).toBe("HIGH");
    expect(n.packages).toHaveLength(1);
    expect(n.packages[0]).toMatchObject({
      purl: "pkg:npm/static-gate",
      affected: "<3.4.2 || >=4.0.0 <4.0.3",
      fixed: ["3.4.2", "4.0.3"],
      topic: "npm",
    });
  });
  it("Debian の ID から CVE 番号を取り出す", () => {
    expect(canonicalVulnId({ id: "DEBIAN-CVE-2026-1111" })).toEqual({ id: "CVE-2026-1111", isCve: true });
    expect(canonicalVulnId({ id: "MAL-2026-1" })).toEqual({ id: "MAL-2026-1", isCve: false });
  });
  it("last_affected を <= にする", () => {
    const n = normalizeOsv({
      id: "CVE-2026-2222",
      modified: "2026-10-01T00:00:00Z",
      affected: [{ package: { ecosystem: "PyPI", name: "line-bot-sdk" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0" }, { last_affected: "3.1.0" }] }] }],
    });
    expect(n.packages[0]).toMatchObject({ affected: ">=1.0 <=3.1.0", fixed: [], topic: "line" });
  });
  it("差分", () => {
    expect(diffIds(["a", "b"], ["b", "c"])).toEqual({ added: ["c"], removed: ["a"] });
  });
  it("querybatch のページングを辿る", async () => {
    const calls: unknown[] = [];
    const fetchFn = async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (calls.length === 1) {
        return Response.json({ results: [{ vulns: [{ id: "A", modified: "x" }], next_page_token: "t" }, {}] });
      }
      return Response.json({ results: [{ vulns: [{ id: "B", modified: "y" }] }] });
    };
    const r = await new OsvClient(fetchFn).queryBatch([
      { package: { ecosystem: "npm", name: "a" }, version: "1.0.0" },
      { package: { ecosystem: "npm", name: "b" }, version: "1.0.0" },
    ]);
    expect(r.map((x) => x.map((v) => v.id))).toEqual([["A", "B"], []]);
    expect((calls[1] as { queries: Array<{ page_token?: string }> }).queries[0]!.page_token).toBe("t");
  });
});

describe("NVD・KEV・EPSS・PoC", () => {
  const cve: NvdCve = {
    id: "CVE-2026-3333",
    published: "2026-10-10T00:00:00.000",
    lastModified: "2026-10-11T00:00:00.000",
    metrics: {
      cvssMetricV40: [{ source: "cna@example.com", type: "Secondary", cvssData: { version: "4.0", baseScore: 8.7, vectorString: "CVSS:4.0/..." } }],
      cvssMetricV31: [
        { source: "cna@example.com", type: "Secondary", cvssData: { version: "3.1", baseScore: 7.0, vectorString: "CVSS:3.1/a" } },
        { source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", baseScore: 7.5, vectorString: "CVSS:3.1/b" } },
      ],
    },
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              { vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*", versionStartIncluding: "1.25.0", versionEndExcluding: "1.27.4" },
              { vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*" },
              { vulnerable: false, criteria: "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*" },
              { vulnerable: true, criteria: "cpe:2.3:a:someone:else:1.0:*:*:*:*:*:*:*" },
            ],
          },
        ],
      },
    ],
    references: [{ url: "https://www.exploit-db.com/exploits/1", tags: [] }],
  };
  it("v3.1 の Primary を優先する", () => {
    expect(selectNvdCvss(cve)).toMatchObject({ score: 7.5, version: "3.1", source: "nvd" });
    const v4only = { ...cve, metrics: { cvssMetricV40: cve.metrics!.cvssMetricV40 } };
    expect(selectNvdCvss(v4only)).toMatchObject({ score: 8.7, version: "4.0", source: "cna" });
    expect(selectNvdCvss({ ...cve, metrics: {} })).toBeNull();
  });
  it("ウォッチリストのCPEだけ取り出す", () => {
    const cpes = extractWatchlistCpes(cve);
    expect(cpes).toHaveLength(2);
    expect(cpes[0]).toMatchObject({ productKey: "nginx", startIncluding: "1.25.0", endExcluding: "1.27.4", exact: null });
    expect(cpes[1]).toMatchObject({ productKey: "nginx", exact: "1.20.0" });
  });
  it("PoC を判定する", () => {
    expect(hasPoc(cve.references!)).toBe(true);
    expect(hasPoc([{ url: "https://example.com/x", tags: ["Exploit", "Third Party Advisory"] }])).toBe(true);
    expect(hasPoc([{ url: "https://example.com/x", tags: ["Patch"] }])).toBe(false);
  });
  it("KEV・EPSS を読む", () => {
    expect(parseKev({ vulnerabilities: [{ cveID: "CVE-1", dateAdded: "2026-10-01" }] })).toEqual([{ cveId: "CVE-1", dateAdded: "2026-10-01" }]);
    expect(parseEpss({ data: [{ cve: "CVE-1", epss: "0.12", percentile: "0.9", date: "2026-10-30" }] })[0]!.epss).toBe(0.12);
  });
});
