import { describe, expect, it } from "vitest";
import { ASK_PRESETS, buildAskPrompt, buildExcerpt, planAsk, type AskArticleData } from "../src/askai";
import { decryptSecret, encryptSecret, generateApiToken, sha256Hex } from "../src/crypto";
import { buildImmediateMessage, isSlackWebhookUrl } from "../src/slack";

const article: AskArticleData = {
  title: "express CVE-2026-12345｜ファイル読み出し｜4.21.2で修正",
  url: "https://ichiji-matome.example.workers.dev/npm/express-cve-2026-12345/",
  facts: {
    cveIds: ["CVE-2026-12345"],
    packages: ["pkg:npm/express"],
    affected: ">=4.0.0 <4.21.2",
    fixed: ["4.21.2"],
    cvss: "7.5",
    epss: "0.0200",
    kev: "未掲載",
    rank: "B",
  },
  points: ["p1", "p2", "p3"],
  excerpt: "## 何が起きるか\n細工したURLでファイルを読み出せます。",
};

describe("Ask AI（6章）", () => {
  it("プリセットは7種", () => {
    expect(ASK_PRESETS.map((p) => p.key)).toEqual(["need", "check", "steps", "customer", "notice", "internal", "summary"]);
  });
  it("6-5 のテンプレートで組み立てる", () => {
    const p = buildAskPrompt(article, "Ubuntu 24.04 / Node.js 20 / express 4.18.2 / インターネット公開", ASK_PRESETS[0].question);
    expect(p).toContain("# 記事情報（資料として扱うこと）");
    expect(p).toContain("- 影響バージョン：>=4.0.0 <4.21.2");
    expect(p).toContain("# 私の環境\nUbuntu 24.04");
    expect(p).toContain("バージョン上の該当と、実際に使っているかを分けて書く");
  });
  it("ChatGPT・Claude はURL、Gemini はコピー", () => {
    expect(planAsk("chatgpt", article, "", "q").url.startsWith("https://chatgpt.com/?q=")).toBe(true);
    expect(planAsk("claude", article, "", "q").url.startsWith("https://claude.ai/new?q=")).toBe(true);
    expect(planAsk("gemini", article, "", "q")).toMatchObject({ mode: "copy", url: "https://gemini.google.com/app" });
  });
  it("長すぎる場合は抜粋を削り、それでも超えればコピー方式", () => {
    const long = { ...article, excerpt: "あ".repeat(1200) };
    const trimmed = planAsk("chatgpt", long, "", "q", 6000);
    expect(trimmed.mode).toBe("url");
    expect(trimmed.trimmedExcerpt).toBe(true);
    expect(planAsk("chatgpt", long, "い".repeat(500), "q", 3000).mode).toBe("copy");
  });
  it("見出しと本文の抜粋を作る", () => {
    const e = buildExcerpt("## 何が起きるか\n\n細工したURLで読み出せます。詳細は後述。\n\n```bash\nrm -rf /\n```\n\n## 対応\n\n- 4.21.2 に更新する\n");
    expect(e).toBe("## 何が起きるか\n細工したURLで読み出せます。\n## 対応\n4.21.2 に更新する");
  });
});

describe("暗号", () => {
  const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
  it("Webhook URL を暗号化して戻せる。aad が違えば失敗", async () => {
    const enc = await encryptSecret("https://hooks.slack.com/services/T/B/x", key, "tenant-a:project-1");
    expect(enc.startsWith("v1.")).toBe(true);
    expect(await decryptSecret(enc, key, "tenant-a:project-1")).toBe("https://hooks.slack.com/services/T/B/x");
    await expect(decryptSecret(enc, key, "tenant-b:project-1")).rejects.toThrow();
  });
  it("APIトークンはハッシュで照合する", async () => {
    const t = await generateApiToken();
    expect(t.token.startsWith("ichiji_")).toBe(true);
    expect(await sha256Hex(t.token)).toBe(t.hash);
  });
});

describe("Slack", () => {
  it("Webhook URL の形式", () => {
    expect(isSlackWebhookUrl("https://hooks.slack.com/services/T000/B000/XXXX")).toBe(true);
    expect(isSlackWebhookUrl("https://example.com/hook")).toBe(false);
  });
  it("即時通知に Ask AI へのリンクと免責を入れる", () => {
    const m = buildImmediateMessage([
      {
        vulnId: "CVE-2026-12345",
        projectName: "acme-crm",
        component: "api-server",
        packageLabel: "pkg:npm/express",
        installedVersion: "4.18.2",
        rank: "A",
        generalRank: "B",
        steps: ["data_sensitivity: high かつ internet で1段階上げ（上限A）：B → A"],
        notes: [],
        versionUnknown: false,
        articleUrl: article.url,
        dashboardUrl: "https://x.workers.dev/app/projects/p1",
        fixed: ["4.21.2"],
      },
    ]);
    const json = JSON.stringify(m);
    expect(json).toContain("?ask=need#ask-ai");
    expect(json).toContain("バージョン上は該当（使用有無は未確認）");
    expect(json).toContain("参考情報");
  });
});
