import { DISCLAIMERS, SITE } from "./site";
import { RANK_LABELS, type Rank } from "./scoring";

export interface SlackAlertItem {
  vulnId: string;
  projectName: string;
  component: string;
  packageLabel: string;
  installedVersion: string | null;
  rank: Rank;
  generalRank: Rank;
  steps: string[];
  notes: string[];
  versionUnknown: boolean;
  /** 記事があれば記事の Ask AI（プリセット選択済み）へ。なければダッシュボード */
  articleUrl: string | null;
  dashboardUrl: string;
  fixed: string[];
}

const RANK_EMOJI: Record<Rank, string> = { S: ":rotating_light:", A: ":warning:", B: ":large_yellow_circle:", C: ":white_circle:" };

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function askUrl(articleUrl: string, preset = "need"): string {
  const u = new URL(articleUrl);
  u.searchParams.set("ask", preset);
  u.hash = "ask-ai";
  return u.toString();
}

function itemLines(item: SlackAlertItem): string {
  const version = item.versionUnknown ? "バージョン不明（バージョン確認が必要）" : `${item.installedVersion ?? "不明"}（${DISCLAIMERS.versionOnly}）`;
  const links = [
    item.articleUrl ? `<${askUrl(item.articleUrl)}|うちには必要？をAIに聞く>` : null,
    item.articleUrl ? `<${item.articleUrl}|記事>` : null,
    `<${item.dashboardUrl}|ダッシュボード>`,
  ]
    .filter(Boolean)
    .join(" ・ ");
  return [
    `${RANK_EMOJI[item.rank]} *${item.rank}（${RANK_LABELS[item.rank].meaning}）* ${esc(item.vulnId)} — ${esc(item.packageLabel)}`,
    `プロジェクト：${esc(item.projectName)} ／ component：${esc(item.component)}`,
    `使用中：${esc(version)}${item.fixed.length ? ` ／ 修正版：${esc(item.fixed.join(", "))}` : ""}`,
    `一般緊急度 ${item.generalRank} → 個別緊急度 ${item.rank}${item.steps.length ? `（${esc(item.steps.join("、"))}）` : ""}`,
    ...item.notes.map((n) => `:information_source: ${esc(n)}`),
    links,
  ].join("\n");
}

export interface SlackMessage {
  text: string;
  blocks: Array<Record<string, unknown>>;
}

/** S・A の即時通知（7-1） */
export function buildImmediateMessage(items: SlackAlertItem[]): SlackMessage {
  const top = items[0]!;
  const text = `[${SITE.name}] ${top.rank}：${top.vulnId} ほか${items.length - 1 > 0 ? `${items.length - 1}件` : ""}（${top.projectName}）`;
  const blocks: Array<Record<string, unknown>> = [
    { type: "header", text: { type: "plain_text", text: `${SITE.name}｜緊急度 S・A の新しいアラート（${items.length}件）` } },
  ];
  for (const item of items.slice(0, 20)) {
    blocks.push({ type: "section", text: { type: "mrkdwn", text: itemLines(item) } });
    blocks.push({ type: "divider" });
  }
  if (items.length > 20) {
    blocks.push({ type: "section", text: { type: "mrkdwn", text: `ほか ${items.length - 20} 件はダッシュボードで確認してください。` } });
  }
  blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: DISCLAIMERS.judgement }] });
  return { text, blocks };
}

export interface DigestProject {
  projectName: string;
  dashboardUrl: string;
  /** 最終更新からの経過日数（8-2） */
  daysSinceStackUpdate: number | null;
  items: SlackAlertItem[];
  openCounts: Record<Rank, number>;
}

/** 週次まとめ（毎週月曜09:00 JST） */
export function buildDigestMessage(projects: DigestProject[], weekLabel: string): SlackMessage {
  const total = projects.reduce((n, p) => n + p.items.length, 0);
  const text = `[${SITE.name}] 週次まとめ（${weekLabel}）：新しいB・Cのアラート ${total}件`;
  const blocks: Array<Record<string, unknown>> = [
    { type: "header", text: { type: "plain_text", text: `${SITE.name}｜週次まとめ（${weekLabel}）` } },
  ];
  for (const p of projects) {
    const stale =
      p.daysSinceStackUpdate === null
        ? "スタック未登録"
        : `スタック最終更新から ${p.daysSinceStackUpdate} 日${p.daysSinceStackUpdate >= 30 ? " :warning: 更新をおすすめします" : ""}`;
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*${esc(p.projectName)}*　<${p.dashboardUrl}|ダッシュボード>\n${stale}\n未対応：S ${p.openCounts.S} ／ A ${p.openCounts.A} ／ B ${p.openCounts.B} ／ C ${p.openCounts.C}\n今週の新しいB・C：${p.items.length}件`,
      },
    });
    for (const item of p.items.slice(0, 10)) {
      blocks.push({ type: "section", text: { type: "mrkdwn", text: itemLines(item) } });
    }
    if (p.items.length > 10) {
      blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: `ほか ${p.items.length - 10} 件` }] });
    }
    blocks.push({ type: "divider" });
  }
  blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: DISCLAIMERS.judgement }] });
  return { text, blocks: blocks.slice(0, 50) };
}

/** Slack Incoming Webhook のURLか */
export function isSlackWebhookUrl(url: string): boolean {
  return /^https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+$/.test(url.trim());
}

export async function postSlack(webhookUrl: string, message: SlackMessage, fetchFn: typeof fetch = fetch): Promise<void> {
  const res = await fetchFn(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(message),
  });
  if (!res.ok) throw new Error(`Slack ${res.status}: ${await res.text().catch(() => "")}`);
}
