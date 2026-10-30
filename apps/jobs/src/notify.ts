import {
  buildDigestMessage,
  buildImmediateMessage,
  decryptSecret,
  isImmediateRank,
  postSlack,
  randomId,
  type DigestProject,
  type SlackAlertItem,
} from "@ichiji/core";
import { alertSteps, type AlertRow, type CatalogRepo, type TenantRepo } from "@ichiji/db";

export interface NotifyDeps {
  catalog: CatalogRepo;
  baseUrl: string;
  encKey: string;
  fetch: typeof fetch;
}

function dashboardUrl(baseUrl: string, projectId: string): string {
  return `${baseUrl}/app/projects/${encodeURIComponent(projectId)}/`;
}

async function toItems(deps: NotifyDeps, projectName: string, projectId: string, alerts: AlertRow[]): Promise<SlackAlertItem[]> {
  const urls = await deps.catalog.articleUrlsForCves([...new Set(alerts.map((a) => a.vuln_id))]);
  return alerts.map((a) => {
    const article = urls.get(a.vuln_id);
    const { steps, notes, fixed } = alertSteps(a);
    return {
      vulnId: a.vuln_id,
      projectName,
      component: a.component,
      packageLabel: a.package_label,
      installedVersion: a.installed_version,
      rank: a.rank,
      generalRank: a.general_rank,
      steps,
      notes,
      versionUnknown: a.version_unknown === 1,
      articleUrl: article ? `${deps.baseUrl}/${article.topic}/${article.slug}/` : null,
      dashboardUrl: dashboardUrl(deps.baseUrl, projectId),
      fixed,
    };
  });
}

async function webhookFor(deps: NotifyDeps, repo: TenantRepo, projectId: string): Promise<string | null> {
  const enc = await repo.getSlackWebhookEnc(projectId);
  if (!enc) return null;
  return decryptSecret(enc, deps.encKey, `${repo.tenantId}:${projectId}`);
}

/** S・A の新しいアラートを Slack に即時通知する（7-1） */
export async function notifyImmediate(deps: NotifyDeps, repo: TenantRepo, projectId: string, created: AlertRow[]): Promise<{ sent: number }> {
  const urgent = created.filter((a) => isImmediateRank(a.rank) && !a.notified_at);
  if (!urgent.length) return { sent: 0 };
  const project = await repo.getProject(projectId);
  if (!project) return { sent: 0 };
  const webhook = await webhookFor(deps, repo, projectId);
  if (!webhook) {
    // Webhook 未設定でも、ダッシュボードには出ているので通知済み扱いにはしない
    return { sent: 0 };
  }
  const items = await toItems(deps, project.name, projectId, urgent);
  try {
    await postSlack(webhook, buildImmediateMessage(items), deps.fetch);
    await repo.markNotified(projectId, urgent.map((a) => a.id));
    await repo.logNotification({ id: randomId(), projectId, kind: "immediate", ok: true, detail: `${urgent.length}件` });
    return { sent: urgent.length };
  } catch (e) {
    await repo.logNotification({ id: randomId(), projectId, kind: "immediate", ok: false, detail: String(e) });
    throw e;
  }
}

function jstWeekLabel(now: Date): string {
  const jst = new Date(now.getTime() + 9 * 3_600_000);
  return `${jst.getUTCFullYear()}年${jst.getUTCMonth() + 1}月${jst.getUTCDate()}日`;
}

/** 週次まとめ（毎週月曜09:00 JST）。B以下の新しいアラートとスタックの経過日数 */
export async function sendDigest(deps: NotifyDeps, repo: TenantRepo, projectId: string, now = new Date()): Promise<{ sent: boolean; items: number }> {
  const project = await repo.getProject(projectId);
  if (!project) return { sent: false, items: 0 };
  const alerts = await repo.alertsForDigest(projectId);
  const counts = await repo.alertCounts(projectId);
  const webhook = await webhookFor(deps, repo, projectId);
  const days = project.stack_updated_at ? Math.floor((now.getTime() - new Date(project.stack_updated_at).getTime()) / 86_400_000) : null;
  if (webhook) {
    const digest: DigestProject = {
      projectName: project.name,
      dashboardUrl: dashboardUrl(deps.baseUrl, projectId),
      daysSinceStackUpdate: days,
      items: await toItems(deps, project.name, projectId, alerts),
      openCounts: { S: counts.S, A: counts.A, B: counts.B, C: counts.C },
    };
    try {
      await postSlack(webhook, buildDigestMessage([digest], jstWeekLabel(now)), deps.fetch);
      await repo.logNotification({ id: randomId(), projectId, kind: "digest", ok: true, detail: `${alerts.length}件` });
    } catch (e) {
      await repo.logNotification({ id: randomId(), projectId, kind: "digest", ok: false, detail: String(e) });
      throw e;
    }
  }
  // Webhook がなくても、次の週に同じアラートを繰り返さないよう送信済みにする
  await repo.markDigestSent(projectId, alerts.map((a) => a.id));
  return { sent: Boolean(webhook), items: alerts.length };
}
