import type { AlertStatus, DataSensitivity, Exposure, Rank } from "@ichiji/core";
import { chunk, MAX_BINDINGS, nowIso, parseJson, placeholders, runBatches } from "./util";

/**
 * テナントのデータへのアクセスはすべてこのクラスを通す（12章：テナント分離）。
 * すべてのSQLに `tenant_id = ?` を入れ、コンストラクタで受け取ったテナントIDだけを読み書きする。
 */
export class TenantRepo {
  constructor(
    private readonly db: D1Database,
    readonly tenantId: string,
  ) {
    if (!tenantId) throw new Error("tenantId は必須です");
  }

  // ---------- プロジェクト ----------

  async listProjects(): Promise<ProjectRow[]> {
    const { results } = await this.db
      .prepare(`SELECT ${PROJECT_COLUMNS} FROM projects WHERE tenant_id = ? ORDER BY created_at`)
      .bind(this.tenantId)
      .all<ProjectRow>();
    return results;
  }

  async getProject(projectId: string): Promise<ProjectRow | null> {
    return this.db
      .prepare(`SELECT ${PROJECT_COLUMNS} FROM projects WHERE tenant_id = ? AND id = ?`)
      .bind(this.tenantId, projectId)
      .first<ProjectRow>();
  }

  async createProject(input: { id: string; name: string }): Promise<ProjectRow> {
    const now = nowIso();
    await this.db
      .prepare("INSERT INTO projects (id, tenant_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
      .bind(input.id, this.tenantId, input.name, now, now)
      .run();
    return (await this.getProject(input.id))!;
  }

  async renameProject(projectId: string, name: string): Promise<boolean> {
    const r = await this.db
      .prepare("UPDATE projects SET name = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
      .bind(name, nowIso(), this.tenantId, projectId)
      .run();
    return (r.meta.changes ?? 0) > 0;
  }

  async deleteProject(projectId: string): Promise<boolean> {
    const stmts = ["project_packages", "project_components", "alerts", "stack_uploads", "notification_log"].map((t) =>
      this.db.prepare(`DELETE FROM ${t} WHERE tenant_id = ? AND project_id = ?`).bind(this.tenantId, projectId),
    );
    stmts.push(this.db.prepare("DELETE FROM projects WHERE tenant_id = ? AND id = ?").bind(this.tenantId, projectId));
    const results = await this.db.batch(stmts);
    return (results.at(-1)?.meta.changes ?? 0) > 0;
  }

  async setApiToken(projectId: string, hash: string, hint: string): Promise<boolean> {
    const r = await this.db
      .prepare("UPDATE projects SET api_token_hash = ?, api_token_hint = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
      .bind(hash, hint, nowIso(), this.tenantId, projectId)
      .run();
    return (r.meta.changes ?? 0) > 0;
  }

  async setSlackWebhook(projectId: string, encrypted: string | null): Promise<boolean> {
    const r = await this.db
      .prepare("UPDATE projects SET slack_webhook_enc = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
      .bind(encrypted, nowIso(), this.tenantId, projectId)
      .run();
    return (r.meta.changes ?? 0) > 0;
  }

  async getSlackWebhookEnc(projectId: string): Promise<string | null> {
    const row = await this.db
      .prepare("SELECT slack_webhook_enc FROM projects WHERE tenant_id = ? AND id = ?")
      .bind(this.tenantId, projectId)
      .first<{ slack_webhook_enc: string | null }>();
    return row?.slack_webhook_enc ?? null;
  }

  // ---------- スタック ----------

  /** stack.yaml ＋ bom.json の内容でプロジェクトの照合対象を入れ替える */
  async replaceStack(
    projectId: string,
    input: {
      serviceName: string;
      dataSensitivity: DataSensitivity;
      components: Array<{ name: string; exposure: Exposure; exposureReason: string | null; managed: boolean }>;
      packages: ProjectPackageInput[];
    },
  ): Promise<void> {
    const project = await this.getProject(projectId);
    if (!project) throw new Error("プロジェクトが見つかりません");
    const now = nowIso();
    const stmts: D1PreparedStatement[] = [
      this.db
        .prepare("UPDATE projects SET service_name = ?, data_sensitivity = ?, stack_updated_at = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
        .bind(input.serviceName, input.dataSensitivity, now, now, this.tenantId, projectId),
      this.db.prepare("DELETE FROM project_components WHERE tenant_id = ? AND project_id = ?").bind(this.tenantId, projectId),
      this.db.prepare("DELETE FROM project_packages WHERE tenant_id = ? AND project_id = ?").bind(this.tenantId, projectId),
      ...input.components.map((c) =>
        this.db
          .prepare("INSERT INTO project_components (tenant_id, project_id, name, exposure, exposure_reason, managed) VALUES (?, ?, ?, ?, ?, ?)")
          .bind(this.tenantId, projectId, c.name, c.exposure, c.exposureReason, c.managed ? 1 : 0),
      ),
      ...input.packages.map((p) =>
        this.db
          .prepare(
            "INSERT OR REPLACE INTO project_packages (tenant_id, project_id, component, kind, ecosystem, name, version, purl, is_dev, source, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .bind(this.tenantId, projectId, p.component, p.kind, p.ecosystem, p.name, p.version, p.purl, p.isDev ? 1 : 0, p.source, p.evidence ?? null),
      ),
    ];
    // 入れ替えは1回の batch（トランザクション）で行いたいが、上限があるので先頭の削除と最初の挿入をまとめる
    await runBatches(this.db, stmts, 500);
  }

  async listComponents(projectId: string): Promise<ComponentRow[]> {
    const { results } = await this.db
      .prepare("SELECT name, exposure, exposure_reason, managed FROM project_components WHERE tenant_id = ? AND project_id = ? ORDER BY name")
      .bind(this.tenantId, projectId)
      .all<ComponentRow>();
    return results;
  }

  async listPackages(projectId: string): Promise<ProjectPackageRow[]> {
    const { results } = await this.db
      .prepare(
        "SELECT component, kind, ecosystem, name, version, purl, is_dev, source, evidence FROM project_packages WHERE tenant_id = ? AND project_id = ? ORDER BY component, kind, ecosystem, name",
      )
      .bind(this.tenantId, projectId)
      .all<ProjectPackageRow>();
    return results;
  }

  async packageCounts(projectId: string): Promise<Array<{ component: string; kind: string; n: number; dev: number }>> {
    const { results } = await this.db
      .prepare(
        "SELECT component, kind, COUNT(*) AS n, SUM(is_dev) AS dev FROM project_packages WHERE tenant_id = ? AND project_id = ? GROUP BY component, kind ORDER BY component",
      )
      .bind(this.tenantId, projectId)
      .all<{ component: string; kind: string; n: number; dev: number }>();
    return results;
  }

  async recordUpload(input: { id: string; projectId: string; via: "api" | "ui"; r2Prefix: string; summary: unknown }): Promise<void> {
    await this.db
      .prepare("INSERT INTO stack_uploads (id, tenant_id, project_id, uploaded_at, via, r2_prefix, summary) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(input.id, this.tenantId, input.projectId, nowIso(), input.via, input.r2Prefix, JSON.stringify(input.summary))
      .run();
  }

  async listUploads(projectId: string, limit = 10): Promise<Array<{ id: string; uploaded_at: string; via: string; summary: string }>> {
    const { results } = await this.db
      .prepare("SELECT id, uploaded_at, via, summary FROM stack_uploads WHERE tenant_id = ? AND project_id = ? ORDER BY uploaded_at DESC LIMIT ?")
      .bind(this.tenantId, projectId, limit)
      .all<{ id: string; uploaded_at: string; via: string; summary: string }>();
    return results;
  }

  // ---------- アラート ----------

  async listAlerts(projectId: string, options: { statuses?: AlertStatus[]; includeResolved?: boolean; limit?: number } = {}): Promise<AlertRow[]> {
    const where = ["tenant_id = ?", "project_id = ?"];
    const binds: unknown[] = [this.tenantId, projectId];
    if (options.statuses?.length) {
      where.push(`status IN (${placeholders(options.statuses.length)})`);
      binds.push(...options.statuses);
    }
    if (!options.includeResolved) where.push("resolved_at IS NULL");
    const { results } = await this.db
      .prepare(
        `SELECT * FROM alerts WHERE ${where.join(" AND ")}
         ORDER BY CASE rank WHEN 'S' THEN 0 WHEN 'A' THEN 1 WHEN 'B' THEN 2 ELSE 3 END, first_detected_at DESC LIMIT ?`,
      )
      .bind(...binds, options.limit ?? 500)
      .all<AlertRow>();
    return results;
  }

  async getAlert(projectId: string, alertId: string): Promise<AlertRow | null> {
    return this.db
      .prepare("SELECT * FROM alerts WHERE tenant_id = ? AND project_id = ? AND id = ?")
      .bind(this.tenantId, projectId, alertId)
      .first<AlertRow>();
  }

  async updateAlertStatus(projectId: string, alertId: string, status: AlertStatus, userId: string): Promise<boolean> {
    const r = await this.db
      .prepare("UPDATE alerts SET status = ?, status_updated_at = ?, status_updated_by = ? WHERE tenant_id = ? AND project_id = ? AND id = ?")
      .bind(status, nowIso(), userId, this.tenantId, projectId, alertId)
      .run();
    return (r.meta.changes ?? 0) > 0;
  }

  async alertCounts(projectId: string): Promise<Record<Rank, number> & { total: number }> {
    const { results } = await this.db
      .prepare(
        "SELECT rank, COUNT(*) AS n FROM alerts WHERE tenant_id = ? AND project_id = ? AND resolved_at IS NULL AND status IN ('open','in_progress') GROUP BY rank",
      )
      .bind(this.tenantId, projectId)
      .all<{ rank: Rank; n: number }>();
    const out = { S: 0, A: 0, B: 0, C: 0, total: 0 };
    for (const r of results) {
      out[r.rank] = r.n;
      out.total += r.n;
    }
    return out;
  }

  /**
   * 照合結果を反映する（9-1：前回結果との差分 ＝ 新たに該当したCVE）。
   * - 新しい該当 → アラートを作る（作ったものを返す）
   * - 既存の該当 → last_seen_at・緊急度を更新（解消済みだったものは再オープン）
   * - 該当しなくなったもの → resolved_at を入れる
   */
  async applyMatches(projectId: string, matches: AlertMatch[]): Promise<{ created: AlertRow[]; resolved: number }> {
    const now = nowIso();
    const { results: existing } = await this.db
      .prepare("SELECT id, vuln_id, component, package_key, resolved_at FROM alerts WHERE tenant_id = ? AND project_id = ?")
      .bind(this.tenantId, projectId)
      .all<{ id: string; vuln_id: string; component: string; package_key: string; resolved_at: string | null }>();
    const key = (m: { vuln_id: string; component: string; package_key: string }) => `${m.vuln_id}\u0000${m.component}\u0000${m.package_key}`;
    const byKey = new Map(existing.map((e) => [key(e), e]));
    const seen = new Set<string>();
    const stmts: D1PreparedStatement[] = [];
    const createdIds: string[] = [];

    for (const m of matches) {
      const k = key({ vuln_id: m.vulnId, component: m.component, package_key: m.packageKey });
      if (seen.has(k)) continue;
      seen.add(k);
      const prev = byKey.get(k);
      if (prev) {
        stmts.push(
          this.db
            .prepare(
              `UPDATE alerts SET last_seen_at = ?, resolved_at = NULL, general_rank = ?, rank = ?, rank_steps = ?, rank_notes = ?, installed_version = ?,
                 version_unknown = ?, is_dev = ?, fixed = ?, package_label = ? WHERE tenant_id = ? AND project_id = ? AND id = ?`,
            )
            .bind(
              now,
              m.generalRank,
              m.rank,
              JSON.stringify(m.steps),
              JSON.stringify(m.notes),
              m.installedVersion,
              m.versionUnknown ? 1 : 0,
              m.isDev ? 1 : 0,
              JSON.stringify(m.fixed),
              m.packageLabel,
              this.tenantId,
              projectId,
              prev.id,
            ),
        );
      } else {
        createdIds.push(m.id);
        stmts.push(
          this.db
            .prepare(
              `INSERT INTO alerts (id, tenant_id, project_id, vuln_id, component, package_key, package_label, installed_version, version_unknown, is_dev,
                 general_rank, rank, rank_steps, rank_notes, fixed, status, first_detected_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
            )
            .bind(
              m.id,
              this.tenantId,
              projectId,
              m.vulnId,
              m.component,
              m.packageKey,
              m.packageLabel,
              m.installedVersion,
              m.versionUnknown ? 1 : 0,
              m.isDev ? 1 : 0,
              m.generalRank,
              m.rank,
              JSON.stringify(m.steps),
              JSON.stringify(m.notes),
              JSON.stringify(m.fixed),
              now,
              now,
            ),
        );
      }
    }
    let resolved = 0;
    for (const e of existing) {
      if (!seen.has(key(e)) && !e.resolved_at) {
        resolved++;
        stmts.push(this.db.prepare("UPDATE alerts SET resolved_at = ? WHERE tenant_id = ? AND project_id = ? AND id = ?").bind(now, this.tenantId, projectId, e.id));
      }
    }
    stmts.push(this.db.prepare("UPDATE projects SET last_matched_at = ? WHERE tenant_id = ? AND id = ?").bind(now, this.tenantId, projectId));
    await runBatches(this.db, stmts);

    const created: AlertRow[] = [];
    for (const part of chunk(createdIds, MAX_BINDINGS - 2)) {
      const { results } = await this.db
        .prepare(`SELECT * FROM alerts WHERE tenant_id = ? AND project_id = ? AND id IN (${placeholders(part.length)})`)
        .bind(this.tenantId, projectId, ...part)
        .all<AlertRow>();
      created.push(...results);
    }
    return { created, resolved };
  }

  async markNotified(projectId: string, alertIds: string[]): Promise<void> {
    const now = nowIso();
    await runBatches(
      this.db,
      alertIds.map((id) =>
        this.db.prepare("UPDATE alerts SET notified_at = ? WHERE tenant_id = ? AND project_id = ? AND id = ?").bind(now, this.tenantId, projectId, id),
      ),
    );
  }

  /** 週次まとめの対象：B・Cで、まだ週次まとめに載せていない未解消のアラート */
  async alertsForDigest(projectId: string): Promise<AlertRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT * FROM alerts WHERE tenant_id = ? AND project_id = ? AND rank IN ('B','C') AND digest_sent_at IS NULL AND resolved_at IS NULL
         ORDER BY rank, first_detected_at`,
      )
      .bind(this.tenantId, projectId)
      .all<AlertRow>();
    return results;
  }

  async markDigestSent(projectId: string, alertIds: string[]): Promise<void> {
    const now = nowIso();
    await runBatches(
      this.db,
      alertIds.map((id) =>
        this.db.prepare("UPDATE alerts SET digest_sent_at = ? WHERE tenant_id = ? AND project_id = ? AND id = ?").bind(now, this.tenantId, projectId, id),
      ),
    );
  }

  async logNotification(input: { id: string; projectId: string; kind: string; ok: boolean; detail?: string }): Promise<void> {
    await this.db
      .prepare("INSERT INTO notification_log (id, tenant_id, project_id, kind, sent_at, ok, detail) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(input.id, this.tenantId, input.projectId, input.kind, nowIso(), input.ok ? 1 : 0, input.detail?.slice(0, 1000) ?? null)
      .run();
  }

  async listNotifications(projectId: string, limit = 10): Promise<Array<{ kind: string; sent_at: string; ok: number; detail: string | null }>> {
    const { results } = await this.db
      .prepare("SELECT kind, sent_at, ok, detail FROM notification_log WHERE tenant_id = ? AND project_id = ? ORDER BY sent_at DESC LIMIT ?")
      .bind(this.tenantId, projectId, limit)
      .all<{ kind: string; sent_at: string; ok: number; detail: string | null }>();
    return results;
  }
}

const PROJECT_COLUMNS =
  "id, tenant_id, name, service_name, data_sensitivity, api_token_hint, (slack_webhook_enc IS NOT NULL) AS has_slack, created_at, updated_at, stack_updated_at, last_matched_at";

export interface ProjectRow {
  id: string;
  tenant_id: string;
  name: string;
  service_name: string | null;
  data_sensitivity: DataSensitivity;
  api_token_hint: string | null;
  has_slack: number;
  created_at: string;
  updated_at: string;
  stack_updated_at: string | null;
  last_matched_at: string | null;
}

export interface ComponentRow {
  name: string;
  exposure: Exposure;
  exposure_reason: string | null;
  managed: number;
}

export interface ProjectPackageInput {
  component: string;
  /** package = OSVで照合 / watch = MWウォッチリスト（NVDのCPE） */
  kind: "package" | "watch";
  ecosystem: string;
  name: string;
  /** null は unknown */
  version: string | null;
  purl: string;
  isDev: boolean;
  source: "sbom" | "image" | "middleware" | "cdn";
  evidence?: string | null;
}

export interface ProjectPackageRow {
  component: string;
  kind: "package" | "watch";
  ecosystem: string;
  name: string;
  version: string | null;
  purl: string;
  is_dev: number;
  source: string;
  evidence: string | null;
}

export interface AlertMatch {
  id: string;
  vulnId: string;
  component: string;
  packageKey: string;
  packageLabel: string;
  installedVersion: string | null;
  versionUnknown: boolean;
  isDev: boolean;
  generalRank: Rank;
  rank: Rank;
  steps: string[];
  notes: string[];
  fixed: string[];
}

export interface AlertRow {
  id: string;
  tenant_id: string;
  project_id: string;
  vuln_id: string;
  component: string;
  package_key: string;
  package_label: string;
  installed_version: string | null;
  version_unknown: number;
  is_dev: number;
  general_rank: Rank;
  rank: Rank;
  rank_steps: string;
  rank_notes: string;
  fixed: string;
  status: AlertStatus;
  status_updated_at: string | null;
  status_updated_by: string | null;
  first_detected_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  notified_at: string | null;
  digest_sent_at: string | null;
}

export function alertSteps(row: Pick<AlertRow, "rank_steps" | "rank_notes" | "fixed">): { steps: string[]; notes: string[]; fixed: string[] } {
  return {
    steps: parseJson<string[]>(row.rank_steps, []),
    notes: parseJson<string[]>(row.rank_notes, []),
    fixed: parseJson<string[]>(row.fixed, []),
  };
}
