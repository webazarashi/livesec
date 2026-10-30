import { chunk, MAX_BINDINGS, nowIso, parseJson, runBatches } from "./util";

/**
 * テナントをまたぐシステム処理（突合ジョブ・APIトークンの解決）専用。
 * テナントのデータそのものは返さず、IDの解決と、重複排除した「パッケージ＋バージョン」だけを扱う。
 * テナントの行を読み書きするときは、ここで得たテナントIDで TenantRepo を作って使う。
 */
export class SystemRepo {
  constructor(private readonly db: D1Database) {}

  async findProjectByTokenHash(hash: string): Promise<{ projectId: string; tenantId: string } | null> {
    const row = await this.db
      .prepare("SELECT id, tenant_id FROM projects WHERE api_token_hash = ?")
      .bind(hash)
      .first<{ id: string; tenant_id: string }>();
    return row ? { projectId: row.id, tenantId: row.tenant_id } : null;
  }

  /** 照合対象のプロジェクト（スタック登録済み） */
  async listProjectRefs(): Promise<Array<{ projectId: string; tenantId: string }>> {
    const { results } = await this.db
      .prepare("SELECT id, tenant_id FROM projects WHERE stack_updated_at IS NOT NULL ORDER BY id")
      .all<{ id: string; tenant_id: string }>();
    return results.map((r) => ({ projectId: r.id, tenantId: r.tenant_id }));
  }

  /** 全テナントの「パッケージ＋バージョン」を重複排除（9-1） */
  async distinctPackages(): Promise<Array<{ ecosystem: string; name: string; version: string }>> {
    const { results } = await this.db
      .prepare("SELECT DISTINCT ecosystem, name, version FROM project_packages WHERE kind = 'package' AND version IS NOT NULL ORDER BY ecosystem, name, version")
      .all<{ ecosystem: string; name: string; version: string }>();
    return results;
  }

  async getCachedVulns(keys: Array<{ ecosystem: string; name: string; version: string }>): Promise<Map<string, { vulnIds: string[]; checkedAt: string }>> {
    const out = new Map<string, { vulnIds: string[]; checkedAt: string }>();
    // 3列の複合キーなので1文あたり30件まで
    for (const part of chunk(keys, Math.floor(MAX_BINDINGS / 3))) {
      const cond = part.map(() => "(ecosystem = ? AND name = ? AND version = ?)").join(" OR ");
      const { results } = await this.db
        .prepare(`SELECT ecosystem, name, version, vuln_ids, checked_at FROM package_vuln_cache WHERE ${cond}`)
        .bind(...part.flatMap((k) => [k.ecosystem, k.name, k.version]))
        .all<{ ecosystem: string; name: string; version: string; vuln_ids: string; checked_at: string }>();
      for (const r of results) out.set(cacheKey(r), { vulnIds: parseJson<string[]>(r.vuln_ids, []), checkedAt: r.checked_at });
    }
    return out;
  }

  async putCachedVulns(entries: Array<{ ecosystem: string; name: string; version: string; vulnIds: string[] }>): Promise<void> {
    const now = nowIso();
    await runBatches(
      this.db,
      entries.map((e) =>
        this.db
          .prepare(
            "INSERT INTO package_vuln_cache (ecosystem, name, version, vuln_ids, checked_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(ecosystem, name, version) DO UPDATE SET vuln_ids = excluded.vuln_ids, checked_at = excluded.checked_at",
          )
          .bind(e.ecosystem, e.name, e.version, JSON.stringify([...new Set(e.vulnIds)].sort()), now),
      ),
    );
  }
}

export function cacheKey(k: { ecosystem: string; name: string; version: string }): string {
  return `${k.ecosystem}\u0000${k.name}\u0000${k.version}`;
}
