import { MY_ENVIRONMENT_MAX_CHARS } from "@ichiji/core";
import { nowIso } from "./util";

/** ユーザー単位のデータ（テナントの解決と「私の環境」） */
export class AccountRepo {
  constructor(private readonly db: D1Database) {}

  /** ユーザーの所属テナント。なければ作る（会員登録直後） */
  async ensureTenant(userId: string, name: string, newId: () => string): Promise<string> {
    const existing = await this.getTenantId(userId);
    if (existing) return existing;
    const id = newId();
    const now = nowIso();
    await this.db.batch([
      this.db.prepare("INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)").bind(id, name.slice(0, 200), now),
      this.db.prepare("INSERT INTO tenant_members (tenant_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)").bind(id, userId, now),
    ]);
    return id;
  }

  async getTenantId(userId: string): Promise<string | null> {
    const row = await this.db
      .prepare("SELECT tenant_id FROM tenant_members WHERE user_id = ? ORDER BY created_at LIMIT 1")
      .bind(userId)
      .first<{ tenant_id: string }>();
    return row?.tenant_id ?? null;
  }

  async getMyEnvironment(userId: string): Promise<{ text: string; updatedAt: string | null }> {
    const row = await this.db
      .prepare("SELECT my_environment, updated_at FROM user_profiles WHERE user_id = ?")
      .bind(userId)
      .first<{ my_environment: string; updated_at: string }>();
    return { text: row?.my_environment ?? "", updatedAt: row?.updated_at ?? null };
  }

  async setMyEnvironment(userId: string, text: string): Promise<void> {
    const value = [...text].slice(0, MY_ENVIRONMENT_MAX_CHARS).join("");
    await this.db
      .prepare(
        "INSERT INTO user_profiles (user_id, my_environment, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET my_environment = excluded.my_environment, updated_at = excluded.updated_at",
      )
      .bind(userId, value, nowIso())
      .run();
  }
}
