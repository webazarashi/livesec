import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

/**
 * テスト用：node:sqlite の上に D1Database と同じ形の最小限のAPIを載せる。
 * 本番の D1 も SQLite なので、SQL の挙動はほぼ同じになる。
 */
class ShimStatement {
  constructor(
    private readonly db: DatabaseSync,
    readonly sql: string,
    readonly params: unknown[] = [],
  ) {}

  bind(...values: unknown[]): ShimStatement {
    return new ShimStatement(this.db, this.sql, values);
  }

  private args(): SQLInputValue[] {
    return this.params.map((v) => (v === undefined ? null : typeof v === "boolean" ? (v ? 1 : 0) : (v as SQLInputValue)));
  }

  async first<T>(column?: string): Promise<T | null> {
    const row = this.db.prepare(this.sql).get(...this.args()) as Record<string, unknown> | undefined;
    if (!row) return null;
    return (column ? row[column] : { ...row }) as T;
  }

  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    const stmt = this.db.prepare(this.sql);
    const rows = /^\s*(select|with|pragma)|returning/i.test(this.sql) ? stmt.all(...this.args()) : (stmt.run(...this.args()), []);
    return { results: rows.map((r) => ({ ...r }) as T), success: true, meta: {} };
  }

  async run(): Promise<{ success: true; meta: { changes: number; last_row_id: number } }> {
    const r = this.db.prepare(this.sql).run(...this.args());
    return { success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }

  runSync() {
    const stmt = this.db.prepare(this.sql);
    if (/^\s*(select|with)|returning/i.test(this.sql)) {
      return { results: stmt.all(...this.args()).map((r) => ({ ...r })), success: true, meta: { changes: 0 } };
    }
    const r = stmt.run(...this.args());
    return { results: [], success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }
}

export class ShimD1 {
  readonly raw: DatabaseSync;
  constructor(path = ":memory:") {
    this.raw = new DatabaseSync(path);
    this.raw.exec("PRAGMA foreign_keys = ON;");
  }

  prepare(sql: string): ShimStatement {
    return new ShimStatement(this.raw, sql);
  }

  async batch(statements: ShimStatement[]) {
    this.raw.exec("BEGIN");
    try {
      const out = statements.map((s) => s.runSync());
      this.raw.exec("COMMIT");
      return out;
    } catch (e) {
      this.raw.exec("ROLLBACK");
      throw e;
    }
  }

  async exec(sql: string) {
    this.raw.exec(sql);
    return { count: 0, duration: 0 };
  }
}

export function migrate(db: ShimD1, dir: "app" | "catalog"): void {
  const base = new URL(`../migrations/${dir}/`, import.meta.url);
  for (const file of readdirSync(base).filter((f) => f.endsWith(".sql")).sort()) {
    db.raw.exec(readFileSync(new URL(file, base), "utf8"));
  }
}

export function createAppDb(): D1Database {
  const db = new ShimD1();
  migrate(db, "app");
  return db as unknown as D1Database;
}

export function createCatalogDb(): D1Database {
  const db = new ShimD1();
  migrate(db, "catalog");
  return db as unknown as D1Database;
}

export function insertUser(db: D1Database, id: string, email: string): void {
  const raw = (db as unknown as ShimD1).raw;
  raw
    .prepare('INSERT INTO "user" (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, 0, ?, ?)')
    .run(id, email, email, new Date().toISOString(), new Date().toISOString());
}
