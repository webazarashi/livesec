// Better Auth のテーブル定義を SQLite(D1) 用のSQLとして出力する。
// 使い方：node scripts/gen-auth-schema.mjs > ../../packages/db/migrations/app/0001_auth.sql
import { DatabaseSync } from "node:sqlite";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";

const db = new DatabaseSync(":memory:");
const { compileMigrations } = await getMigrations({
  database: db,
  emailAndPassword: { enabled: true },
  rateLimit: { enabled: true, storage: "database" },
  plugins: [twoFactor({ issuer: "一次対応まとめ" })],
});
process.stdout.write(`-- Better Auth（scripts/gen-auth-schema.mjs で生成）\n${await compileMigrations()}\n`);
