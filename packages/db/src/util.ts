/** D1 の1文あたりのバインド変数の上限は100。余裕をもって分割する */
export const MAX_BINDINGS = 90;

export function nowIso(): string {
  return new Date().toISOString();
}

export function chunk<T>(list: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

export function parseJson<T>(value: unknown, fallback: T): T {
  if (typeof value !== "string" || !value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function placeholders(n: number): string {
  return Array.from({ length: n }, () => "?").join(",");
}

/** D1 の batch は1回の上限があるので分割して実行する */
export async function runBatches(db: D1Database, statements: D1PreparedStatement[], size = 50): Promise<void> {
  for (const part of chunk(statements, size)) {
    if (part.length) await db.batch(part);
  }
}
