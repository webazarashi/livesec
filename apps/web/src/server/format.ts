import { getTopic, parseJson, RANK_LABELS, type Rank } from "./shared";

export { parseJson };

/** 日本時間の日付（2026年10月30日） */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const jst = new Date(d.getTime() + 9 * 3_600_000);
  return `${jst.getUTCFullYear()}年${jst.getUTCMonth() + 1}月${jst.getUTCDate()}日`;
}

/** 2026-10-30 */
export function formatIsoDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Date(d.getTime() + 9 * 3_600_000).toISOString().slice(0, 10);
}

/** 2026/10/30 14:05（JST） */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const j = new Date(d.getTime() + 9 * 3_600_000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${j.getUTCFullYear()}/${p(j.getUTCMonth() + 1)}/${p(j.getUTCDate())} ${p(j.getUTCHours())}:${p(j.getUTCMinutes())}`;
}

export function daysSince(iso: string | null | undefined, now = new Date()): number | null {
  if (!iso) return null;
  return Math.floor((now.getTime() - new Date(iso).getTime()) / 86_400_000);
}

export function topicName(key: string): string {
  return getTopic(key)?.name ?? key;
}

export function topicLabel(key: string): string {
  return getTopic(key)?.label ?? key;
}

export function rankMeaning(rank: string): string {
  return RANK_LABELS[rank as Rank]?.meaning ?? "";
}

export function articleUrl(a: { topic: string; slug: string }): string {
  return `/${a.topic}/${a.slug}/`;
}
