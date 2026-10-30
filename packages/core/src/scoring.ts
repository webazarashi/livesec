import defaultConfig from "./scoring.config.json";

/** 緊急度ランク（7-1） */
export type Rank = "S" | "A" | "B" | "C";

export const RANKS: readonly Rank[] = ["S", "A", "B", "C"];

export const RANK_LABELS: Record<Rank, { label: string; meaning: string; notify: string }> = {
  S: { label: "S", meaning: "今すぐ対応", notify: "Slack即時" },
  A: { label: "A", meaning: "24時間以内", notify: "Slack即時" },
  B: { label: "B", meaning: "次の定期保守", notify: "週次まとめ（月曜09:00）" },
  C: { label: "C", meaning: "記録のみ", notify: "週次まとめ（月曜09:00）" },
};

const ORDER: Record<Rank, number> = { C: 0, B: 1, A: 2, S: 3 };
const BY_ORDER: Rank[] = ["C", "B", "A", "S"];

export function rankValue(rank: Rank): number {
  return ORDER[rank];
}

export function compareRank(a: Rank, b: Rank): number {
  return ORDER[a] - ORDER[b];
}

function shift(rank: Rank, delta: number): Rank {
  const v = Math.min(3, Math.max(0, ORDER[rank] + delta));
  return BY_ORDER[v]!;
}

export function isImmediateRank(rank: Rank): boolean {
  return rank === "S" || rank === "A";
}

export interface ScoringConfig {
  S: { pocMinCvss: number; minEpss: number; epssMinCvss: number };
  A: { minCvss: number; signalMinCvss: number; signalMinEpss: number };
  B: { minCvss: number; signalMinCvss: number; signalMinEpss: number };
  ghsaSeverityScore: Record<string, number>;
}

export const DEFAULT_SCORING_CONFIG: ScoringConfig = defaultConfig;

/** シグナル（7-2） */
export interface Signals {
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  poc: boolean;
}

export interface GeneralRankResult {
  rank: Rank;
  /** 判定理由（画面表示用） */
  reasons: string[];
}

function fmt(n: number): string {
  return Number.isInteger(n) ? n.toFixed(1) : String(n);
}

/** 一般緊急度（7-3）。上から順に判定し、最初に当てはまったランク。 */
export function generalRank(signals: Signals, config: ScoringConfig = DEFAULT_SCORING_CONFIG): GeneralRankResult {
  const cvss = signals.cvss ?? 0;
  const epss = signals.epss ?? 0;
  const { S, A, B } = config;

  if (signals.kev) return { rank: "S", reasons: ["CISA KEV 掲載（悪用が確認済み）"] };
  if (signals.poc && cvss >= S.pocMinCvss)
    return { rank: "S", reasons: [`PoCあり かつ CVSS ${fmt(cvss)}（${fmt(S.pocMinCvss)}以上）`] };
  if (epss >= S.minEpss && cvss >= S.epssMinCvss)
    return { rank: "S", reasons: [`EPSS ${epss.toFixed(3)}（${S.minEpss}以上） かつ CVSS ${fmt(cvss)}`] };

  if (cvss >= A.minCvss) return { rank: "A", reasons: [`CVSS ${fmt(cvss)}（${fmt(A.minCvss)}以上）`] };
  if (cvss >= A.signalMinCvss && (signals.poc || epss >= A.signalMinEpss))
    return {
      rank: "A",
      reasons: [`CVSS ${fmt(cvss)} かつ ${signals.poc ? "PoCあり" : `EPSS ${epss.toFixed(3)}`}`],
    };

  if (cvss >= B.minCvss) return { rank: "B", reasons: [`CVSS ${fmt(cvss)}（${fmt(B.minCvss)}以上）`] };
  if (cvss >= B.signalMinCvss && (signals.poc || epss >= B.signalMinEpss))
    return {
      rank: "B",
      reasons: [`CVSS ${fmt(cvss)} かつ ${signals.poc ? "PoCあり" : `EPSS ${epss.toFixed(3)}`}`],
    };

  return {
    rank: "C",
    reasons: [signals.cvss === null ? "CVSS 未算出・悪用の兆候なし" : `CVSS ${fmt(cvss)}・悪用の兆候なし`],
  };
}

/** GHSA の深刻度をCVSSの代用値にする（7-2） */
export function ghsaSeverityToScore(severity: string | null | undefined, config: ScoringConfig = DEFAULT_SCORING_CONFIG): number | null {
  if (!severity) return null;
  return config.ghsaSeverityScore[severity.toUpperCase()] ?? null;
}

export type Exposure = "internet" | "internal" | "offline";
export type DataSensitivity = "high" | "medium" | "low";

export interface IndividualContext {
  /** 該当バージョンを使っているか（false なら通知しない） */
  versionMatched: boolean;
  /** MWウォッチリストでバージョンが unknown */
  versionUnknown: boolean;
  exposure: Exposure;
  dataSensitivity: DataSensitivity;
  /** SBOMで開発用依存と判別できる */
  isDev: boolean;
  managed: boolean;
  kev: boolean;
}

export interface IndividualRankResult {
  /** null は通知しない（該当バージョンを使っていない） */
  rank: Rank | null;
  /** 適用した調整（画面・Slack表示用） */
  steps: string[];
  /** 利用者に促すこと */
  notes: string[];
}

/** 個別緊急度（7-4）。一般緊急度に上から順に適用する。 */
export function individualRank(general: Rank, ctx: IndividualContext): IndividualRankResult {
  const steps: string[] = [];
  const notes: string[] = [];

  // 1
  if (!ctx.versionMatched && !ctx.versionUnknown) {
    return { rank: null, steps: ["該当バージョンを使っていない"], notes };
  }
  if (ctx.versionUnknown) {
    return {
      rank: "B",
      steps: ["バージョンが unknown のため B 固定"],
      notes: ["バージョン確認が必要です"],
    };
  }

  let rank = general;
  const apply = (next: Rank, label: string) => {
    if (next !== rank) steps.push(`${label}：${rank} → ${next}`);
    else steps.push(`${label}：${rank}（変化なし）`);
    rank = next;
  };

  // 2
  if (ctx.exposure === "internal") apply(shift(rank, -1), "exposure: internal で1段階下げ");
  else if (ctx.exposure === "offline") apply(shift(rank, -2), "exposure: offline で2段階下げ");

  // 3
  if (ctx.dataSensitivity === "high" && ctx.exposure === "internet") {
    // 1段階上げ（上限A）。すでにA以上ならそのまま。Sへは上げない
    const raised = ORDER[rank] < ORDER.A ? shift(rank, +1) : rank;
    apply(raised, "data_sensitivity: high かつ internet で1段階上げ（上限A）");
  } else if (ctx.dataSensitivity === "low") {
    apply(shift(rank, -1), "data_sensitivity: low で1段階下げ");
  }

  // 4
  if (ctx.isDev) apply(shift(rank, -1), "開発用依存のため1段階下げ");

  // 5
  if (ctx.managed) {
    apply(ORDER[rank] > ORDER.B ? "B" : rank, "managed: true で上限B");
    notes.push("提供元（マネージドサービス）のパッチ適用状況を確認してください");
  }

  // 6
  if (ctx.kev && !ctx.managed) {
    apply(ORDER[rank] < ORDER.A ? "A" : rank, "KEV掲載 かつ managed: false で下限A");
  }

  return { rank, steps, notes };
}
