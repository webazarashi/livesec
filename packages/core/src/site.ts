/** サイト全体の文言（2章の免責・5章の構成） */
export const SITE = {
  name: "一次対応まとめ",
  tagline: "CVEを、知るから、直すまで。",
  description:
    "npm・PyPI・RubyGems・Packagist・Go・OSパッケージ・ミドルウェアの脆弱性（CVE）を、自社SaaSの開発チーム向けに「自社に関係あるか判定 → 直す → 説明する」までまとめるセキュリティメディアです。",
  editorial: "一次対応まとめ編集部",
  heroCopy: "その脆弱性、うちに関係ある？を、すぐ判断できるように。",
  heroLead:
    "対象範囲のCVEを一次ソースと機械照合し、影響範囲・確認コマンド・対応手順までまとめています。記事の内容をもとに、あなたのAIにワンクリックで相談できます。",
} as const;

export const DISCLAIMERS = {
  /** 全ページのフッター */
  footer:
    "本サイトの情報は公開情報をもとに作成した参考情報です。正確性・完全性・最新性を保証するものではありません。対応の判断は、各製品の公式アドバイザリをご確認のうえ、ご自身の責任で行ってください。",
  /** 記事の冒頭または末尾 */
  article: "本記事は公開時点の情報にもとづく参考情報です。最新の状況は参照元をご確認ください。",
  /** 個別の判定結果（ダッシュボード・Slack） */
  judgement:
    "この判定はバージョン情報の照合にもとづく参考情報です。実際に影響を受けるかは、該当機能の使用状況によって異なります。",
  /** バージョン一致で判定していること（7-6） */
  versionOnly: "バージョン上は該当（使用有無は未確認）",
  /** Ask AI 欄の注意書き（6-7） */
  askAi:
    "記事の要点（見出し・事実データ・本文の抜粋）と質問、ログイン中は「私の環境」が、選んだAIにそのまま渡ります。相談内容は当サイトのサーバには送信しません。Geminiは自動入力に対応していないため、押すとプロンプトをコピーしてGeminiを開きます。APIキー・社内のURL・個人情報は入力しないでください。AIの回答は記事の内容にもとづく参考情報です。",
  /** 私の環境の入力時の注意（6-4） */
  myEnvironment:
    "APIキー・社内URL・ホスト名・IPアドレス・顧客名・個人情報は書かないでください。ここに書いた内容は、Ask AI で選んだAIにそのまま渡ります。",
} as const;

/** データソースのクレジット（12章：出典表示） */
export const DATA_SOURCES = [
  { name: "OSV", url: "https://osv.dev/", license: "CC-BY 4.0（各データベースのライセンスに従う）" },
  { name: "GitHub Advisory Database", url: "https://github.com/advisories", license: "CC-BY 4.0" },
  {
    name: "NVD（National Vulnerability Database）",
    url: "https://nvd.nist.gov/",
    license: "This product uses the NVD API but is not endorsed or certified by the NVD.",
  },
  { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", license: "CC0 1.0" },
  { name: "FIRST EPSS", url: "https://www.first.org/epss/", license: "EPSS の利用規約に従う" },
] as const;

/** アラートの状態（4-2） */
export const ALERT_STATUSES = [
  { key: "open", label: "未対応" },
  { key: "in_progress", label: "対応中" },
  { key: "not_needed", label: "対応不要" },
  { key: "done", label: "完了" },
] as const;

export type AlertStatus = (typeof ALERT_STATUSES)[number]["key"];

export function isAlertStatus(v: string): v is AlertStatus {
  return ALERT_STATUSES.some((s) => s.key === v);
}

export function alertStatusLabel(v: string): string {
  return ALERT_STATUSES.find((s) => s.key === v)?.label ?? v;
}
