-- CVEカタログ用D1（11章）。公開情報のみ。テナントのデータは置かない

-- 脆弱性。id は正規ID（CVE番号があればCVE、なければOSVのID）
CREATE TABLE IF NOT EXISTS vulns (
  id TEXT PRIMARY KEY,
  is_cve INTEGER NOT NULL DEFAULT 0,
  aliases TEXT NOT NULL DEFAULT '[]',
  -- メディアの対象範囲（3章）かつ掲載期間内なら1
  in_scope INTEGER NOT NULL DEFAULT 0,
  topic TEXT,
  summary TEXT,
  published_at TEXT,
  modified_at TEXT,
  cvss_score REAL,
  cvss_version TEXT,
  cvss_source TEXT,
  cvss_vector TEXT,
  ghsa_severity TEXT,
  epss REAL,
  epss_percentile REAL,
  epss_updated_at TEXT,
  kev INTEGER NOT NULL DEFAULT 0,
  kev_added_at TEXT,
  poc INTEGER NOT NULL DEFAULT 0,
  general_rank TEXT NOT NULL DEFAULT 'C',
  rank_reasons TEXT NOT NULL DEFAULT '[]',
  facts_hash TEXT,
  withdrawn INTEGER NOT NULL DEFAULT 0,
  nvd_checked_at TEXT,
  first_seen_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vulns_scope_idx ON vulns(in_scope, is_cve, general_rank, published_at);
CREATE INDEX IF NOT EXISTS vulns_topic_idx ON vulns(topic, in_scope);
CREATE INDEX IF NOT EXISTS vulns_nvd_idx ON vulns(is_cve, nvd_checked_at);

-- 影響パッケージ（OSV由来）。source は元のOSVのID。OSVの1件を取り込み直すときは source 単位で入れ替える
CREATE TABLE IF NOT EXISTS vuln_packages (
  vuln_id TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  purl TEXT NOT NULL,
  affected TEXT NOT NULL,
  fixed TEXT NOT NULL DEFAULT '[]',
  topic TEXT,
  source TEXT NOT NULL,
  PRIMARY KEY (vuln_id, ecosystem, name, source)
);
CREATE INDEX IF NOT EXISTS vuln_packages_pkg_idx ON vuln_packages(ecosystem, name);
CREATE INDEX IF NOT EXISTS vuln_packages_source_idx ON vuln_packages(source);

-- ウォッチリスト製品の脆弱なCPE範囲（NVD由来、9-2）
CREATE TABLE IF NOT EXISTS vuln_cpes (
  vuln_id TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  product_key TEXT NOT NULL,
  criteria TEXT NOT NULL,
  version_exact TEXT,
  start_incl TEXT,
  start_excl TEXT,
  end_incl TEXT,
  end_excl TEXT
);
CREATE INDEX IF NOT EXISTS vuln_cpes_product_idx ON vuln_cpes(product_key);
CREATE INDEX IF NOT EXISTS vuln_cpes_vuln_idx ON vuln_cpes(vuln_id);

CREATE TABLE IF NOT EXISTS vuln_references (
  vuln_id TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (vuln_id, url)
);

-- OSVのID → 正規ID
CREATE TABLE IF NOT EXISTS osv_records (
  osv_id TEXT PRIMARY KEY,
  vuln_id TEXT NOT NULL,
  modified TEXT NOT NULL,
  r2_key TEXT
);
CREATE INDEX IF NOT EXISTS osv_records_vuln_idx ON osv_records(vuln_id);

-- 取り込みの進み具合（ソースごと）
CREATE TABLE IF NOT EXISTS ingest_state (
  source TEXT PRIMARY KEY,
  cursor TEXT,
  updated_at TEXT NOT NULL,
  detail TEXT
);

-- 記事（5-3・10章）
CREATE TABLE IF NOT EXISTS articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  topic TEXT NOT NULL,
  title TEXT NOT NULL,
  why_read TEXT NOT NULL,
  points TEXT NOT NULL DEFAULT '[]',
  gains TEXT NOT NULL DEFAULT '[]',
  faq TEXT NOT NULL DEFAULT '[]',
  sources TEXT NOT NULL DEFAULT '[]',
  tags TEXT NOT NULL DEFAULT '[]',
  body_md TEXT NOT NULL,
  body_html TEXT NOT NULL,
  check_html TEXT,
  summary_html TEXT,
  toc TEXT NOT NULL DEFAULT '[]',
  excerpt TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  reading_minutes INTEGER NOT NULL DEFAULT 1,
  cve_ids TEXT NOT NULL,
  primary_cve TEXT NOT NULL,
  -- 一覧表示用に公開時の一般緊急度を持つ（カタログ更新時に同期する）
  general_rank TEXT NOT NULL DEFAULT 'C',
  facts_hash TEXT NOT NULL,
  -- ソース側が更新されたら1（10-1 の5）
  needs_update INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0,
  pinned_at TEXT,
  published_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS articles_topic_idx ON articles(topic, published_at);
CREATE INDEX IF NOT EXISTS articles_rank_idx ON articles(general_rank, published_at);
CREATE INDEX IF NOT EXISTS articles_published_idx ON articles(published_at);

CREATE TABLE IF NOT EXISTS article_cves (
  article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  PRIMARY KEY (article_id, cve_id)
);
CREATE INDEX IF NOT EXISTS article_cves_cve_idx ON article_cves(cve_id);

CREATE TABLE IF NOT EXISTS article_tags (
  article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY (article_id, tag)
);
CREATE INDEX IF NOT EXISTS article_tags_tag_idx ON article_tags(tag);

-- 訂正履歴（5-3 の21・10-2）
CREATE TABLE IF NOT EXISTS article_revisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  revised_at TEXT NOT NULL,
  kind TEXT NOT NULL,
  note TEXT NOT NULL,
  previous_body_md TEXT
);
CREATE INDEX IF NOT EXISTS article_revisions_article_idx ON article_revisions(article_id, revised_at);

-- 機械照合ゲートで差し戻した下書き（10-1 の4）
CREATE TABLE IF NOT EXISTS article_drafts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT,
  cve_ids TEXT NOT NULL DEFAULT '[]',
  raw TEXT NOT NULL,
  errors TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

-- 人気ランキング（Analytics Engine から定期的に確定）
CREATE TABLE IF NOT EXISTS article_rankings (
  period TEXT NOT NULL,
  article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  views INTEGER NOT NULL,
  position INTEGER NOT NULL,
  computed_at TEXT NOT NULL,
  PRIMARY KEY (period, article_id)
);

CREATE TABLE IF NOT EXISTS site_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
