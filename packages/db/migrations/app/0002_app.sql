-- アプリ用D1（11章）。単一D1＋tenant_id。テナントのデータは必ず tenant_id 付きで読み書きする（12章）

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_members (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'owner',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS tenant_members_user_idx ON tenant_members(user_id);

-- 私の環境（6-4）。アカウントに1つ
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id TEXT PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
  my_environment TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

-- プロジェクト（1つの stack.yaml = 1プロジェクト）
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  service_name TEXT,
  data_sensitivity TEXT NOT NULL DEFAULT 'medium',
  api_token_hash TEXT,
  api_token_hint TEXT,
  slack_webhook_enc TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  stack_updated_at TEXT,
  last_matched_at TEXT
);
CREATE INDEX IF NOT EXISTS projects_tenant_idx ON projects(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS projects_token_idx ON projects(api_token_hash);

CREATE TABLE IF NOT EXISTS project_components (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  exposure TEXT NOT NULL,
  exposure_reason TEXT,
  managed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (project_id, name)
);
CREATE INDEX IF NOT EXISTS project_components_tenant_idx ON project_components(tenant_id, project_id);

-- 照合対象。kind = package（OSVで照合）/ watch（MWウォッチリスト、NVDのCPEで照合）
CREATE TABLE IF NOT EXISTS project_packages (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  component TEXT NOT NULL,
  kind TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT,
  purl TEXT NOT NULL,
  is_dev INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL,
  evidence TEXT,
  PRIMARY KEY (project_id, component, kind, ecosystem, name, purl)
);
CREATE INDEX IF NOT EXISTS project_packages_tenant_idx ON project_packages(tenant_id, project_id);
CREATE INDEX IF NOT EXISTS project_packages_lookup_idx ON project_packages(kind, ecosystem, name, version);

-- アラート（4-2）。status = open（未対応）/ in_progress（対応中）/ not_needed（対応不要）/ done（完了）
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  vuln_id TEXT NOT NULL,
  component TEXT NOT NULL,
  package_key TEXT NOT NULL,
  package_label TEXT NOT NULL,
  installed_version TEXT,
  version_unknown INTEGER NOT NULL DEFAULT 0,
  is_dev INTEGER NOT NULL DEFAULT 0,
  general_rank TEXT NOT NULL,
  rank TEXT NOT NULL,
  rank_steps TEXT NOT NULL DEFAULT '[]',
  rank_notes TEXT NOT NULL DEFAULT '[]',
  fixed TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  status_updated_at TEXT,
  status_updated_by TEXT,
  first_detected_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  -- 照合で該当しなくなった日時（更新して解消した等）
  resolved_at TEXT,
  notified_at TEXT,
  digest_sent_at TEXT,
  UNIQUE (project_id, vuln_id, component, package_key)
);
CREATE INDEX IF NOT EXISTS alerts_tenant_project_idx ON alerts(tenant_id, project_id, status);
CREATE INDEX IF NOT EXISTS alerts_digest_idx ON alerts(digest_sent_at, rank);

CREATE TABLE IF NOT EXISTS stack_uploads (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  uploaded_at TEXT NOT NULL,
  via TEXT NOT NULL,
  r2_prefix TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS stack_uploads_project_idx ON stack_uploads(tenant_id, project_id, uploaded_at);

CREATE TABLE IF NOT EXISTS notification_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  sent_at TEXT NOT NULL,
  ok INTEGER NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS notification_log_project_idx ON notification_log(tenant_id, project_id, sent_at);

-- OSV querybatch の結果キャッシュ（9-1）。全テナントで重複排除した「パッケージ＋バージョン」単位。テナント情報は持たない
CREATE TABLE IF NOT EXISTS package_vuln_cache (
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  vuln_ids TEXT NOT NULL DEFAULT '[]',
  checked_at TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version)
);
