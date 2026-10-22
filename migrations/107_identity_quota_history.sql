-- 107 · M01 T4：租户配额版本历史（只追加）
-- 背景：spec 1.2.1 `TenantQuotasAck.policy_version` 要求「配额变更生成新版本，随请求写入，
--       不覆盖历史」。现值仍在 tenant_quotas（唯一键 (tenant,kind)），历史落本表。
-- 原则：只加表、只追加（00-conventions §7.5：账本 / 审计 / 事件表只追加）。
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL（107 段）。
BEGIN;

CREATE TABLE IF NOT EXISTS tenant_quota_history (
  id              UUID PRIMARY KEY,
  tenant_id       UUID NOT NULL,
  key_id          BIGINT,
  kind            TEXT NOT NULL,
  value           BIGINT NOT NULL,
  previous_value  BIGINT,
  policy_version  TEXT NOT NULL,
  actor_id        UUID,
  reason          TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT tenant_quota_history_kind_chk CHECK (kind IN ('qps', 'daily_usd_minor', 'concurrency')),
  CONSTRAINT tenant_quota_history_value_chk CHECK (value >= 0),
  CONSTRAINT tenant_quota_history_prev_chk CHECK (previous_value IS NULL OR previous_value >= 0),
  CONSTRAINT tenant_quota_history_version_chk CHECK (char_length(policy_version) BETWEEN 1 AND 64),
  CONSTRAINT tenant_quota_history_key_fk FOREIGN KEY (key_id) REFERENCES api_keys (id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS tenant_quota_history_tenant_idx
  ON tenant_quota_history (tenant_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS tenant_quota_history_version_idx
  ON tenant_quota_history (policy_version);

-- 只追加：UPDATE / DELETE 一律报错（不是靠自觉）
CREATE OR REPLACE FUNCTION identity_forbid_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % not allowed', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tenant_quota_history_no_mutation ON tenant_quota_history;
CREATE TRIGGER tenant_quota_history_no_mutation
  BEFORE UPDATE OR DELETE ON tenant_quota_history
  FOR EACH ROW EXECUTE FUNCTION identity_forbid_mutation();

COMMIT;
