-- 103 · 配额主体 tenant_quotas（M01 §5 / INV-07；CR-2 已统一表名）
-- 生效配额 = min(租户, Key, 节点能力)，并随请求写 policy_version 快照；无快照不得计费（40907）。
-- 本表只存「租户级」与「Key 级」两档上限；节点能力由 M02/M04 在调用侧传入，M01 不读其基表。
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL。
BEGIN;

CREATE TABLE IF NOT EXISTS tenant_quotas (
  id             UUID PRIMARY KEY,
  tenant_id      UUID NOT NULL,
  key_id         BIGINT,
  kind           TEXT NOT NULL,
  value          BIGINT NOT NULL,
  policy_version TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 租户隔离：Key 级配额的 (key_id, tenant_id) 必须与 api_keys 同一行一致
  CONSTRAINT tenant_quotas_key_tenant_fk FOREIGN KEY (key_id, tenant_id)
    REFERENCES api_keys (id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT tenant_quotas_kind_chk CHECK (kind IN ('qps', 'daily_usd_minor', 'concurrency')),
  CONSTRAINT tenant_quotas_value_chk CHECK (value >= 0),
  CONSTRAINT tenant_quotas_policy_chk CHECK (char_length(policy_version) BETWEEN 1 AND 64)
);

-- 一档一条：租户级 (tenant, kind)、Key 级 (key, kind) 各自唯一
CREATE UNIQUE INDEX IF NOT EXISTS tenant_quotas_tenant_uq ON tenant_quotas (tenant_id, kind)
  WHERE key_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_quotas_key_uq ON tenant_quotas (key_id, kind)
  WHERE key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tenant_quotas_tenant_idx ON tenant_quotas (tenant_id);

DROP TRIGGER IF EXISTS tenant_quotas_touch ON tenant_quotas;
CREATE TRIGGER tenant_quotas_touch BEFORE UPDATE ON tenant_quotas
  FOR EACH ROW EXECUTE FUNCTION identity_touch_updated_at();

COMMIT;
