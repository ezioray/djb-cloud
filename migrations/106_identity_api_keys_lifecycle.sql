-- 106 · M01 T3：API Key 生命周期所需的两列（只加不改）
-- 归属：M01 identity-tenant（01-ownership §2 api_keys）
-- 背景：spec 1.2.1 的 ApiKeyCreateRequest / ApiKeySummary 需要 scopes 与 expires_at；
--       `name` 复用已有 label、`prefix` 复用已有 key_prefix（禁止同义列，01-ownership §7.4）。
-- 注意：**不**加 CR-3 的 NOT NULL（app/api.py 旧写入未迁，T4 前由 Lead 统一切换；见证据 CR-3 方案）。
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL（106 段）。
BEGIN;

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes     JSONB;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_scopes_chk' AND connamespace = current_schema()::regnamespace AND conrelid = 'api_keys'::regclass) THEN
    -- scopes 只接受字符串数组；NULL = 未声明（等价于全量 scopes，由网关按账户权限裁决）
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_scopes_chk
      CHECK (scopes IS NULL OR jsonb_typeof(scopes) = 'array') NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_expires_chk' AND connamespace = current_schema()::regnamespace AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_expires_chk
      CHECK (expires_at IS NULL OR expires_at > created_at) NOT VALID;
  END IF;
END
$$;

-- 过期 / 计划失效的扫描索引（网关鉴权与回收 job 都按时间判断）
CREATE INDEX IF NOT EXISTS api_keys_expiry_idx ON api_keys (expires_at)
  WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS api_keys_revoked_after_idx ON api_keys (revoked_at)
  WHERE revoked_at IS NOT NULL;

COMMIT;
