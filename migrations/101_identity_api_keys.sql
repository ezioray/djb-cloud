-- 101 · API Key：在 002 存量表上**只加列**（存量列语义与三列插入路径保持兼容）
-- 归属：M01 identity-tenant（01-ownership §2 api_keys）
-- 存量表冻结（01-ownership §7.1）：id 保持 BIGSERIAL、user_id / key_prefix / key_hash 不改名；
--   本文件只追加 M01 需要的归属列、限额列与约束。
-- 「prefix」在存量表里的列名是 key_prefix（同义列禁止新建，01-ownership §7.4）。
-- 明文永不入库：库中只有 key_hash = sha256(明文) 与 8 位前缀（INV-04）。
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL。
BEGIN;

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS account_id      UUID;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS tenant_id       UUID;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS qps             INTEGER;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS daily_usd_minor BIGINT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS label           TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotated_from    BIGINT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at    TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS created_by      UUID;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_reason  TEXT;

-- 复合外键的目标：同一 Key 只能属于其账户所在租户（租户隔离在库层成立）
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_id_tenant_uq ON api_keys (id, tenant_id);

DO $$
BEGIN
  -- 租户隔离：api_keys.(account_id, tenant_id) 必须与 user_accounts 的同一行一致。
  -- NOT VALID：存量行（002 三列插入，account_id 为空）不回溯校验，但新行一律校验。
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_account_tenant_fk'
                    AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_account_tenant_fk
      FOREIGN KEY (account_id, tenant_id) REFERENCES user_accounts (id, tenant_id)
      ON DELETE RESTRICT NOT VALID;
  END IF;

  -- 轮换链：旧钥 → 新钥（同事务内旧钥 revoked_at=now，重叠窗口 0）
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_rotated_from_fk'
                    AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_rotated_from_fk
      FOREIGN KEY (rotated_from) REFERENCES api_keys (id) ON DELETE RESTRICT NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_qps_chk' AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_qps_chk CHECK (qps IS NULL OR qps > 0) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_daily_usd_chk' AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_daily_usd_chk
      CHECK (daily_usd_minor IS NULL OR daily_usd_minor > 0) NOT VALID;
  END IF;

  -- 只存 sha256 十六进制；明文形态（如 'sk-...'）不可能通过
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_hash_shape_chk' AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_hash_shape_chk
      CHECK (key_hash ~ '^[0-9a-f]{64}$') NOT VALID;
  END IF;

  -- 前缀 8 位（M01 §8.2），仅展示与排障
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_prefix_shape_chk' AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_prefix_shape_chk
      CHECK (key_prefix ~ '^[A-Za-z0-9_-]{8}$') NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'api_keys_revoke_chk' AND conrelid = 'api_keys'::regclass) THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_revoke_chk
      CHECK (revoked_at IS NULL OR revoked_reason IS NOT NULL) NOT VALID;
  END IF;
END
$$;

-- 鉴权热路径：按账户查活的 Key；按租户统计
CREATE INDEX IF NOT EXISTS api_keys_account_live_idx ON api_keys (account_id)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);

-- 跨模块只读视图：M03 鉴权只需前缀 / 归属 / 限额，看不到哈希（00-conventions §7.4）
CREATE OR REPLACE VIEW v_identity_api_keys AS
  SELECT id AS api_key_id, account_id, tenant_id, key_prefix, qps, daily_usd_minor,
         created_at, last_used_at, revoked_at
    FROM api_keys;

COMMIT;
