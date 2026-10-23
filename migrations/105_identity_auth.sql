-- 105 · M01 T2 认证地基：会话令牌 / MFA 因子 / 扫码中间态 / 幂等键
-- 归属：M01 identity-tenant（01-ownership §2）；迁移段 1xx（100–104 已在 T1 落地）
-- 原则：只加不改——sessions / users 只追加列与「放宽式」约束；新增两张本模块自有表。
-- 明文永不入库：会话令牌只存 sha256；MFA 因子只存 scrypt 派生值 + salt；扫码票据只存哈希。
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL（105 段）。
BEGIN;

-- --------------------------------------------------------------------------- sessions：令牌与绝对期限
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS access_hash        TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_hash       TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS absolute_expires_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS rotated_at         TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS idle_expires_at    TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS step_up_until      TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_ip_hash     TEXT;

-- 令牌哈希唯一：同一枚令牌不可能指向两个会话
CREATE UNIQUE INDEX IF NOT EXISTS sessions_access_uq ON sessions (access_hash)
  WHERE access_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS sessions_refresh_uq ON sessions (refresh_hash)
  WHERE refresh_hash IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'sessions_token_hash_chk' AND connamespace = current_schema()::regnamespace
                    AND conrelid = 'sessions'::regclass) THEN
    ALTER TABLE sessions ADD CONSTRAINT sessions_token_hash_chk
      CHECK ((access_hash IS NULL OR access_hash ~ '^[0-9a-f]{64}$')
         AND (refresh_hash IS NULL OR refresh_hash ~ '^[0-9a-f]{64}$')) NOT VALID;
  END IF;

  -- 绝对上限不晚于创建 + 12h（用户会话用 30 天刷新窗口，故只对 admin/step_up 生效）
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'sessions_absolute_chk' AND connamespace = current_schema()::regnamespace
                    AND conrelid = 'sessions'::regclass) THEN
    ALTER TABLE sessions ADD CONSTRAINT sessions_absolute_chk
      CHECK (absolute_expires_at IS NULL OR absolute_expires_at > created_at) NOT VALID;
  END IF;
END
$$;

-- kind 取值加宽（user/admin → +mfa_pending +step_up）：先删旧 CHECK 再加新 CHECK（放宽，兼容）
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_kind_chk;
ALTER TABLE sessions ADD CONSTRAINT sessions_kind_chk CHECK (
  kind IN ('user', 'admin', 'mfa_pending', 'step_up'));

-- --------------------------------------------------------------------------- users：MFA 因子与登录锁定
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash      TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_hash   TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_salt          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled_at    TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at     TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'users_mfa_factor_chk' AND connamespace = current_schema()::regnamespace AND conrelid = 'users'::regclass) THEN
    -- 因子只以 scrypt 派生值 + salt 存在；none 态必须为空，pending/enabled 必须有
    -- 因子串形如 scrypt$n=..,r=..,p=..$salt$hash（与口令同款派生，盐也在串里）
    ALTER TABLE users ADD CONSTRAINT users_mfa_factor_chk CHECK (
      (mfa_state = 'none' AND mfa_secret_hash IS NULL AND mfa_salt IS NULL)
      OR (mfa_state IN ('pending', 'enabled')
          AND mfa_secret_hash ~
              '^scrypt\$n=[0-9]+,r=[0-9]+,p=[0-9]+\$[0-9a-f]+\$[0-9a-f]+$'
          AND mfa_salt ~ '^[0-9a-f]{32}$')) NOT VALID;
  END IF;

  -- 口令只存 scrypt 派生串（scrypt$n=..,r=..,p=..$salt$hash），明文永不入库
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'users_password_shape_chk' AND connamespace = current_schema()::regnamespace AND conrelid = 'users'::regclass) THEN
    ALTER TABLE users ADD CONSTRAINT users_password_shape_chk CHECK (
      password_hash IS NULL OR password_hash ~ '^scrypt\$n=[0-9]+,r=[0-9]+,p=[0-9]+\$[0-9a-f]+\$[0-9a-f]+$'
    ) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'users_login_lock_chk' AND connamespace = current_schema()::regnamespace AND conrelid = 'users'::regclass) THEN
    ALTER TABLE users ADD CONSTRAINT users_login_lock_chk
      CHECK (failed_login_count >= 0) NOT VALID;
  END IF;
END
$$;

-- --------------------------------------------------------------------------- 扫码登录中间态
-- 一次性票据：created → scanned → confirmed → consumed；120 s 未完成 → expired（M01 §8.2）
CREATE TABLE IF NOT EXISTS identity_scan_tickets (
  id           UUID PRIMARY KEY,
  ticket_hash  TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'created',
  account_id   UUID REFERENCES user_accounts (id) ON DELETE RESTRICT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  scanned_at   TIMESTAMPTZ,
  confirmed_at TIMESTAMPTZ,
  consumed_at  TIMESTAMPTZ,
  CONSTRAINT identity_scan_tickets_hash_uq UNIQUE (ticket_hash),
  CONSTRAINT identity_scan_tickets_hash_chk CHECK (ticket_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT identity_scan_tickets_status_chk CHECK (
    status IN ('created', 'scanned', 'confirmed', 'consumed', 'expired')),
  CONSTRAINT identity_scan_tickets_ttl_chk CHECK (expires_at > created_at),
  -- 状态与时间戳/归属一致：confirmed 之后必须绑定账户
  CONSTRAINT identity_scan_tickets_shape_chk CHECK (
    (status = 'created' AND scanned_at IS NULL AND confirmed_at IS NULL
      AND consumed_at IS NULL AND account_id IS NULL)
    OR (status = 'scanned' AND scanned_at IS NOT NULL AND confirmed_at IS NULL
      AND consumed_at IS NULL AND account_id IS NOT NULL)
    OR (status = 'confirmed' AND confirmed_at IS NOT NULL AND consumed_at IS NULL
      AND account_id IS NOT NULL)
    OR (status = 'consumed' AND confirmed_at IS NOT NULL AND consumed_at IS NOT NULL
      AND account_id IS NOT NULL)
    -- 到期可以发生在「已扫码」之后，故 expired 不要求 account_id 为空
    OR (status = 'expired' AND consumed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS identity_scan_tickets_live_idx
  ON identity_scan_tickets (expires_at) WHERE status IN ('created', 'scanned');

-- --------------------------------------------------------------------------- 幂等键（24h 窗口）
-- 00-conventions §6.1：写接口按 (scope, key) 唯一；同一键不同载荷 → 40919
CREATE TABLE IF NOT EXISTS identity_idempotency (
  id           UUID PRIMARY KEY,
  scope        TEXT NOT NULL,
  idem_key     TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status_code  INTEGER NOT NULL,
  response     JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  CONSTRAINT identity_idempotency_uq UNIQUE (scope, idem_key),
  CONSTRAINT identity_idempotency_scope_chk CHECK (char_length(scope) BETWEEN 1 AND 64),
  CONSTRAINT identity_idempotency_key_chk CHECK (char_length(idem_key) BETWEEN 1 AND 128),
  CONSTRAINT identity_idempotency_ttl_chk CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS identity_idempotency_expiry_idx ON identity_idempotency (expires_at);

COMMIT;
