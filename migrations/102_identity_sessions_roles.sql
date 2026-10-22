-- 102 · 会话与后台角色绑定（M01 §3 / §5）
-- sessions：登录会话（epoch 与账户 session_epoch 对齐，角色变更即失效；A4）
-- role_bindings：八角色 + scope + approved_by + 90 天到期回收（03-facts §8）
-- 只加不改：全新表，与 001–006 无交集。回滚：见 app/identity/migrate.py 的 DOWN_SQL。
BEGIN;

-- --------------------------------------------------------------------------- sessions
CREATE TABLE IF NOT EXISTS sessions (
  id                 UUID PRIMARY KEY,
  account_id         UUID NOT NULL,
  tenant_id          UUID NOT NULL,
  epoch              INTEGER NOT NULL,
  kind               TEXT NOT NULL DEFAULT 'user',
  mfa                BOOLEAN NOT NULL DEFAULT FALSE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  refresh_expires_at TIMESTAMPTZ,
  revoked_at         TIMESTAMPTZ,
  revoked_reason     TEXT,
  CONSTRAINT sessions_id_tenant_uq UNIQUE (id, tenant_id),
  -- 租户隔离：会话必须与账户同租户（库层拒绝跨租户会话）
  CONSTRAINT sessions_account_tenant_fk FOREIGN KEY (account_id, tenant_id)
    REFERENCES user_accounts (id, tenant_id) ON DELETE RESTRICT,
  CONSTRAINT sessions_kind_chk CHECK (kind IN ('user', 'admin')),
  CONSTRAINT sessions_epoch_chk CHECK (epoch >= 0),
  CONSTRAINT sessions_ttl_chk CHECK (expires_at > created_at),
  CONSTRAINT sessions_refresh_chk CHECK (refresh_expires_at IS NULL OR refresh_expires_at > created_at),
  CONSTRAINT sessions_revoke_chk CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

-- 角色变更后旧会话按 epoch 判定失效（M01 §5 索引要求）
CREATE INDEX IF NOT EXISTS sessions_account_epoch_idx ON sessions (account_id, epoch);
CREATE INDEX IF NOT EXISTS sessions_live_idx ON sessions (account_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at) WHERE revoked_at IS NULL;

-- --------------------------------------------------------------------------- role_bindings
CREATE TABLE IF NOT EXISTS role_bindings (
  id             UUID PRIMARY KEY,
  account_id     UUID NOT NULL,
  tenant_id      UUID NOT NULL,
  admin_role     TEXT NOT NULL,
  scope          TEXT NOT NULL DEFAULT 'platform',
  granted_by     UUID NOT NULL,
  approved_by    UUID NOT NULL,
  granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at     TIMESTAMPTZ NOT NULL,
  revoked_at     TIMESTAMPTZ,
  revoked_reason TEXT,
  CONSTRAINT role_bindings_id_tenant_uq UNIQUE (id, tenant_id),
  CONSTRAINT role_bindings_account_tenant_fk FOREIGN KEY (account_id, tenant_id)
    REFERENCES user_accounts (id, tenant_id) ON DELETE RESTRICT,
  -- 八角色白名单（03-facts §8；03-facts 用 CS，不再用 CS 之外的旧名）
  CONSTRAINT role_bindings_role_chk CHECK (
    admin_role IN ('SUPER', 'OPS', 'RISK', 'FIN', 'CS', 'AUDIT', 'VIEWER', 'SVC')),
  CONSTRAINT role_bindings_scope_chk CHECK (scope IN ('platform', 'tenant')),
  -- 双人复核：批准人不得是授予人
  CONSTRAINT role_bindings_dual_control_chk CHECK (approved_by <> granted_by),
  CONSTRAINT role_bindings_ttl_chk CHECK (expires_at > granted_at),
  CONSTRAINT role_bindings_revoke_chk CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

-- 同一账户同一角色只允许一条**未撤销**绑定（部分唯一；到期回收由 job 写 revoked_at）
CREATE UNIQUE INDEX IF NOT EXISTS role_bindings_live_uq ON role_bindings (account_id, admin_role)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS role_bindings_account_idx ON role_bindings (account_id);
CREATE INDEX IF NOT EXISTS role_bindings_expiry_idx ON role_bindings (expires_at)
  WHERE revoked_at IS NULL;

-- INV-06：SVC（服务账户）不得绑自然人身份 —— 有邮箱 / 手机哈希的账户不能拿 SVC。
CREATE OR REPLACE FUNCTION role_bindings_svc_guard() RETURNS trigger AS $$
DECLARE
  human BOOLEAN;
BEGIN
  IF NEW.admin_role = 'SVC' THEN
    SELECT (u.email_hash IS NOT NULL OR u.phone_hash IS NOT NULL) INTO human
      FROM user_accounts a JOIN users u ON u.id = a.user_id
     WHERE a.id = NEW.account_id;
    IF human THEN
      RAISE EXCEPTION 'INV-06：SVC 不得绑自然人账户（account_id=%）', NEW.account_id
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS role_bindings_svc_guard_trg ON role_bindings;
CREATE TRIGGER role_bindings_svc_guard_trg BEFORE INSERT OR UPDATE ON role_bindings
  FOR EACH ROW EXECUTE FUNCTION role_bindings_svc_guard();

COMMIT;
