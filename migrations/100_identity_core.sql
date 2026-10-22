-- 100 · M01 身份域地基：users / orgs / user_accounts / org_members
-- 归属：M01 identity-tenant（01-ownership §2）；迁移段 1xx（01-ownership §5）
-- 只加不改：001–006 存量表（accounts 科目表 / api_keys 原型）不改名、不重建。
--   · 001 的 accounts 是 M06 科目表，**不是**用户账户；本文件新建 user_accounts（01-ownership §7）。
--   · 不建第二套后台用户表：后台自然人也是 user_accounts + role_bindings（M01 §1「不做」）。
-- 五态口径：pending_verify / normal / frozen / closing / closed（M01 §3、03-facts §8）
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL（DROP 本文件全部对象）。
BEGIN;

-- --------------------------------------------------------------------------- 公用
-- updated_at 由触发器维护，应用不写时间戳（00-conventions §4：时间只用服务端）。
CREATE OR REPLACE FUNCTION identity_touch_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- --------------------------------------------------------------------------- users
-- 登录身份（M01 §5）：只存**不可逆哈希**，明文邮箱 / 手机不入库、不入日志。
CREATE TABLE IF NOT EXISTS users (
  id           UUID PRIMARY KEY,
  email_hash   TEXT,
  phone_hash   TEXT,
  mfa_state    TEXT NOT NULL DEFAULT 'none',
  display_name TEXT,
  locale       TEXT NOT NULL DEFAULT 'zh-CN',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT users_mfa_state_chk CHECK (mfa_state IN ('none', 'pending', 'enabled')),
  -- 哈希形态硬约束：明文邮箱（含 '@'）与 11 位手机号都不可能通过
  CONSTRAINT users_email_hash_chk CHECK (email_hash IS NULL OR email_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT users_phone_hash_chk CHECK (phone_hash IS NULL OR phone_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT users_display_name_chk CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 64),
  CONSTRAINT users_locale_chk CHECK (locale ~ '^[a-z]{2}(-[A-Z]{2})?$')
);

-- 同一邮箱 / 手机只能有一个登录身份（空值不参与唯一）
CREATE UNIQUE INDEX IF NOT EXISTS users_email_hash_uq ON users (email_hash) WHERE email_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_hash_uq ON users (phone_hash) WHERE phone_hash IS NOT NULL;

DROP TRIGGER IF EXISTS users_touch ON users;
CREATE TRIGGER users_touch BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION identity_touch_updated_at();

-- --------------------------------------------------------------------------- orgs
-- 组织 = team / enterprise 的租户本体（personal 无 org，租户即账户本身）。
CREATE TABLE IF NOT EXISTS orgs (
  id               UUID PRIMARY KEY,
  tenant_id        UUID NOT NULL,
  type             TEXT NOT NULL,
  name             TEXT NOT NULL,
  seats            INTEGER NOT NULL DEFAULT 1,
  seats_limit      INTEGER NOT NULL,
  owner_account_id UUID,
  state            TEXT NOT NULL DEFAULT 'active',
  -- INV-05：owner 转让 24 h 冷却
  owner_transfer_cooldown_until TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT orgs_type_chk CHECK (type IN ('team', 'enterprise')),
  CONSTRAINT orgs_state_chk CHECK (state IN ('active', 'closing', 'closed')),
  -- INV-01：org 与 tenant 1:1（team/enterprise 的 tenant_id 就是 org id）
  CONSTRAINT orgs_tenant_is_id_chk CHECK (tenant_id = id),
  -- 席位上限（M01 §1：team 20 / enterprise 200）
  CONSTRAINT orgs_seats_chk CHECK (
    seats >= 0
    AND ((type = 'team' AND seats_limit BETWEEN 1 AND 20)
      OR (type = 'enterprise' AND seats_limit BETWEEN 1 AND 200))
    AND seats <= seats_limit),
  CONSTRAINT orgs_name_chk CHECK (char_length(name) BETWEEN 1 AND 120)
);

CREATE UNIQUE INDEX IF NOT EXISTS orgs_tenant_uq ON orgs (tenant_id);

DROP TRIGGER IF EXISTS orgs_touch ON orgs;
CREATE TRIGGER orgs_touch BEFORE UPDATE ON orgs
  FOR EACH ROW EXECUTE FUNCTION identity_touch_updated_at();

-- --------------------------------------------------------------------------- user_accounts
-- 账户（M01 §3 的 Account）：一个 Account 恰属一个 tenant（INV-01），状态机唯一口径。
-- 余额不在本表：唯一余额源是 M06 account_balances（CR-L3）；M01 不持有余额缓存列。
CREATE TABLE IF NOT EXISTS user_accounts (
  id                       UUID PRIMARY KEY,
  user_id                  UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  type                     TEXT NOT NULL,
  state                    TEXT NOT NULL,
  tenant_id                UUID NOT NULL,
  org_id                   UUID REFERENCES orgs (id) ON DELETE RESTRICT,
  session_epoch            INTEGER NOT NULL DEFAULT 0,
  frozen_until             TIMESTAMPTZ,
  frozen_reason            TEXT,
  frozen_by                UUID,
  frozen_approval          JSONB,
  closing_deadline         TIMESTAMPTZ,
  closed_at                TIMESTAMPTZ,
  pii_purged_at            TIMESTAMPTZ,
  ledger_unlink_requested_at TIMESTAMPTZ,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT user_accounts_type_chk CHECK (type IN ('personal', 'team', 'enterprise')),
  CONSTRAINT user_accounts_state_chk CHECK (
    state IN ('pending_verify', 'normal', 'frozen', 'closing', 'closed')),
  -- INV-01：每 Account 恰属一个 tenant；personal 1:1（tenant_id = id），
  -- team/enterprise 的账户共享 org 租户（一个 org 有 N 个成员账户，故 tenant_id 不唯一）。
  -- (id, tenant_id) 唯一是给 api_keys / sessions / role_bindings / org_members 的复合外键做目标。
  CONSTRAINT user_accounts_id_tenant_uq UNIQUE (id, tenant_id),
  CONSTRAINT user_accounts_tenant_src_chk CHECK (
    (type = 'personal' AND org_id IS NULL AND tenant_id = id)
    OR (type IN ('team', 'enterprise') AND org_id IS NOT NULL AND tenant_id = org_id)),
  -- INV-01：frozen ⇒ frozen_until 非空；非 frozen 一律清空冻结留痕（历史进 outbox）
  CONSTRAINT user_accounts_frozen_chk CHECK (
    (state = 'frozen' AND frozen_until IS NOT NULL AND frozen_reason IS NOT NULL
      AND frozen_by IS NOT NULL AND frozen_approval IS NOT NULL)
    OR (state <> 'frozen' AND frozen_until IS NULL AND frozen_reason IS NULL
      AND frozen_by IS NULL AND frozen_approval IS NULL)),
  -- 注销三步：closing 必有冷静期截止；closed 必有 closed_at；其余态两者皆空
  CONSTRAINT user_accounts_closing_chk CHECK (
    (state = 'closing' AND closing_deadline IS NOT NULL AND closed_at IS NULL)
    OR (state = 'closed' AND closed_at IS NOT NULL)
    OR (state IN ('pending_verify', 'normal', 'frozen')
        AND closing_deadline IS NULL AND closed_at IS NULL)),
  CONSTRAINT user_accounts_session_epoch_chk CHECK (session_epoch >= 0),
  CONSTRAINT user_accounts_purge_chk CHECK (pii_purged_at IS NULL OR state = 'closed')
);

-- 到期解冻 / 冷静期到期 / 待验证清理三个 job 的扫描索引
CREATE INDEX IF NOT EXISTS user_accounts_state_idx ON user_accounts (state, frozen_until);
CREATE INDEX IF NOT EXISTS user_accounts_closing_idx ON user_accounts (closing_deadline)
  WHERE state = 'closing';
CREATE INDEX IF NOT EXISTS user_accounts_user_idx ON user_accounts (user_id);

DROP TRIGGER IF EXISTS user_accounts_touch ON user_accounts;
CREATE TRIGGER user_accounts_touch BEFORE UPDATE ON user_accounts
  FOR EACH ROW EXECUTE FUNCTION identity_touch_updated_at();

-- 组织 → owner 账户（循环引用：org 先建、账户后建，故 owner 允许先空，FK 后置）
DO $$
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_constraint
       WHERE conname = 'orgs_owner_account_fk' AND conrelid = 'orgs'::regclass) THEN
    ALTER TABLE orgs ADD CONSTRAINT orgs_owner_account_fk
      FOREIGN KEY (owner_account_id) REFERENCES user_accounts (id) ON DELETE RESTRICT;
  END IF;
END
$$;

-- --------------------------------------------------------------------------- org_members
-- 成员生命周期：invited → active → removed（M01 §3）；邀请令牌一次性 ≤72h，只存哈希。
CREATE TABLE IF NOT EXISTS org_members (
  id                UUID PRIMARY KEY,
  org_id            UUID NOT NULL REFERENCES orgs (id) ON DELETE RESTRICT,
  tenant_id         UUID NOT NULL,
  account_id        UUID NOT NULL,
  org_role          TEXT NOT NULL,
  state             TEXT NOT NULL DEFAULT 'invited',
  invited_by        UUID,
  invite_hash       TEXT,
  invite_expires_at TIMESTAMPTZ,
  joined_at         TIMESTAMPTZ,
  removed_at        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT org_members_role_chk CHECK (org_role IN ('owner', 'admin', 'operator', 'billing')),
  CONSTRAINT org_members_state_chk CHECK (state IN ('invited', 'active', 'removed')),
  CONSTRAINT org_members_tenant_chk CHECK (tenant_id = org_id),
  CONSTRAINT org_members_id_tenant_uq UNIQUE (id, tenant_id),
  -- 一个账户在一个组织里只有一条成员关系
  CONSTRAINT org_members_account_uq UNIQUE (tenant_id, account_id),
  -- 租户隔离：成员账户必须属于该组织租户（库层复合外键，不靠调用方自觉）
  CONSTRAINT org_members_account_fk FOREIGN KEY (account_id, tenant_id)
    REFERENCES user_accounts (id, tenant_id) ON DELETE RESTRICT,
  CONSTRAINT org_members_invite_hash_chk CHECK (invite_hash IS NULL OR invite_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT org_members_invite_chk CHECK (
    (state = 'invited' AND invite_hash IS NOT NULL AND invite_expires_at IS NOT NULL)
    OR (state <> 'invited' AND invite_hash IS NULL AND invite_expires_at IS NULL)),
  -- invited → active → removed；撤销未接受的邀请时 joined_at 仍为空
  CONSTRAINT org_members_joined_chk CHECK (
    (state = 'invited' AND joined_at IS NULL AND removed_at IS NULL)
    OR (state = 'active' AND joined_at IS NOT NULL AND removed_at IS NULL)
    OR (state = 'removed' AND removed_at IS NOT NULL))
);

-- INV-05：每 org 恰一个 owner（未移除的 owner 唯一）
CREATE UNIQUE INDEX IF NOT EXISTS org_members_owner_uq ON org_members (org_id)
  WHERE org_role = 'owner' AND state <> 'removed';
CREATE INDEX IF NOT EXISTS org_members_org_idx ON org_members (org_id, state);
CREATE INDEX IF NOT EXISTS org_members_account_idx ON org_members (account_id);

DROP TRIGGER IF EXISTS org_members_touch ON org_members;
CREATE TRIGGER org_members_touch BEFORE UPDATE ON org_members
  FOR EACH ROW EXECUTE FUNCTION identity_touch_updated_at();

-- --------------------------------------------------------------------------- 跨模块只读视图
-- 00-conventions §7.4：别的模块只能读 v_<module>_<object>，不得 join 本模块基表。
-- 视图**不含**哈希与任何 PII。
CREATE OR REPLACE VIEW v_identity_accounts AS
  SELECT id AS account_id, type, state, tenant_id, org_id, session_epoch,
         frozen_until, closing_deadline, closed_at, created_at, updated_at
    FROM user_accounts;

COMMIT;
