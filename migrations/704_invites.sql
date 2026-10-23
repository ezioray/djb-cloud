-- 704 · M07 单层邀请（invites）
-- 规格：product/v4/modules/M07-reputation-cop.md §3（Invite 实体 / 状态机 sent→bound / sent→expired / bound→revoked）
--       §3 不变量 **INV-03**（只有一层：inviter 自身不得有 inviter，库内不存在二级链路）
--       **INV-04**（(inviter_id, invitee_id) 唯一且两者不同；同设备簇 / 同支付方式簇拒绝）
--       §5（invites，迁移 704，保留 ≥5 年）· §6.2（绑定与奖励计提）
--       00-conventions §7.2（只加列 / 表 / 索引）
--
-- 原则：
--   1) **单层**（INV-03）：由触发器强制「绑定后不得形成二级链路」——
--      · 邀请人自己不得是任何一条已绑定邀请的被邀请人；
--      · 被邀请人不得已经是一个邀请人（否则 binding 会把它变成中间层）。
--   2) **唯一**（INV-04）：(inviter_id, invitee_id) 部分唯一（invitee 为空表示尚未绑定，可多张）；
--      另加「一个被邀请人只能绑定一次」的部分唯一索引，避免同一人同时被多人绑定。
--   3) **码唯一且一次性**：UNIQUE(code)；绑定后不可复用（状态机 + 唯一索引共同保证）。
--   4) **状态机**：只允许 sent→bound / sent→expired / bound→revoked；
--      code / inviter_id / invitee_id 一经写入不可改；bound_at 与 status 一致。
--   5) 反自邀、反同设备 / 同支付方式簇（§6.2）在领域层判定（需要 points_account 的风控簇字段，
--      库内不做跨表校验，避免把 M07 的判定逻辑散到 DDL 里）。
BEGIN;

CREATE TABLE IF NOT EXISTS invites (
  id          UUID PRIMARY KEY,                     -- UUIDv7
  inviter_id  TEXT NOT NULL,                        -- 邀请人账户
  invitee_id  TEXT,                                 -- 被邀请人（尚未绑定为 NULL）
  code        TEXT NOT NULL,                        -- 邀请码（一次性；绑定后不可复用）
  status      TEXT NOT NULL DEFAULT 'sent',         -- sent / bound / expired / revoked
  bound_at    TIMESTAMPTZ,                          -- 绑定时刻（status='bound' 时必填）
  expire_at   TIMESTAMPTZ,                          -- 过期时刻（到期结转 job 置 expired）
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),   -- 创建时刻（保留期按它）
  issued_by   TEXT NOT NULL DEFAULT 'system:m07'    -- 发放人（self / admin:xxx / system:m07）
);

ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_status_ck;
ALTER TABLE invites ADD CONSTRAINT invites_status_ck
  CHECK (status IN ('sent', 'bound', 'expired', 'revoked')) NOT VALID;

-- INV-04：两者不同
ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_no_self_ck;
ALTER TABLE invites ADD CONSTRAINT invites_no_self_ck
  CHECK (invitee_id IS NULL OR invitee_id <> inviter_id) NOT VALID;

-- 状态与时间一致：bound ⇒ bound_at 必填；有 bound_at ⇒ 只能是 bound 或 revoked
-- （bound→revoked 保留原绑定时刻，已发放 COP 不回溯，§3 状态机）
ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_bound_ck;
ALTER TABLE invites ADD CONSTRAINT invites_bound_ck
  CHECK ((status = 'bound') = (bound_at IS NOT NULL) OR status = 'revoked') NOT VALID;

ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_bound_at_ck;
ALTER TABLE invites ADD CONSTRAINT invites_bound_at_ck
  CHECK (bound_at IS NULL OR status IN ('bound', 'revoked')) NOT VALID;

-- 已绑定必须有被邀请人；其它状态不强制（expired / revoked 可能从 sent 直接来）
ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_bound_invitee_ck;
ALTER TABLE invites ADD CONSTRAINT invites_bound_invitee_ck
  CHECK (status <> 'bound' OR invitee_id IS NOT NULL) NOT VALID;

ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_code_ck;
ALTER TABLE invites ADD CONSTRAINT invites_code_ck
  CHECK (char_length(code) BETWEEN 6 AND 64) NOT VALID;

-- INV-04：(inviter_id, invitee_id) 唯一（invitee 为空不参与，允许同时存在多张待绑定邀请）
CREATE UNIQUE INDEX IF NOT EXISTS invites_inviter_invitee_uq
  ON invites (inviter_id, invitee_id) WHERE invitee_id IS NOT NULL;

-- code 唯一（§5 UNIQUE(invites.code)）
CREATE UNIQUE INDEX IF NOT EXISTS invites_code_uq ON invites (code);

-- 一个被邀请人只能绑定一次（单层邀请的直接推论；防止同一人同时挂两个上级）
CREATE UNIQUE INDEX IF NOT EXISTS invites_invitee_bound_uq
  ON invites (invitee_id) WHERE status = 'bound' AND invitee_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS invites_inviter_page_idx ON invites (inviter_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS invites_expiry_idx ON invites (expire_at) WHERE status = 'sent';

-- ────────────────────────────────────────────────────────── INV-03 单层护栏
CREATE OR REPLACE FUNCTION m07_invite_single_layer() RETURNS trigger AS $$
DECLARE
  parent TEXT;
BEGIN
  IF NEW.status <> 'bound' THEN
    RETURN NEW;
  END IF;
  IF NEW.invitee_id IS NULL THEN
    RAISE EXCEPTION 'invites: bound 邀请必须有 invitee_id' USING ERRCODE = '23514';
  END IF;
  -- ① 邀请人自身不得有邀请人（否则本行就是第二层）
  SELECT i.inviter_id INTO parent
    FROM invites i
   WHERE i.invitee_id = NEW.inviter_id AND i.status = 'bound'
   LIMIT 1;
  IF parent IS NOT NULL THEN
    RAISE EXCEPTION 'invites: INV-03 邀请只有一层（% 已是 % 的被邀请人）',
      NEW.inviter_id, parent USING ERRCODE = '23514';
  END IF;
  -- ② 被邀请人不得已经是邀请人（否则绑定后它会成为中间层）
  IF EXISTS (SELECT 1 FROM invites i WHERE i.inviter_id = NEW.invitee_id) THEN
    RAISE EXCEPTION 'invites: INV-03 被邀请人 % 已是邀请人，绑定会形成二级链路',
      NEW.invitee_id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS invites_single_layer ON invites;
CREATE TRIGGER invites_single_layer BEFORE INSERT OR UPDATE ON invites
  FOR EACH ROW EXECUTE FUNCTION m07_invite_single_layer();

-- ────────────────────────────────────────────────────────── 状态机护栏
CREATE OR REPLACE FUNCTION m07_invite_state_machine() RETURNS trigger AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'invites: DELETE not allowed（保留 ≥5 年，用 revoked 表达）'
      USING ERRCODE = '42501';
  END IF;

  -- 不可变列：code / inviter_id / 创建时刻 / 发放人
  IF NEW.code IS DISTINCT FROM OLD.code
     OR NEW.inviter_id IS DISTINCT FROM OLD.inviter_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.issued_by IS DISTINCT FROM OLD.issued_by THEN
    RAISE EXCEPTION 'invites: code / inviter_id / created_at / issued_by 不可修改'
      USING ERRCODE = '42501';
  END IF;

  -- invitee_id 只允许从 NULL 变成具体人（绑定），之后不可改 / 不可清空
  IF OLD.invitee_id IS NOT NULL AND NEW.invitee_id IS DISTINCT FROM OLD.invitee_id THEN
    RAISE EXCEPTION 'invites: invitee_id 绑定后不可修改' USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    allowed := (OLD.status, NEW.status) IN (
      ('sent', 'bound'), ('sent', 'expired'), ('bound', 'revoked'));
    IF NOT allowed THEN
      RAISE EXCEPTION 'invites: 非法状态迁移 % → %（§3 只允许 sent→bound / sent→expired / bound→revoked）',
        OLD.status, NEW.status USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS invites_state_machine ON invites;
CREATE TRIGGER invites_state_machine BEFORE UPDATE OR DELETE ON invites
  FOR EACH ROW EXECUTE FUNCTION m07_invite_state_machine();

DROP TRIGGER IF EXISTS invites_no_truncate ON invites;
CREATE TRIGGER invites_no_truncate BEFORE TRUNCATE ON invites
  FOR EACH STATEMENT EXECUTE FUNCTION m07_forbid_truncate();

COMMENT ON TABLE invites IS
  'M07 单层邀请（M07 §5 / 迁移 704，保留 ≥5 年）：INV-03 单层 + INV-04 唯一，由触发器强制';
COMMENT ON INDEX invites_invitee_bound_uq IS
  '一个被邀请人只能绑定一次：单层邀请的直接推论（防同一人挂两个上级）';
COMMENT ON COLUMN invites.bound_at IS
  '绑定时刻；bound 必填，revoked 保留原值（invites_bound_ck / invites_bound_at_ck）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'invites_code_uq') THEN
    RAISE EXCEPTION '704: 缺 UNIQUE(invites.code)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'invites_inviter_invitee_uq') THEN
    RAISE EXCEPTION '704: 缺 UNIQUE(inviter_id, invitee_id)（INV-04）';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'invites_single_layer') THEN
    RAISE EXCEPTION '704: 缺单层邀请触发器 invites_single_layer（INV-03）';
  END IF;
END
$$;

COMMIT;
