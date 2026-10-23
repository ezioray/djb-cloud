-- 705 · M07 人工授予 / 扣回（reward_grants，只追加）
-- 规格：product/v4/modules/M07-reputation-cop.md §3（RewardGrant：kind/amount/reason/actor/approval_id）
--       §4.1（POST /admin/reputation/grants：双人复核 + 理由；缺 step-up 424/42401；复核人=发起人 409/40919）
--       §5（reward_grants，迁移 705，保留 ≥5 年）· §7（扣回必须带 ref_id 与理由，正向冲正，不删原分录）
--       00-conventions §9.4（管理面写操作二次认证；高危动作双人复核）
--
-- 原则：
--   1) **只追加**：授予与扣回都是新行，更正用反向行（kind 相反），禁止 UPDATE / DELETE。
--   2) **双人复核**：``approved_by`` 必填且 ≠ ``actor``（库层 CHECK 兜底，领域层先行判定 → 409/40919）。
--   3) **理由必填**：reason 1–512 字符（spec ReputationGrantRequest.reason）。
--   4) **与 COP 台账同事务**：``journal_id`` 指向 points_journal（COP 唯一账本），
--      本表只是「人工作业的凭据」，金额以 points_* 为准（不重复记账）。
BEGIN;

CREATE TABLE IF NOT EXISTS reward_grants (
  id           UUID PRIMARY KEY,                    -- UUIDv7；对外 grant_id
  account_id   TEXT NOT NULL,                       -- 被授予 / 扣回账户
  kind         TEXT NOT NULL,                       -- grant（授予）/ clawback（扣回）
  amount       BIGINT NOT NULL,                     -- COP 单位数（>0；方向由 kind 决定）
  reason       TEXT NOT NULL,                       -- 理由（1–512 字符，必填）
  actor        TEXT NOT NULL,                       -- 发起人（admin 主体）
  approved_by  TEXT NOT NULL,                       -- 复核人（≠ actor，双人复核）
  approval_id  TEXT,                                -- 审批单号（可空；M14 高危动作回填）
  journal_id   UUID,                                -- 关联的 points_journal（COP 唯一账本）
  request_id   TEXT,                                -- X-DJB-Idempotency-Key（24h 幂等）
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()   -- 作业时刻
);

ALTER TABLE reward_grants DROP CONSTRAINT IF EXISTS reward_grants_kind_ck;
ALTER TABLE reward_grants ADD CONSTRAINT reward_grants_kind_ck
  CHECK (kind IN ('grant', 'clawback')) NOT VALID;

ALTER TABLE reward_grants DROP CONSTRAINT IF EXISTS reward_grants_amount_ck;
ALTER TABLE reward_grants ADD CONSTRAINT reward_grants_amount_ck
  CHECK (amount > 0) NOT VALID;

ALTER TABLE reward_grants DROP CONSTRAINT IF EXISTS reward_grants_reason_ck;
ALTER TABLE reward_grants ADD CONSTRAINT reward_grants_reason_ck
  CHECK (char_length(reason) BETWEEN 1 AND 512) NOT VALID;

-- 双人复核（§4.1 / 00-conventions §9.4）：复核人必填且不得等于发起人
ALTER TABLE reward_grants DROP CONSTRAINT IF EXISTS reward_grants_sod_ck;
ALTER TABLE reward_grants ADD CONSTRAINT reward_grants_sod_ck
  CHECK (char_length(approved_by) BETWEEN 1 AND 128 AND approved_by <> actor) NOT VALID;

ALTER TABLE reward_grants DROP CONSTRAINT IF EXISTS reward_grants_actor_ck;
ALTER TABLE reward_grants ADD CONSTRAINT reward_grants_actor_ck
  CHECK (char_length(actor) BETWEEN 1 AND 128 AND char_length(account_id) BETWEEN 1 AND 128) NOT VALID;

-- 幂等：同一 X-DJB-Idempotency-Key 只落一条；同一 journal 只对应一条作业凭据
CREATE UNIQUE INDEX IF NOT EXISTS reward_grants_request_uq
  ON reward_grants (request_id) WHERE request_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS reward_grants_journal_uq
  ON reward_grants (journal_id) WHERE journal_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS reward_grants_account_idx ON reward_grants (account_id, created_at DESC);

-- 只追加护栏（与 reputation_events 同一个函数）
DROP TRIGGER IF EXISTS reward_grants_no_mutation ON reward_grants;
CREATE TRIGGER reward_grants_no_mutation BEFORE UPDATE OR DELETE ON reward_grants
  FOR EACH ROW EXECUTE FUNCTION m07_forbid_mutation();

DROP TRIGGER IF EXISTS reward_grants_no_truncate ON reward_grants;
CREATE TRIGGER reward_grants_no_truncate BEFORE TRUNCATE ON reward_grants
  FOR EACH STATEMENT EXECUTE FUNCTION m07_forbid_truncate();

COMMENT ON TABLE reward_grants IS
  'M07 人工授予 / 扣回凭据（M07 §5 / 迁移 705，保留 ≥5 年）：只追加；金额以 points_* 为准';
COMMENT ON COLUMN reward_grants.approved_by IS
  '复核人：必填且 ≠ actor（§4.1 双人复核；违反 → 409/40919）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'reward_grants_no_mutation') THEN
    RAISE EXCEPTION '705: 缺只追加触发器 reward_grants_no_mutation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'reward_grants_request_uq') THEN
    RAISE EXCEPTION '705: 缺幂等唯一索引 reward_grants_request_uq';
  END IF;
END
$$;

COMMIT;
