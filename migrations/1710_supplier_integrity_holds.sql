-- 1710 · M17 待分润冻结（supplier_integrity_holds）+ 事件流水（supplier_integrity_events）
-- 规格：M17-supply-integrity.md §6.1（作弊升级与待分润冻结）· §7 数据模型（迁移段 1700–1799）
-- 决策（task-15 / Lead 裁决）：S2 全开 I0–I4；比例 I0=0 / I1=50% / I2=80% / I3=I4=100%；
--       S2 **只冻结不罚没**（罚没留 S3）；冻结的只是「待分润」，绝不改账本。
--
-- 原则（与 M11 案件表同款护栏）：
--   1) **不碰账本**：本迁移不创建、不修改任何 ledger_* / account_balances / loss_pool 对象，
--      也不新增账本科目或分录；冻结只改本表 state 与金额快照（迁移末尾有断言兜底）。
--   2) **只冻待分润**：base_amount_micro 由调用方传入（M05 待分润快照），本表不查账本、不出分录；
--      frozen_amount_micro = base_amount_micro * ratio_bp / 10000（整数向下取整，DB CHECK 兜底）。
--   3) **等级-比例绑定**：ratio_bp 必须与 level 表一致（DB CHECK）：
--      I0=0、I1=5000、I2=8000、I3=I4=10000。service 层再校验一次（双保险）。
--   4) **同 (node_id, model) 只能 1 条 active**：部分唯一索引 uq_integrity_holds_active；
--      升级只改同一行（只升不降），不新建第二条。
--   5) **事件只追加**：supplier_integrity_events 禁止 UPDATE / DELETE / TRUNCATE；
--      I0 不建 hold 但**要留事件**（hold_id 可空），保证「判过 I0」可追溯。
--   6) hold 身份字段不可变、version 只增、终态不可回写 active、禁止 DELETE / TRUNCATE；
--      I1 到期由 service 的 expire_due() 写 state='expired'（仍然只改本表）。
BEGIN;

-- ───────────────────────────────────────────────────────── supplier_integrity_holds
CREATE TABLE IF NOT EXISTS supplier_integrity_holds (
  id                  UUID PRIMARY KEY,                     -- UUIDv7（应用生成，时间有序）
  node_id             TEXT NOT NULL,                        -- 供应节点（M02）
  upstream_id         TEXT,                                 -- 可选：具体上游（relay / A1 / A2）
  model               TEXT NOT NULL,                       -- canonical model slug
  level               TEXT NOT NULL,                        -- I0–I4（§6.1）
  ratio_bp            INTEGER NOT NULL,                     -- 冻结比例（基点；0–10000）
  base_amount_micro   BIGINT NOT NULL,                      -- 待分润快照（micro；调用方给，不查账本）
  frozen_amount_micro BIGINT NOT NULL,                      -- = base * ratio_bp / 10000（整数取整）
  state               TEXT NOT NULL DEFAULT 'active',       -- active / released / expired
  reason              TEXT NOT NULL,                        -- 粗粒度原因码（不含阈值 / PII）
  evidence_ref        TEXT NOT NULL,                        -- 证据引用（事件 id / 案件 id / 收据 id）
  created_at          TIMESTAMPTZ NOT NULL,
  expires_at          TIMESTAMPTZ,                          -- I1=now+7d；I2+ 无自动到期（NULL）
  released_at         TIMESTAMPTZ,
  release_reason      TEXT,
  reviewer_a          TEXT,
  reviewer_b          TEXT,
  version             INTEGER NOT NULL DEFAULT 1,           -- 乐观并发 / 审计（每次变更 +1）
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 等级枚举
  CONSTRAINT supplier_integrity_holds_level_ck CHECK
    (level IN ('I0', 'I1', 'I2', 'I3', 'I4')),
  -- 比例范围 + 与等级绑定（决策：I0=0 / I1=5000 / I2=8000 / I3=I4=10000）
  CONSTRAINT supplier_integrity_holds_ratio_range_ck CHECK (ratio_bp BETWEEN 0 AND 10000),
  CONSTRAINT supplier_integrity_holds_ratio_level_ck CHECK (
    (level = 'I0' AND ratio_bp = 0)
    OR (level = 'I1' AND ratio_bp = 5000)
    OR (level = 'I2' AND ratio_bp = 8000)
    OR (level IN ('I3', 'I4') AND ratio_bp = 10000)),
  -- 金额非负 + 冻结额必须等于「基数 × 比例」（整数向下取整）
  CONSTRAINT supplier_integrity_holds_base_ck CHECK (base_amount_micro >= 0),
  CONSTRAINT supplier_integrity_holds_frozen_ck CHECK (
    frozen_amount_micro = (base_amount_micro * ratio_bp) / 10000),
  CONSTRAINT supplier_integrity_holds_frozen_nonneg_ck CHECK (frozen_amount_micro >= 0),
  -- 状态枚举 + 状态字段一致性
  CONSTRAINT supplier_integrity_holds_state_ck CHECK
    (state IN ('active', 'released', 'expired')),
  CONSTRAINT supplier_integrity_holds_expiry_ck CHECK (
    (level = 'I1' AND expires_at IS NOT NULL) OR (level <> 'I1')),
  CONSTRAINT supplier_integrity_holds_no_auto_expiry_ck CHECK (
    (level IN ('I2', 'I3', 'I4') AND expires_at IS NULL) OR (level NOT IN ('I2', 'I3', 'I4'))),
  CONSTRAINT supplier_integrity_holds_released_ck CHECK (
    state <> 'released'
    OR (released_at IS NOT NULL AND release_reason IS NOT NULL AND reviewer_a IS NOT NULL)),
  CONSTRAINT supplier_integrity_holds_active_ck CHECK (
    state <> 'active'
    OR (released_at IS NULL AND release_reason IS NULL
        AND reviewer_a IS NULL AND reviewer_b IS NULL)),
  CONSTRAINT supplier_integrity_holds_reviewers_ck CHECK (
    reviewer_b IS NULL OR (reviewer_a IS NOT NULL AND reviewer_b <> reviewer_a)),
  CONSTRAINT supplier_integrity_holds_version_ck CHECK (version >= 1),
  CONSTRAINT supplier_integrity_holds_reason_ck CHECK (char_length(reason) BETWEEN 1 AND 64),
  CONSTRAINT supplier_integrity_holds_evidence_ck CHECK (char_length(evidence_ref) BETWEEN 1 AND 128),
  CONSTRAINT supplier_integrity_holds_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT supplier_integrity_holds_model_ck CHECK (char_length(model) BETWEEN 1 AND 128)
);

-- 同 (node_id, model) 只能有 1 条 active（升级 = 改同一行，不新建）
CREATE UNIQUE INDEX IF NOT EXISTS uq_integrity_holds_active
  ON supplier_integrity_holds (node_id, model)
  WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_integrity_holds_node
  ON supplier_integrity_holds (node_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_holds_level
  ON supplier_integrity_holds (level, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_holds_expiry
  ON supplier_integrity_holds (expires_at) WHERE state = 'active' AND expires_at IS NOT NULL;

COMMENT ON TABLE supplier_integrity_holds IS
  'M17 §6.1 待分润冻结（S2 只冻结不罚没）：只改本表状态与金额快照，不改账本/不出分录；'
  '同 (node_id, model) 仅 1 条 active；ratio 与 level 绑定；I1 7 天自动到期';

-- ───────────────────────────────────────────────────────── supplier_integrity_events
CREATE TABLE IF NOT EXISTS supplier_integrity_events (
  event_id    UUID PRIMARY KEY,                             -- UUIDv7
  hold_id     UUID REFERENCES supplier_integrity_holds (id),-- I0 不建 hold → 可空（仍留事件）
  node_id     TEXT NOT NULL,
  model       TEXT NOT NULL,
  event       TEXT NOT NULL,                                -- created / escalated / released / expired
  from_level  TEXT,
  to_level    TEXT,
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,           -- 只放 id / 比例 / 金额 / 粗粒度原因
  actor       TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL,
  CONSTRAINT supplier_integrity_events_event_ck CHECK
    (event IN ('created', 'escalated', 'released', 'expired')),
  CONSTRAINT supplier_integrity_events_levels_ck CHECK (
    (from_level IS NULL OR from_level IN ('I0', 'I1', 'I2', 'I3', 'I4'))
    AND (to_level IS NULL OR to_level IN ('I0', 'I1', 'I2', 'I3', 'I4'))),
  CONSTRAINT supplier_integrity_events_created_ck CHECK (
    event <> 'created' OR (to_level IS NOT NULL AND from_level IS NULL)),
  CONSTRAINT supplier_integrity_events_escalated_ck CHECK (
    event <> 'escalated' OR (from_level IS NOT NULL AND to_level IS NOT NULL)),
  CONSTRAINT supplier_integrity_events_closed_ck CHECK (
    event NOT IN ('released', 'expired') OR from_level IS NOT NULL),
  -- 事件 detail 只放元数据：不得出现正文 / 凭据 / 阈值类键
  CONSTRAINT supplier_integrity_events_detail_ck CHECK (
    NOT (detail ?| ARRAY['prompt', 'response', 'messages', 'content', 'body', 'text',
                         'token', 'secret', 'password', 'api_key', 'threshold', 'weight'])),
  CONSTRAINT supplier_integrity_events_actor_ck CHECK (char_length(actor) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_integrity_events_hold
  ON supplier_integrity_events (hold_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_events_node
  ON supplier_integrity_events (node_id, model, created_at DESC);

COMMENT ON TABLE supplier_integrity_events IS
  'M17 §6.1 冻结事件流水（只追加）：created / escalated / released / expired；'
  'I0 不建 hold 也留事件（hold_id 可空）；detail 只放 id / 比例 / 金额';

-- ───────────────────────────────────────────────────────── 护栏函数
-- 通用：禁止 TRUNCATE（两张表都要）
CREATE OR REPLACE FUNCTION m17_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% 只追加：禁止 TRUNCATE', TG_TABLE_NAME USING ERRCODE = '42501';
END $$;

-- hold：身份不可变 / version 只增 / 只升不降 / 终态不可回写 / 禁止 DELETE
CREATE OR REPLACE FUNCTION m17_holds_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  old_rank INTEGER;
  new_rank INTEGER;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'supplier_integrity_holds 禁止 DELETE（冻结记录保留可查）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.model IS DISTINCT FROM OLD.model
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'supplier_integrity_holds 身份字段不可变（id / node_id / model / created_at）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'supplier_integrity_holds.version 只能 +1（乐观并发）'
      USING ERRCODE = '42501';
  END IF;
  -- 终态不可回写 active / 不可换终态
  IF OLD.state IN ('released', 'expired') AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION '冻结处于终态 %：不可再迁移', OLD.state USING ERRCODE = '42501';
  END IF;
  -- 冻结额只能由 base/ratio 推导（这里再校验一次，防止绕过 CHECK 的 UPDATE）
  IF NEW.frozen_amount_micro <> (NEW.base_amount_micro * NEW.ratio_bp) / 10000 THEN
    RAISE EXCEPTION 'frozen_amount_micro 必须等于 base * ratio_bp / 10000'
      USING ERRCODE = '42501';
  END IF;
  -- 等级只升不降（降级必须先 release 再重建）
  IF NEW.level IS DISTINCT FROM OLD.level THEN
    old_rank := CASE OLD.level WHEN 'I0' THEN 0 WHEN 'I1' THEN 1 WHEN 'I2' THEN 2
                               WHEN 'I3' THEN 3 ELSE 4 END;
    new_rank := CASE NEW.level WHEN 'I0' THEN 0 WHEN 'I1' THEN 1 WHEN 'I2' THEN 2
                               WHEN 'I3' THEN 3 ELSE 4 END;
    IF new_rank <= old_rank THEN
      RAISE EXCEPTION '冻结等级只升不降（% → %）', OLD.level, NEW.level USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS supplier_integrity_holds_guard ON supplier_integrity_holds;
CREATE TRIGGER supplier_integrity_holds_guard BEFORE UPDATE OR DELETE
  ON supplier_integrity_holds FOR EACH ROW EXECUTE FUNCTION m17_holds_guard();

DROP TRIGGER IF EXISTS supplier_integrity_holds_no_truncate ON supplier_integrity_holds;
CREATE TRIGGER supplier_integrity_holds_no_truncate BEFORE TRUNCATE
  ON supplier_integrity_holds FOR EACH STATEMENT EXECUTE FUNCTION m17_forbid_truncate();

-- 事件：只追加
CREATE OR REPLACE FUNCTION m17_events_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'supplier_integrity_events 只追加：禁止 %', TG_OP USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS supplier_integrity_events_guard ON supplier_integrity_events;
CREATE TRIGGER supplier_integrity_events_guard BEFORE UPDATE OR DELETE
  ON supplier_integrity_events FOR EACH ROW EXECUTE FUNCTION m17_events_guard();

DROP TRIGGER IF EXISTS supplier_integrity_events_no_truncate ON supplier_integrity_events;
CREATE TRIGGER supplier_integrity_events_no_truncate BEFORE TRUNCATE
  ON supplier_integrity_events FOR EACH STATEMENT EXECUTE FUNCTION m17_forbid_truncate();

-- ───────────────────────────────────────────────────────── 迁移自检（不碰账本）
-- 本迁移**不创建、不修改任何账本对象**（ledger_journal / ledger_entry / account_balances /
-- merkle_commitments / ledger_outbox / loss_pool_entries 全部由 M05/M06/M09 的迁移拥有）。
-- 迁移内不做 schema 级断言（账本表在本迁移之前就已存在，扫全 schema 无意义）；
-- 「迁移前后账本对象结构指纹 + 行摘要 diff = 0」由
-- tests/integrity/test_migration.py::test_ledger_fingerprint_and_rows_unchanged 证明。
COMMIT;
