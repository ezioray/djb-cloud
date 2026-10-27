-- 1712 · M17 冻结申诉通道（supplier_integrity_appeals）
-- 规格：M17-supply-integrity.md §6.1（申诉 7 天窗口）· §7 数据模型（1700–1799）
--
-- 原则（只加不改）：
--   1) **不改 1710 既有表 / 约束**：申诉单独建表，`supplier_integrity_events` 的事件枚举
--      与 CHECK 保持原样（回滚只 DROP 本表，零影响）。
--   2) **不改账本**：本表只记录申诉与复核结论，不动 ledger_* / 余额 / 分录；
--      解除仍走 holds.release()（它本身只改 hold 状态）。
--   3) **一条 hold 同时只允许 1 条 open 申诉**：部分唯一索引 uq_integrity_appeals_open。
--   4) **7 天窗口**：deadline_at = hold.created_at + 7d（应用按 facts.APPEAL_WINDOW 写入，
--      DB CHECK 只保证 deadline_at >= created_at；窗口边界含等号）。
--   5) 结论状态机：open → upheld（维持冻结，进入人工/决策路径）| released（经复核解除）
--      | expired（窗口内未处理，由定时任务翻）。终态不可回 open，禁止 DELETE / TRUNCATE。
BEGIN;

CREATE TABLE IF NOT EXISTS supplier_integrity_appeals (
  id              UUID PRIMARY KEY,                       -- UUIDv7（应用生成）
  hold_id         UUID NOT NULL REFERENCES supplier_integrity_holds (id),
  node_id         TEXT NOT NULL,
  model           TEXT NOT NULL,
  state           TEXT NOT NULL DEFAULT 'open',            -- open / upheld / released / expired
  reason          TEXT NOT NULL,                           -- 申诉理由（粗粒度，不含正文/PII）
  appellant       TEXT NOT NULL,                           -- 申诉主体（共享方 id / 运营代提）
  created_at      TIMESTAMPTZ NOT NULL,
  deadline_at     TIMESTAMPTZ NOT NULL,                    -- = hold.created_at + 7d
  resolved_at     TIMESTAMPTZ,
  resolution      TEXT,                                    -- upheld / released / expired（与 state 同步）
  release_reason  TEXT,
  reviewer_a      TEXT,
  reviewer_b      TEXT,
  version         INTEGER NOT NULL DEFAULT 1,
  updated_at      TIMESTAMPTZ NOT NULL,
  CONSTRAINT supplier_integrity_appeals_state_ck
    CHECK (state IN ('open', 'upheld', 'released', 'expired')),
  CONSTRAINT supplier_integrity_appeals_window_ck
    CHECK (deadline_at >= created_at),
  CONSTRAINT supplier_integrity_appeals_reason_ck
    CHECK (char_length(reason) BETWEEN 1 AND 64),
  CONSTRAINT supplier_integrity_appeals_actor_ck
    CHECK (char_length(appellant) BETWEEN 1 AND 128),
  CONSTRAINT supplier_integrity_appeals_resolution_ck
    CHECK ((state = 'open') = (resolved_at IS NULL))
);

-- 同一 hold 同时只允许 1 条未结申诉（并发双提直接 23505，service 先查后插）
CREATE UNIQUE INDEX IF NOT EXISTS uq_integrity_appeals_open
  ON supplier_integrity_appeals (hold_id) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS idx_integrity_appeals_hold
  ON supplier_integrity_appeals (hold_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_appeals_node
  ON supplier_integrity_appeals (node_id, state, created_at DESC);

COMMENT ON TABLE supplier_integrity_appeals IS
  'M17 §6.1 冻结申诉（7 天窗口）：open→upheld/released/expired；只记录申诉与复核结论，'
  '不改账本；解除仍由 holds.release() 执行（只改 hold 状态）';

-- 护栏：身份字段不可变、version 只增、终态不可回 open；禁止 DELETE / TRUNCATE
CREATE OR REPLACE FUNCTION m17_appeal_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'supplier_integrity_appeals 只追加：禁止 DELETE' USING ERRCODE = '42501';
  END IF;
  IF NEW.hold_id <> OLD.hold_id OR NEW.node_id <> OLD.node_id
     OR NEW.model <> OLD.model OR NEW.created_at <> OLD.created_at
     OR NEW.deadline_at <> OLD.deadline_at OR NEW.appellant <> OLD.appellant THEN
    RAISE EXCEPTION '申诉身份字段不可变' USING ERRCODE = '42501';
  END IF;
  IF OLD.state <> 'open' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION '申诉终态不可回写（% → %）', OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'version 只能 +1' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_integrity_appeals_guard ON supplier_integrity_appeals;
CREATE TRIGGER trg_integrity_appeals_guard
  BEFORE UPDATE OR DELETE ON supplier_integrity_appeals
  FOR EACH ROW EXECUTE FUNCTION m17_appeal_guard();

CREATE OR REPLACE FUNCTION m17_appeals_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'supplier_integrity_appeals 只追加：禁止 TRUNCATE' USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS trg_integrity_appeals_no_truncate ON supplier_integrity_appeals;
CREATE TRIGGER trg_integrity_appeals_no_truncate
  BEFORE TRUNCATE ON supplier_integrity_appeals
  FOR EACH STATEMENT EXECUTE FUNCTION m17_appeals_forbid_truncate();

COMMIT;
