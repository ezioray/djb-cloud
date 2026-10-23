-- 505 · M05 计量收据 · 亏损池（loss_pool_entries）+ 只追加护栏
-- 规格：product/v4/modules/M05-metering-receipt.md §3（INV-09：只记「上游已消耗、用户未计费」，
--       同一 (request_id, attempt_no) 只能一条；**不冲减 4101**）
--       §5 数据所有权（loss_pool_entries，迁移 505，保留 5 年）· §6 流程 3 第 3 步
--       §9 验收④（兜底切换导致上游已消耗 8 USD、用户未计费 → 一条 loss_pool_entry，E15 金额 8）
--       §7（只追加、不静默丢账）
--
-- 语义：亏损池是**平台承担**的已发生成本（M06 消费后落 E15：借 5104 / 贷 1109），
-- 与用户计费无关——因此本表**不写 amount_minor 到 usage_records**，也不做任何冲减。
BEGIN;

CREATE TABLE IF NOT EXISTS loss_pool_entries (
  entry_id      UUID PRIMARY KEY,
  request_id    TEXT NOT NULL,                    -- M03 网关请求号（软引用）
  attempt_no    INTEGER NOT NULL DEFAULT 1,       -- 与 usage_records 同一尝试口径
  amount_minor  BIGINT NOT NULL,                  -- 上游已消耗金额（整数分；>0）
  reason        TEXT NOT NULL,                    -- 原因码（见下表注释；T4 扩展需登记）
  evidence_ref  TEXT,                             -- 证据引用（上游账单行 / 日志 id / 工单号）
  recorded_at   TIMESTAMPTZ NOT NULL,             -- 业务发生时间（UTC）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 金额必须为正：0 或负数的「亏损」没有意义；负向调整走校正（508 段之外的 503 表）
ALTER TABLE loss_pool_entries DROP CONSTRAINT IF EXISTS loss_pool_amount_ck;
ALTER TABLE loss_pool_entries ADD CONSTRAINT loss_pool_amount_ck
  CHECK (amount_minor > 0) NOT VALID;

ALTER TABLE loss_pool_entries DROP CONSTRAINT IF EXISTS loss_pool_attempt_ck;
ALTER TABLE loss_pool_entries ADD CONSTRAINT loss_pool_attempt_ck
  CHECK (attempt_no >= 1) NOT VALID;

-- INV-09：同一 (request_id, attempt_no) 只能一条（重复入池 = 重复计成本）
DROP INDEX IF EXISTS loss_pool_request_attempt_uq;
CREATE UNIQUE INDEX loss_pool_request_attempt_uq
  ON loss_pool_entries (request_id, attempt_no);

ALTER TABLE loss_pool_entries DROP CONSTRAINT IF EXISTS loss_pool_text_ck;
ALTER TABLE loss_pool_entries ADD CONSTRAINT loss_pool_text_ck
  CHECK (char_length(request_id) BETWEEN 1 AND 128
     AND char_length(reason) BETWEEN 1 AND 64
     AND (evidence_ref IS NULL OR char_length(evidence_ref) BETWEEN 1 AND 256)) NOT VALID;

DROP INDEX IF EXISTS loss_pool_recorded_idx;
CREATE INDEX loss_pool_recorded_idx ON loss_pool_entries (recorded_at DESC, reason);

DROP TRIGGER IF EXISTS loss_pool_no_mutation ON loss_pool_entries;
CREATE TRIGGER loss_pool_no_mutation BEFORE UPDATE OR DELETE ON loss_pool_entries
  FOR EACH ROW EXECUTE FUNCTION m05_forbid_mutation();

DROP TRIGGER IF EXISTS loss_pool_no_truncate ON loss_pool_entries;
CREATE TRIGGER loss_pool_no_truncate BEFORE TRUNCATE ON loss_pool_entries
  FOR EACH STATEMENT EXECUTE FUNCTION m05_forbid_truncate();

COMMENT ON TABLE loss_pool_entries IS
  'M05 亏损池（M05 §5 / 迁移 505）：只记「上游已消耗、用户未计费」，只追加，不冲减 4101（INV-09）';
COMMENT ON COLUMN loss_pool_entries.reason IS
  '已知取值：fallback_switch（兜底切换）/ stream_interrupt（流式中断）/ upstream_consumed（上游已计费）';

COMMENT ON FUNCTION m05_forbid_mutation() IS
  'M05 只追加护栏（501 建，502/505 复用）：UPDATE / DELETE 一律 42501';
COMMENT ON FUNCTION m05_forbid_truncate() IS
  'M05 只追加护栏（501 建，502/503/504/505 复用）：TRUNCATE 一律 42501';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'loss_pool_request_attempt_uq') THEN
    RAISE EXCEPTION '505: 缺唯一索引 loss_pool_request_attempt_uq（INV-09）';
  END IF;
END
$$;

COMMIT;
