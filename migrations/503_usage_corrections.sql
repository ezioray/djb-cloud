-- 503 · M05 计量收据 · 校正在案（usage_corrections）+ 只追加护栏
-- 规格：product/v4/modules/M05-metering-receipt.md §3（INV-06/INV-07/INV-08/INV-11）
--       §5 数据所有权（usage_corrections，迁移 503，保留 5 年）· §6 流程 3 · §8.2（1% 阈值）
--       product/v4/modules/03-facts.md §10（S1 验收：收据差异率 ≤1%）
--
-- 语义：上游账单 / 人工复核的差额**只追加校正**，绝不改 usage_records 的原值（INV-06）。
-- 单条 usage 的累计校正不得超过原额（INV-08）、负向校正需人工复核（second_approver）；
-- 累计校验是跨行聚合，放在域层（T4）并在 tests/metering 里给正反例，DDL 只钉住单行约束。
BEGIN;

CREATE TABLE IF NOT EXISTS usage_corrections (
  correction_id     UUID PRIMARY KEY,
  usage_id          UUID NOT NULL,                 -- 指向 usage_records（软引用，不建跨表 FK）
  delta_minor       BIGINT NOT NULL,               -- 差额（整数分；正=补收，负=退款方向）
  original_minor    BIGINT NOT NULL,               -- 提出时的原额快照（累计校验用）
  reason_code       TEXT NOT NULL,                 -- overbill / underbill / estimate_fix / dispute
  upstream_bill_id  TEXT,                          -- 上游账单行号（人工校正时为 NULL）
  state             TEXT NOT NULL DEFAULT 'proposed',   -- proposed → applied / rejected
  requested_by      TEXT NOT NULL,                 -- 操作人（M01 admin id）
  second_approver   TEXT,                          -- 双人复核（≥50 USD 或负向校正必填）
  detail            TEXT,                          -- 复核说明（不含正文 / 凭据）
  created_at        TIMESTAMPTZ NOT NULL,
  applied_at        TIMESTAMPTZ,
  rejected_at       TIMESTAMPTZ
);

ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_reason_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_reason_ck
  CHECK (reason_code IN ('overbill', 'underbill', 'estimate_fix', 'dispute')) NOT VALID;

ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_state_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_state_ck
  CHECK (state IN ('proposed', 'applied', 'rejected')) NOT VALID;

-- 差额不为 0；原额非负（INV-05 口径：整数最小单位）
ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_delta_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_delta_ck
  CHECK (delta_minor <> 0 AND original_minor >= 0) NOT VALID;

-- 状态与时间戳成对；负向校正（退款方向）必须有第二复核人（INV-08）
ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_state_ck2;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_state_ck2
  CHECK ((state = 'proposed' AND applied_at IS NULL AND rejected_at IS NULL)
      OR (state = 'applied'  AND applied_at IS NOT NULL AND rejected_at IS NULL)
      OR (state = 'rejected' AND rejected_at IS NOT NULL AND applied_at IS NULL))
  NOT VALID;

ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_review_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_review_ck
  CHECK (delta_minor > 0 OR second_approver IS NOT NULL) NOT VALID;

ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_text_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_text_ck
  CHECK (char_length(requested_by) BETWEEN 1 AND 128
     AND (second_approver IS NULL OR char_length(second_approver) BETWEEN 1 AND 128)
     AND (upstream_bill_id IS NULL OR char_length(upstream_bill_id) BETWEEN 1 AND 128)
     AND (detail IS NULL OR char_length(detail) <= 512)) NOT VALID;

-- INV-11 幂等键：(usage_id, upstream_bill_id) 唯一
DROP INDEX IF EXISTS usage_corrections_bill_uq;
CREATE UNIQUE INDEX usage_corrections_bill_uq
  ON usage_corrections (usage_id, upstream_bill_id) WHERE upstream_bill_id IS NOT NULL;

DROP INDEX IF EXISTS usage_corrections_usage_time_idx;
CREATE INDEX usage_corrections_usage_time_idx ON usage_corrections (usage_id, created_at DESC);

DROP INDEX IF EXISTS usage_corrections_state_idx;
CREATE INDEX usage_corrections_state_idx ON usage_corrections (state, created_at DESC);

-- 状态机：proposed → applied / rejected；业务列（金额、原因、usage_id）写入即不可改
CREATE OR REPLACE FUNCTION m05_correction_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['state', 'applied_at', 'rejected_at', 'second_approver'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'usage_corrections is append-only: DELETE not allowed (M05 INV-06)'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'usage_corrections: only state / approval columns may change (M05 INV-06)'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.state <> 'proposed' OR NEW.state NOT IN ('applied', 'rejected') THEN
    RAISE EXCEPTION 'usage_corrections: illegal transition % -> % (M05 §3)',
      OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS usage_corrections_guard ON usage_corrections;
CREATE TRIGGER usage_corrections_guard BEFORE UPDATE OR DELETE ON usage_corrections
  FOR EACH ROW EXECUTE FUNCTION m05_correction_guard();

DROP TRIGGER IF EXISTS usage_corrections_no_truncate ON usage_corrections;
CREATE TRIGGER usage_corrections_no_truncate BEFORE TRUNCATE ON usage_corrections
  FOR EACH STATEMENT EXECUTE FUNCTION m05_forbid_truncate();

-- 新行只能是 proposed：applied / rejected 必须经状态机迁移（不能一次写入终态绕过护栏）
CREATE OR REPLACE FUNCTION m05_correction_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.state <> 'proposed' THEN
    RAISE EXCEPTION 'usage_corrections: rows must start at state=proposed (M05 §3)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS usage_corrections_insert_guard ON usage_corrections;
CREATE TRIGGER usage_corrections_insert_guard BEFORE INSERT ON usage_corrections
  FOR EACH ROW EXECUTE FUNCTION m05_correction_insert_guard();

COMMENT ON TABLE usage_corrections IS
  'M05 校正在案（M05 §5 / 迁移 503）：只追加；差额以校正表达，不改 usage_records 原值（INV-06）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'usage_corrections_bill_uq') THEN
    RAISE EXCEPTION '503: 缺唯一索引 usage_corrections_bill_uq（INV-11）';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'usage_corrections' AND column_name = 'delta_minor') THEN
    RAISE EXCEPTION '503: usage_corrections 缺列 delta_minor';
  END IF;
END
$$;

COMMIT;
