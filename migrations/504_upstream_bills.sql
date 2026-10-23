-- 504 · M05 计量收据 · 上游账单（upstream_bills）+ 只追加护栏
-- 规格：product/v4/modules/M05-metering-receipt.md §5 数据所有权（upstream_bills，迁移 504）
--       §6 流程 3（导入 → 按 access/period 匹配 usage → 差额率 ≤1% 只记录校验结果，>1% 追加校正）
--       §7 失败矩阵（账单迟到保持 estimated，不阻塞计费）· §8.1（metering.overbill_tolerance_pct）
--       product/v4/modules/03-facts.md §10（S1 验收：收据差异率 ≤1%）
--
-- 语义：账单是**上游给的事实**，只追加、只标记对账状态（imported → reconciled），
-- 金额与周期不可改；导入逐行受理，单行失败不回滚整批（与 502 同款）。
BEGIN;

CREATE TABLE IF NOT EXISTS upstream_bills (
  bill_id        TEXT PRIMARY KEY,                -- 上游账单行号（幂等键的一半：(usage_id, bill_id)）
  provider       TEXT NOT NULL,                   -- 上游标识（如 openai / anthropic …）
  period         TEXT NOT NULL,                   -- 账单周期：YYYY-MM 或 YYYY-MM-DD（UTC）
  amount_minor   BIGINT NOT NULL,                 -- 整数最小单位（USD 分，00-conventions §3）
  access         TEXT NOT NULL,                   -- A1 / A2 / B（M05 §5 枚举）
  state          TEXT NOT NULL DEFAULT 'imported',-- imported → reconciled
  imported_at    TIMESTAMPTZ NOT NULL,
  reconciled_at  TIMESTAMPTZ,
  imported_by    TEXT,                            -- 导入人（FIN / OPS 后台 id）
  trace_id       TEXT
);

ALTER TABLE upstream_bills DROP CONSTRAINT IF EXISTS upstream_bills_access_ck;
ALTER TABLE upstream_bills ADD CONSTRAINT upstream_bills_access_ck
  CHECK (access IN ('A1', 'A2', 'B')) NOT VALID;

ALTER TABLE upstream_bills DROP CONSTRAINT IF EXISTS upstream_bills_state_ck;
ALTER TABLE upstream_bills ADD CONSTRAINT upstream_bills_state_ck
  CHECK (state IN ('imported', 'reconciled')) NOT VALID;

ALTER TABLE upstream_bills DROP CONSTRAINT IF EXISTS upstream_bills_amount_ck;
ALTER TABLE upstream_bills ADD CONSTRAINT upstream_bills_amount_ck
  CHECK (amount_minor >= 0) NOT VALID;

-- 周期形状（与 M06 constants 的 PERIOD_LEN_MONTH / PERIOD_LEN_DAY 同源：7 / 10 字符）
ALTER TABLE upstream_bills DROP CONSTRAINT IF EXISTS upstream_bills_period_ck;
ALTER TABLE upstream_bills ADD CONSTRAINT upstream_bills_period_ck
  CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])(-(0[1-9]|[12][0-9]|3[01]))?$') NOT VALID;

ALTER TABLE upstream_bills DROP CONSTRAINT IF EXISTS upstream_bills_text_ck;
ALTER TABLE upstream_bills ADD CONSTRAINT upstream_bills_text_ck
  CHECK (char_length(bill_id) BETWEEN 1 AND 128
     AND char_length(provider) BETWEEN 1 AND 64
     AND (imported_by IS NULL OR char_length(imported_by) BETWEEN 1 AND 128)
     AND (trace_id IS NULL OR char_length(trace_id) BETWEEN 1 AND 128)) NOT VALID;

ALTER TABLE upstream_bills DROP CONSTRAINT IF EXISTS upstream_bills_state_ck2;
ALTER TABLE upstream_bills ADD CONSTRAINT upstream_bills_state_ck2
  CHECK ((state = 'imported'   AND reconciled_at IS NULL)
      OR (state = 'reconciled' AND reconciled_at IS NOT NULL)) NOT VALID;

DROP INDEX IF EXISTS upstream_bills_provider_period_idx;
CREATE INDEX upstream_bills_provider_period_idx ON upstream_bills (provider, period, access);

DROP INDEX IF EXISTS upstream_bills_state_idx;
CREATE INDEX upstream_bills_state_idx ON upstream_bills (state, imported_at DESC);

-- 只追加：金额 / 周期 / access 写入即不可改；只允许 imported → reconciled 状态迁移
CREATE OR REPLACE FUNCTION m05_bill_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['state', 'reconciled_at'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'upstream_bills is append-only: DELETE not allowed (M05 §5)'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'upstream_bills: only reconciliation columns may change (M05 §5)'
      USING ERRCODE = '42501';
  END IF;
  IF NOT (OLD.state = 'imported' AND NEW.state = 'reconciled') THEN
    RAISE EXCEPTION 'upstream_bills: illegal transition % -> % (M05 §3)',
      OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS upstream_bills_guard ON upstream_bills;
CREATE TRIGGER upstream_bills_guard BEFORE UPDATE OR DELETE ON upstream_bills
  FOR EACH ROW EXECUTE FUNCTION m05_bill_guard();

DROP TRIGGER IF EXISTS upstream_bills_no_truncate ON upstream_bills;
CREATE TRIGGER upstream_bills_no_truncate BEFORE TRUNCATE ON upstream_bills
  FOR EACH STATEMENT EXECUTE FUNCTION m05_forbid_truncate();

-- 新行只能是 imported：reconciled 必须经状态迁移（对账动作可追溯）
CREATE OR REPLACE FUNCTION m05_bill_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.state <> 'imported' THEN
    RAISE EXCEPTION 'upstream_bills: rows must start at state=imported (M05 §5)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS upstream_bills_insert_guard ON upstream_bills;
CREATE TRIGGER upstream_bills_insert_guard BEFORE INSERT ON upstream_bills
  FOR EACH ROW EXECUTE FUNCTION m05_bill_insert_guard();

COMMENT ON TABLE upstream_bills IS
  'M05 上游账单（M05 §5 / 迁移 504）：只追加；imported → reconciled，金额与周期不可改';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'upstream_bills' AND column_name = 'amount_minor') THEN
    RAISE EXCEPTION '504: upstream_bills 缺列 amount_minor';
  END IF;
END
$$;

COMMIT;
