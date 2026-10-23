-- 508 · M05 计量收据 · 放宽状态机：settled → corrected（上游账单迟到时的追加校正）
-- 规格：product/v4/modules/M05-metering-receipt.md §3 状态机 + INV-06
--       「``usage_source=estimated`` 必须显式标记；上游账单到达后**只能追加校正**，不得改原值」
--       §6 流程 3（导入上游账单 → 差额 >1% 追加校正）
--       §7「上游账单迟到」：保持 estimated，不阻塞计费
--
-- 为什么需要放宽：501 最初只允许 ``recorded → settled`` / ``recorded → corrected``。但上游账单
-- 按 T+1 到达，此时 usage 往往已经 ``settled``（结算完成）；INV-06 要求**迟到差额只能追加校正**，
-- 校正落定后该 usage 的正确状态是 ``corrected``。若不放开 ``settled → corrected``，迟到账单
-- 要么无法追加校正（要改历史，违反 INV-06），要么只能把校正记在账外（违反 append-only 审计）。
-- 因此本迁移**只放宽**一条边：``settled → corrected``（已有行仍然全部合法，属兼容性放宽）。
BEGIN;

CREATE OR REPLACE FUNCTION m05_usage_state_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['state', 'settled_at', 'corrected_at', 'correction_id'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'usage_records is append-only: DELETE not allowed (M05 INV-06)'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'usage_records: only state machine columns may change (M05 INV-06)'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.state = NEW.state THEN
    IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
      RAISE EXCEPTION 'usage_records: no-op state update with changed columns is not allowed'
        USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  -- 合法迁移：recorded → settled / corrected；settled → corrected（508：迟到账单追加校正）
  IF NOT (OLD.state = 'recorded' AND NEW.state IN ('settled', 'corrected')
       OR OLD.state = 'settled'  AND NEW.state = 'corrected') THEN
    RAISE EXCEPTION 'usage_records: illegal transition % -> % (M05 §3 / 508)',
      OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 状态与时间戳成对（重建 CHECK：corrected 必须带 corrected_at + correction_id；
-- 从 settled 迁移过来时 settled_at 保留，便于审计「先结算后校正」的时序）
ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_state_time_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_state_time_ck
  CHECK ((state = 'recorded'  AND settled_at IS NULL AND corrected_at IS NULL
                            AND correction_id IS NULL)
      OR (state = 'settled'   AND settled_at IS NOT NULL AND corrected_at IS NULL)
      OR (state = 'corrected' AND corrected_at IS NOT NULL AND correction_id IS NOT NULL))
  NOT VALID;

COMMENT ON FUNCTION m05_usage_state_guard() IS
  'M05 usage 状态机（501 建 / 508 放宽）：recorded→settled|corrected；settled→corrected（迟到账单）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'usage_records_state_guard') THEN
    RAISE EXCEPTION '508: usage_records_state_guard 触发器缺失（501 未应用？）';
  END IF;
END
$$;

COMMIT;
