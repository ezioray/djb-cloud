-- 509 · M05 计量收据 · 复核约束改为「生效时」检查（负向校正的人工复核口径）
-- 规格：product/v4/modules/M05-metering-receipt.md INV-08「单条 usage 的校正累计不得超过原额；
--       负向校正（退款方向）需人工复核」· §6 流程 3（>1% 追加 correction + 差异工单）
--       §7「校正累计超额 → 拒绝校正 + 人工复核」
--
-- 为什么改：503 的 ``usage_corrections_review_ck`` 要求「delta < 0 时必须有 second_approver」，
-- 这在**自动对账**路径上无法满足——上游账单 T+1 到达时，复核人还不存在，但差额必须先在案
-- （否则差异丢失）。复核的意义在「生效」而不是「登记」：
--   1) ``proposed``：允许无复核人（人工 / 自动都可以登记差额，等复核）；
--   2) ``applied``：负向校正**必须**有 second_approver（否则不能生效）；
--   3) 域层另外保证：提交侧（管理面人工校正）与生效侧都做「复核人 ≠ 操作人」校验。
-- 只放宽不收紧：已有行仍然全部合法。
BEGIN;

ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_review_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_review_ck
  CHECK (state <> 'applied' OR delta_minor > 0 OR second_approver IS NOT NULL) NOT VALID;

COMMENT ON CONSTRAINT usage_corrections_review_ck ON usage_corrections IS
  'INV-08：负向校正必须人工复核——proposed 可无复核人，applied 必须有 second_approver';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'usage_corrections_review_ck') THEN
    RAISE EXCEPTION '509: 缺约束 usage_corrections_review_ck';
  END IF;
END
$$;

COMMIT;
