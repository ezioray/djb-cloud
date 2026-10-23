-- 409 · M04 scheduler-pricing · 配额软停与公平计数（quota_usage 只加列）
-- 规格：M04 §3 QuotaUsage / §4.7.3 P3 失败动作（全部违反 → 冻结该租户 60 s 并给可执行建议）
--       §4.7.5 公平与配额（防大户独占 ≤25%、日/周/月窗口）
--       INV-08（单租户同模型并发占比）· 00-conventions §7.2（只加不改）
--
-- 本迁移**只加列**（不改 405 的任何列与约束）：
--   1) frozen_until / frozen_reason —— 配额软停状态（P3 全违反时冻结，默认 60 s）；
--   2) wait_started_at —— 该租户在该模型上首次被拒的时刻（反饥饿 / 公平观测输入）；
--   3) share_updated_at —— 占比最后一次计算的时刻（占比由 M04 自有计数算出，不靠上游）；
--   4) 两个索引：软停扫描、公平快照。
BEGIN;

ALTER TABLE quota_usage ADD COLUMN IF NOT EXISTS frozen_until      TIMESTAMPTZ;
ALTER TABLE quota_usage ADD COLUMN IF NOT EXISTS frozen_reason     TEXT;
ALTER TABLE quota_usage ADD COLUMN IF NOT EXISTS wait_started_at   TIMESTAMPTZ;
ALTER TABLE quota_usage ADD COLUMN IF NOT EXISTS share_updated_at  TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'quota_usage_frozen_reason_ck' AND connamespace = current_schema()::regnamespace) THEN
    ALTER TABLE quota_usage ADD CONSTRAINT quota_usage_frozen_reason_ck
      CHECK (frozen_reason IS NULL OR char_length(frozen_reason) BETWEEN 1 AND 64) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'quota_usage_frozen_pair_ck' AND connamespace = current_schema()::regnamespace) THEN
    ALTER TABLE quota_usage ADD CONSTRAINT quota_usage_frozen_pair_ck
      CHECK ((frozen_until IS NULL) = (frozen_reason IS NULL)) NOT VALID;
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS quota_usage_frozen_idx
  ON quota_usage (frozen_until) WHERE frozen_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS quota_usage_share_idx
  ON quota_usage (model, window_start, share_pct_bps DESC);

COMMENT ON COLUMN quota_usage.frozen_until IS
  '配额软停到期时刻（§4.7.3 P3：全部约束违反 → 冻结 60 s；仅当开关 scheduling.quota_soft_stop 打开时写入）';
COMMENT ON COLUMN quota_usage.share_pct_bps IS
  '单租户同模型并发占比（bps）：由 M04 自有计数算出（本表 concurrent / 同模型合计），不依赖上游';
COMMENT ON COLUMN quota_usage.wait_started_at IS '首次被拒时刻（反饥饿与公平观测输入；成功路由后清空）';

COMMIT;
