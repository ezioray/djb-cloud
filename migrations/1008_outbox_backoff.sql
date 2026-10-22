-- 1008 · M10 配置中心 · T5：事件投递退避（last_attempt_at / next_attempt_at）
-- 规格：02-events §2（指数退避 1s/5s/30s/5min/30min，最多 8 次；之后进死信并告警）
--       M10 §7（失败与补偿：有限次重试后停止）
--
-- 只加列：1007 已有 delivery_attempts / last_error / dead_lettered_at；本文件补两个时间列，
-- 让「退避」成为可查询状态（worker 按 next_attempt_at 取下一批，不靠进程内 sleep）。
BEGIN;

ALTER TABLE config_outbox
  ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

ALTER TABLE config_outbox
  DROP CONSTRAINT IF EXISTS config_outbox_next_attempt_ck;
ALTER TABLE config_outbox
  ADD CONSTRAINT config_outbox_next_attempt_ck CHECK (
    next_attempt_at IS NULL OR last_attempt_at IS NOT NULL);

-- 待投递索引继续排除死信；退避过滤在查询里做（next_attempt_at IS NULL OR <= now）
DROP INDEX IF EXISTS config_outbox_pending_idx;
CREATE INDEX IF NOT EXISTS config_outbox_pending_idx
  ON config_outbox (created_at)
  WHERE published_at IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX IF NOT EXISTS config_outbox_next_attempt_idx
  ON config_outbox (next_attempt_at)
  WHERE published_at IS NULL AND dead_lettered_at IS NULL;

-- 升级 outbox 护栏：投递器可改的两个新列也纳入白名单（其余规则不变）
CREATE OR REPLACE FUNCTION m10_outbox_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_outbox is append-only: DELETE not allowed'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['published_at', 'delivery_attempts', 'last_error',
                            'dead_lettered_at', 'last_attempt_at', 'next_attempt_at'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['published_at', 'delivery_attempts', 'last_error',
                            'dead_lettered_at', 'last_attempt_at', 'next_attempt_at'])
  THEN
    RAISE EXCEPTION 'config_outbox is append-only: only delivery fields may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
    RAISE EXCEPTION 'config_outbox: published_at is write-once (% -> %)',
      OLD.published_at, NEW.published_at
      USING ERRCODE = '42501';
  END IF;
  IF OLD.dead_lettered_at IS NOT NULL AND NEW.dead_lettered_at IS DISTINCT FROM OLD.dead_lettered_at THEN
    RAISE EXCEPTION 'config_outbox: dead_lettered_at is write-once'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.delivery_attempts < OLD.delivery_attempts THEN
    RAISE EXCEPTION 'config_outbox: delivery_attempts must not decrease (% -> %)',
      OLD.delivery_attempts, NEW.delivery_attempts
      USING ERRCODE = '42501';
  END IF;
  IF NEW.published_at IS NOT NULL AND NEW.dead_lettered_at IS NOT NULL THEN
    RAISE EXCEPTION 'config_outbox: event cannot be both published and dead-lettered'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['last_attempt_at', 'next_attempt_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_outbox' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_outbox 结构与 1008 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
