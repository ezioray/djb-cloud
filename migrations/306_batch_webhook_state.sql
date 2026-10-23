-- 306 · M03 网关 · 慢任务 webhook 投递台账（batch_jobs 加列 + 状态机护栏放宽）
-- 规格：product/v4/modules/M03-gateway-protocol.md §4.3（批次 Webhook 属**对外**投递）·
--       §3.2 INV-M03-06（终态不可逆）· §5（batch_jobs 归 M03）· §12.5.6（事件目录）
--       00-conventions §7.2「只允许加列 / 加表 / 加索引」
--
-- 为什么用加列而不是新表：webhook 投递台账只服务 batch_jobs 的**同一聚合**（一次投递 =
-- 一个批次的对外通知），01-ownership §2 未给 M03 分配投递表；加列即可满足「不新增未登记表」。
-- 若后续需要按次审计（每次尝试一行），再走 CR 新建 m03_webhook_deliveries。
--
-- 变更内容：
--   1) 加 4 列：webhook_state / webhook_attempts / webhook_last_error / webhook_delivered_at
--      （全部可空或带默认，向后兼容；不删不改既有列）
--   2) 放宽状态机护栏：终态行允许改动「投递台账列 + updated_at」（webhook 常在终态之后投递），
--      业务列（status / 金额 / 计数 / model …）仍然冻结（INV-M03-06 不放宽）
BEGIN;

ALTER TABLE batch_jobs ADD COLUMN IF NOT EXISTS webhook_state TEXT;
ALTER TABLE batch_jobs ADD COLUMN IF NOT EXISTS webhook_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE batch_jobs ADD COLUMN IF NOT EXISTS webhook_last_error TEXT;
ALTER TABLE batch_jobs ADD COLUMN IF NOT EXISTS webhook_delivered_at TIMESTAMPTZ;

ALTER TABLE batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_webhook_state_ck;
ALTER TABLE batch_jobs ADD CONSTRAINT batch_jobs_webhook_state_ck
  CHECK (webhook_state IS NULL
     OR webhook_state IN ('pending', 'delivered', 'failed', 'skipped')) NOT VALID;

ALTER TABLE batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_webhook_meta_ck;
ALTER TABLE batch_jobs ADD CONSTRAINT batch_jobs_webhook_meta_ck
  CHECK (webhook_attempts >= 0
     AND (webhook_last_error IS NULL OR char_length(webhook_last_error) <= 200)) NOT VALID;

-- 状态机护栏：终态行只允许投递台账与 updated_at 变化（业务列仍冻结）
CREATE OR REPLACE FUNCTION m03_batch_state_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['updated_at', 'results_ref', 'results_expires_at',
                          'cost_actual_minor', 'checkpoint_resumes', 'error_code',
                          'webhook_state', 'webhook_attempts', 'webhook_last_error',
                          'webhook_delivered_at'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.created_at > now() - INTERVAL '7 days' THEN
      RAISE EXCEPTION 'batch_jobs: only rows older than 7 days may be deleted (retention)'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;

  IF OLD.status IN ('succeeded', 'failed', 'canceled') THEN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'batch_jobs: terminal status % cannot move to % (INV-M03-06)',
        OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
    IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
      RAISE EXCEPTION 'batch_jobs: terminal row is immutable except delivery columns (INV-M03-06)'
        USING ERRCODE = '42501';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT ((OLD.status = 'queued' AND NEW.status IN ('running', 'canceled', 'failed'))
         OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed', 'canceled'))) THEN
      RAISE EXCEPTION 'batch_jobs: illegal transition % -> % (M03 §3.1)',
        OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.status = 'canceled' AND NEW.canceled_at IS NULL THEN
    NEW.canceled_at := now();
  END IF;
  IF NEW.status IN ('succeeded', 'failed') AND NEW.completed_at IS NULL THEN
    NEW.completed_at := now();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON COLUMN batch_jobs.webhook_state IS
  '对外 webhook 投递状态：pending / delivered / failed / skipped（NULL = 未配置回调）';
COMMENT ON COLUMN batch_jobs.webhook_attempts IS
  '已投递尝试次数（M03 §4.3；上限由 facts.WEBHOOK_MAX_ATTEMPTS 控制）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'batch_jobs' AND column_name = 'webhook_state') THEN
    RAISE EXCEPTION '306: batch_jobs 缺列 webhook_state';
  END IF;
END
$$;

COMMIT;
