-- 302 · M03 网关 · 慢任务主表（batch_jobs）+ 状态机 / 幂等护栏
-- 规格：product/v4/modules/M03-gateway-protocol.md §3.1（batch 生命周期）/ §3.2 INV-M03-06
--       （终态不可再迁移、取消幂等）· §5 数据所有权（batch_jobs 归 M03，迁移 300–399）
--       §10.3 CR-1 已裁决：batch_jobs / batch_items 归 M03
--       spec `BatchCreateRequest` / `Batch` / `BatchStatus` / `BatchCancelAck`
--       00-conventions §2（UUIDv7）/ §5（错误码段）
--
-- 原则：
--   1) 状态机：queued → running → succeeded | failed | canceled；**终态不可逆**（INV-M03-06）。
--      终态行只允许 webhook 投递记账类字段变化（T4 使用），业务字段一律冻结。
--   2) 幂等（M03 §6 流程 3）：(account_id, idempotency_key) 唯一（部分索引），重复提交回同一 batch。
--   3) 金额整数最小单位（USD 分，00-conventions §3.1）：cost_estimate_minor / cost_actual_minor。
--   4) 结果签名 URL ≤15 分钟、保留 7 天（INV-M03-09）：results_ref + results_expires_at。
--   5) 可重复执行 + 末尾结构断言。
BEGIN;

CREATE TABLE IF NOT EXISTS batch_jobs (
  batch_id            UUID PRIMARY KEY,                 -- UUIDv7
  account_id          UUID NOT NULL,                    -- M01（软引用）
  tenant_id           UUID,                             -- M01（软引用）
  api_key_id          BIGINT,                           -- M01（软引用）
  kind                TEXT NOT NULL,                    -- chat / completion（spec BatchCreateRequest）
  model               TEXT NOT NULL,                    -- 模型 slug
  status              TEXT NOT NULL DEFAULT 'queued',   -- 状态机见文件头
  request_id          TEXT,                             -- 提交时的 X-Request-Id（排障）
  idempotency_key     TEXT,                             -- X-DJB-Idempotency-Key（24h 语义由应用层保证）
  total_items         INTEGER NOT NULL DEFAULT 0,
  completed_items     INTEGER NOT NULL DEFAULT 0,
  failed_items        INTEGER NOT NULL DEFAULT 0,
  eta_seconds         INTEGER,
  checkpoint_resumes  INTEGER NOT NULL DEFAULT 0,       -- 检查点恢复次数（M03 §3.1）
  results_ref         TEXT,                             -- 结果对象签名 URL（≤15 分钟）
  results_expires_at  TIMESTAMPTZ,
  cost_estimate_minor BIGINT,                           -- 预估成本（USD 分）
  cost_actual_minor   BIGINT,                           -- 实际成本（USD 分；以 M05 收据为准）
  cost_confirmed_at   TIMESTAMPTZ,                      -- >10 USD 的确认时刻（M03 §6.3）
  deadline_seconds    INTEGER,
  webhook_url         TEXT,                             -- 完成回调（T4；验签在投递侧）
  metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_code          INTEGER,                          -- 终态失败时的对外数字码
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at        TIMESTAMPTZ,
  canceled_at         TIMESTAMPTZ
);

ALTER TABLE batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_status_ck;
ALTER TABLE batch_jobs ADD CONSTRAINT batch_jobs_status_ck
  CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')) NOT VALID;

ALTER TABLE batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_kind_ck;
ALTER TABLE batch_jobs ADD CONSTRAINT batch_jobs_kind_ck
  CHECK (kind IN ('chat', 'completion')) NOT VALID;

ALTER TABLE batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_counts_ck;
ALTER TABLE batch_jobs ADD CONSTRAINT batch_jobs_counts_ck
  CHECK (total_items >= 0 AND completed_items >= 0 AND failed_items >= 0
     AND completed_items + failed_items <= total_items
     AND checkpoint_resumes >= 0
     AND (eta_seconds IS NULL OR eta_seconds >= 0)
     AND (cost_estimate_minor IS NULL OR cost_estimate_minor >= 0)
     AND (cost_actual_minor IS NULL OR cost_actual_minor >= 0)
     AND (deadline_seconds IS NULL OR deadline_seconds >= 60)) NOT VALID;

ALTER TABLE batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_meta_ck;
ALTER TABLE batch_jobs ADD CONSTRAINT batch_jobs_meta_ck
  CHECK (char_length(model) BETWEEN 1 AND 128
     AND (request_id IS NULL OR char_length(request_id) BETWEEN 1 AND 128)
     AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 128)
     AND (results_ref IS NULL OR char_length(results_ref) <= 2048)
     AND (webhook_url IS NULL OR char_length(webhook_url) <= 2048)) NOT VALID;

-- 幂等（M03 §6 流程 3）：同一账户同一幂等键只有一个批次
CREATE UNIQUE INDEX IF NOT EXISTS batch_jobs_idempotency_uq
  ON batch_jobs (account_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS batch_jobs_account_time_idx
  ON batch_jobs (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS batch_jobs_active_idx
  ON batch_jobs (status, created_at) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS batch_jobs_results_expiry_idx
  ON batch_jobs (results_expires_at) WHERE results_expires_at IS NOT NULL;

-- ────────────────────────────────────────────────────────── 状态机护栏
CREATE OR REPLACE FUNCTION m03_batch_state_guard() RETURNS trigger AS $$
DECLARE
  -- 终态后仍允许变化的列：投递/签名单（T4）与 stats 收尾
  mutable TEXT[] := ARRAY['updated_at', 'results_ref', 'results_expires_at',
                          'cost_actual_minor', 'checkpoint_resumes', 'error_code'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- 结果保留 7 天（INV-M03-09）：只有够老的行可删
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
    RETURN NEW;
  END IF;

  -- 合法迁移：queued → running / canceled；running → succeeded / failed / canceled
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT ((OLD.status = 'queued' AND NEW.status IN ('running', 'canceled', 'failed'))
         OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed', 'canceled'))) THEN
      RAISE EXCEPTION 'batch_jobs: illegal transition % -> % (M03 §3.1)',
        OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
  END IF;

  -- 终态落库时补齐时间戳（取消幂等：重复取消不改状态）
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

DROP TRIGGER IF EXISTS batch_jobs_guard ON batch_jobs;
CREATE TRIGGER batch_jobs_guard BEFORE UPDATE OR DELETE ON batch_jobs
  FOR EACH ROW EXECUTE FUNCTION m03_batch_state_guard();

DROP TRIGGER IF EXISTS batch_jobs_no_truncate ON batch_jobs;
CREATE TRIGGER batch_jobs_no_truncate BEFORE TRUNCATE ON batch_jobs
  FOR EACH STATEMENT EXECUTE FUNCTION m03_forbid_truncate();

COMMENT ON TABLE batch_jobs IS
  'M03 慢任务（迁移 302）：queued → running → 终态不可逆；结果签名 URL ≤15 分钟、保留 7 天';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'batch_jobs' AND column_name = 'checkpoint_resumes') THEN
    RAISE EXCEPTION '302: batch_jobs 缺列 checkpoint_resumes';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'batch_jobs_idempotency_uq') THEN
    RAISE EXCEPTION '302: 缺幂等索引 batch_jobs_idempotency_uq';
  END IF;
END
$$;

COMMIT;
