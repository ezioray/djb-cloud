-- 1302 · M14 admin-data · 保留任务与删除报告（retention_jobs）
-- 规格：M14 §3 / §5 / §8.2（迁移 1302，保留 24 个月）· INV-05 / INV-06 / INV-07
--       §22.5 保留矩阵：备份 ≤35 天、日志元数据 30 天、埋点 ≤14 个月、工单 24 个月
--
-- 语义：
--   1) 状态 queued → running → done；failed 可幂等重放（回到 queued，replay_count +1）。
--   2) 同一 (object, cutoff) 的**真实执行**只允许一次（部分唯一索引；dry-run 不占名额）。
--   3) 删除报告是任务产物：report（JSONB）必含已删 / 部分保留 / 最迟清除日 / 方式；
--      30 天办结由 sla_due_at 记录，超期在接口层标 overdue。
--   4) M14 不执行删除：deleted_count 来自注入的 Owner 执行器；本表不做任何业务表清理。
BEGIN;

CREATE TABLE IF NOT EXISTS retention_jobs (
  job_id          UUID PRIMARY KEY,
  job_no          TEXT NOT NULL UNIQUE,
  "object"        TEXT NOT NULL,
  policy_days     INTEGER NOT NULL,
  cutoff          TIMESTAMPTZ NOT NULL,
  state           TEXT NOT NULL DEFAULT 'queued',
  dry_run         BOOLEAN NOT NULL DEFAULT false,
  deleted_count   BIGINT NOT NULL DEFAULT 0,
  retained_count  BIGINT NOT NULL DEFAULT 0,
  report          JSONB,
  report_ref      TEXT NOT NULL,
  failure_reason  TEXT,
  replay_count    INTEGER NOT NULL DEFAULT 0,
  sla_due_at      TIMESTAMPTZ NOT NULL,
  requested_by    TEXT NOT NULL,
  idempotency_key TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE retention_jobs DROP CONSTRAINT IF EXISTS retention_jobs_shape_ck;
ALTER TABLE retention_jobs ADD CONSTRAINT retention_jobs_shape_ck
  CHECK (job_no ~ '^[A-Z0-9-]{1,32}$'
     AND "object" IN ('usage', 'receipts', 'tickets', 'logs', 'backups', 'analytics')
     AND policy_days BETWEEN 1 AND 3650
     AND char_length(report_ref) BETWEEN 1 AND 256
     AND char_length(requested_by) BETWEEN 1 AND 128
     AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 16 AND 128)
     AND deleted_count >= 0 AND retained_count >= 0 AND replay_count >= 0) NOT VALID;

ALTER TABLE retention_jobs DROP CONSTRAINT IF EXISTS retention_jobs_state_ck;
ALTER TABLE retention_jobs ADD CONSTRAINT retention_jobs_state_ck
  CHECK (state IN ('queued', 'running', 'done', 'failed')) NOT VALID;

ALTER TABLE retention_jobs DROP CONSTRAINT IF EXISTS retention_jobs_state_fields_ck;
ALTER TABLE retention_jobs ADD CONSTRAINT retention_jobs_state_fields_ck
  CHECK ((state <> 'running' OR started_at IS NOT NULL)
     AND (state <> 'done'
          OR (finished_at IS NOT NULL AND report IS NOT NULL AND jsonb_typeof(report) = 'object'))
     AND (state <> 'failed' OR failure_reason IS NOT NULL)
     AND (report IS NULL OR jsonb_typeof(report) = 'object')) NOT VALID;

CREATE OR REPLACE FUNCTION m14_retention_jobs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF NEW.job_no IS DISTINCT FROM OLD.job_no
     OR NEW."object" IS DISTINCT FROM OLD."object"
     OR NEW.policy_days IS DISTINCT FROM OLD.policy_days
     OR NEW.cutoff IS DISTINCT FROM OLD.cutoff
     OR NEW.dry_run IS DISTINCT FROM OLD.dry_run
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.sla_due_at IS DISTINCT FROM OLD.sla_due_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'retention_jobs 的任务事实字段不可改（INV-07 幂等键）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := (OLD.state, NEW.state) IN (
      ('queued', 'running'), ('queued', 'failed'),
      ('running', 'done'), ('running', 'failed'),
      ('failed', 'queued'));
    IF NOT COALESCE(allowed, false) THEN
      RAISE EXCEPTION '非法保留任务状态迁移 % -> %（M14 §3）', OLD.state, NEW.state
        USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'failed' AND NEW.state = 'queued'
       AND NEW.replay_count <> OLD.replay_count + 1 THEN
      RAISE EXCEPTION '失败重放必须 replay_count + 1（INV-07）' USING ERRCODE = '23514';
    END IF;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS retention_jobs_guard ON retention_jobs;
CREATE TRIGGER retention_jobs_guard BEFORE UPDATE ON retention_jobs
  FOR EACH ROW EXECUTE FUNCTION m14_retention_jobs_guard();
DROP TRIGGER IF EXISTS retention_jobs_no_delete ON retention_jobs;
CREATE TRIGGER retention_jobs_no_delete BEFORE DELETE ON retention_jobs
  FOR EACH ROW EXECUTE FUNCTION m14_forbid_delete();
DROP TRIGGER IF EXISTS retention_jobs_no_truncate ON retention_jobs;
CREATE TRIGGER retention_jobs_no_truncate BEFORE TRUNCATE ON retention_jobs
  FOR EACH STATEMENT EXECUTE FUNCTION m14_forbid_truncate();

-- INV-07：同一 (object, cutoff) 只执行一次；failed 可重放、dry-run 不占名额
DROP INDEX IF EXISTS uq_retention_jobs_object_cutoff;
CREATE UNIQUE INDEX uq_retention_jobs_object_cutoff
  ON retention_jobs ("object", cutoff)
  WHERE state <> 'failed' AND dry_run = false;
DROP INDEX IF EXISTS idx_retention_jobs_object_created;
CREATE INDEX idx_retention_jobs_object_created
  ON retention_jobs ("object", created_at DESC);
DROP INDEX IF EXISTS idx_retention_jobs_state_created;
CREATE INDEX idx_retention_jobs_state_created
  ON retention_jobs (state, created_at DESC);

DO $$
DECLARE
  missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO missing
    FROM unnest(ARRAY['job_id','job_no','object','policy_days','cutoff','state','dry_run',
                      'deleted_count','retained_count','report','report_ref','failure_reason',
                      'replay_count','sla_due_at','requested_by','idempotency_key',
                      'created_at','started_at','finished_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'retention_jobs' AND column_name = c);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'retention_jobs 结构与 1302 不符，缺列：%', missing;
  END IF;
END;
$$;

COMMIT;
