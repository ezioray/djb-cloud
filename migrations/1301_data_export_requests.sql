-- 1301 · M14 admin-data · 导出申请与执行（data_export_requests）
-- 规格：product/v4/modules/M14-admin-data.md §3 / §5 / §8.2（迁移 1301，保留 24 个月）
--       INV-04：导出只含请求人有权范围；链接 ≤15 分钟（应用层）；文件 7 天失效；水印；双人复核
--       product/v4/modules/01-ownership.md §2（M14 自有表）· 00-conventions §7（只加不改）
--
-- 语义：
--   1) 只追加 + 受控状态机：申请事实字段（requester/scope/format/reason/estimated_rows…）不可改，
--      状态只能按 M14 §3 前进（pending → approved → running → done / failed / expired；
--      done → expired 表示文件 7 天失效；pending/approved → failed 表示取消，见 CR-M14-01）。
--   2) 删除 / TRUNCATE 一律拒绝（撤销只改状态，不删申请记录；保留 24 个月由 M16 归档处理）。
--   3) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE；末尾结构断言防半途建表。
BEGIN;

CREATE TABLE IF NOT EXISTS data_export_requests (
  export_id              UUID PRIMARY KEY,
  export_no              TEXT NOT NULL,
  requester              TEXT NOT NULL,
  requester_tenant       TEXT NOT NULL,
  scope                  JSONB NOT NULL,
  "format"               JSONB NOT NULL,
  reason                 TEXT NOT NULL,
  state                  TEXT NOT NULL DEFAULT 'pending',
  row_count              BIGINT NOT NULL DEFAULT 0,
  estimated_rows         BIGINT NOT NULL DEFAULT 0,
  contains_personal_data BOOLEAN NOT NULL DEFAULT false,
  approval_required      BOOLEAN NOT NULL DEFAULT false,
  approver               TEXT,
  approved_at            TIMESTAMPTZ,
  started_at             TIMESTAMPTZ,
  finished_at            TIMESTAMPTZ,
  expires_at             TIMESTAMPTZ,
  watermark              TEXT,
  failure_reason         TEXT,
  cancelled_at           TIMESTAMPTZ,
  cancelled_by           TEXT,
  link_jti               TEXT,
  link_consumed_at       TIMESTAMPTZ,
  idempotency_key        TEXT,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── 形状 / 枚举（NOT VALID：不阻塞历史行，但新写入逐行校验）
ALTER TABLE data_export_requests DROP CONSTRAINT IF EXISTS data_export_requests_no_ck;
ALTER TABLE data_export_requests ADD CONSTRAINT data_export_requests_no_ck
  CHECK (export_no ~ '^[A-Z0-9-]{1,32}$'
     AND char_length(requester) BETWEEN 1 AND 128
     AND char_length(requester_tenant) BETWEEN 1 AND 128
     AND char_length(reason) BETWEEN 1 AND 512
     AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 16 AND 128)
     AND (watermark IS NULL OR char_length(watermark) BETWEEN 1 AND 128)
     AND (link_jti IS NULL OR char_length(link_jti) <= 64)
     AND row_count >= 0 AND estimated_rows >= 0) NOT VALID;

ALTER TABLE data_export_requests DROP CONSTRAINT IF EXISTS data_export_requests_state_ck;
ALTER TABLE data_export_requests ADD CONSTRAINT data_export_requests_state_ck
  CHECK (state IN ('pending', 'approved', 'running', 'done', 'failed', 'expired')) NOT VALID;

ALTER TABLE data_export_requests DROP CONSTRAINT IF EXISTS data_export_requests_scope_ck;
ALTER TABLE data_export_requests ADD CONSTRAINT data_export_requests_scope_ck
  CHECK (jsonb_typeof(scope) = 'object'
     AND scope ? 'object'
     AND scope->>'object' IN ('usage', 'receipts', 'tickets', 'logs', 'backups', 'analytics'))
  NOT VALID;

ALTER TABLE data_export_requests DROP CONSTRAINT IF EXISTS data_export_requests_format_ck;
ALTER TABLE data_export_requests ADD CONSTRAINT data_export_requests_format_ck
  CHECK (jsonb_typeof("format") = 'array'
     AND jsonb_array_length("format") BETWEEN 1 AND 2
     AND "format" <@ '["json", "csv"]'::jsonb) NOT VALID;

-- ── 状态与必填（M14 §3 / §5）
ALTER TABLE data_export_requests DROP CONSTRAINT IF EXISTS data_export_requests_state_fields_ck;
ALTER TABLE data_export_requests ADD CONSTRAINT data_export_requests_state_fields_ck
  CHECK ((state NOT IN ('approved', 'running', 'done')
          OR (approver IS NOT NULL AND approved_at IS NOT NULL))
     AND (state <> 'done'
          OR (finished_at IS NOT NULL AND expires_at IS NOT NULL AND watermark IS NOT NULL))
     AND (state <> 'failed' OR failure_reason IS NOT NULL)
     AND (approver IS NULL OR approver <> requester)
     AND (expires_at IS NULL OR expires_at > created_at)) NOT VALID;

-- ── 状态机 + 事实字段不可改（域层先判，库层兜底）
CREATE OR REPLACE FUNCTION m14_export_requests_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  allowed BOOLEAN;
BEGIN
  IF NEW.export_no IS DISTINCT FROM OLD.export_no
     OR NEW.requester IS DISTINCT FROM OLD.requester
     OR NEW.requester_tenant IS DISTINCT FROM OLD.requester_tenant
     OR NEW.scope IS DISTINCT FROM OLD.scope
     OR NEW."format" IS DISTINCT FROM OLD."format"
     OR NEW.reason IS DISTINCT FROM OLD.reason
     OR NEW.estimated_rows IS DISTINCT FROM OLD.estimated_rows
     OR NEW.contains_personal_data IS DISTINCT FROM OLD.contains_personal_data
     OR NEW.approval_required IS DISTINCT FROM OLD.approval_required
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'data_export_requests 申请事实字段不可改（只加不改 / INV-04）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := (OLD.state, NEW.state) IN (
      ('pending', 'approved'), ('pending', 'failed'), ('pending', 'expired'),
      ('approved', 'running'), ('approved', 'failed'), ('approved', 'expired'),
      ('running', 'done'), ('running', 'failed'),
      ('done', 'expired'));
    IF NOT COALESCE(allowed, false) THEN
      RAISE EXCEPTION '非法导出状态迁移 % -> %（M14 §3）', OLD.state, NEW.state
        USING ERRCODE = '23514';
    END IF;
  END IF;
  IF NEW.state = 'failed' AND OLD.state IN ('pending', 'approved')
     AND NEW.failure_reason = 'cancelled_by_requester'
     AND (NEW.cancelled_at IS NULL OR NEW.cancelled_by IS NULL) THEN
    RAISE EXCEPTION '取消必须记录 cancelled_at / cancelled_by（取消只对未执行生效）'
      USING ERRCODE = '23514';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION m14_forbid_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'M14 申请 / 任务 / 审计相关行禁止删除（只追加；撤销只改状态）'
    USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION m14_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'M14 表禁止 TRUNCATE（只追加）' USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS data_export_requests_guard ON data_export_requests;
CREATE TRIGGER data_export_requests_guard BEFORE UPDATE ON data_export_requests
  FOR EACH ROW EXECUTE FUNCTION m14_export_requests_guard();
DROP TRIGGER IF EXISTS data_export_requests_no_delete ON data_export_requests;
CREATE TRIGGER data_export_requests_no_delete BEFORE DELETE ON data_export_requests
  FOR EACH ROW EXECUTE FUNCTION m14_forbid_delete();
DROP TRIGGER IF EXISTS data_export_requests_no_truncate ON data_export_requests;
CREATE TRIGGER data_export_requests_no_truncate BEFORE TRUNCATE ON data_export_requests
  FOR EACH STATEMENT EXECUTE FUNCTION m14_forbid_truncate();

-- ── 索引（M14 §5：data_export_requests(requester, created_at)）
DROP INDEX IF EXISTS uq_export_requests_idem;
CREATE UNIQUE INDEX uq_export_requests_idem
  ON data_export_requests (requester, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
DROP INDEX IF EXISTS idx_export_requests_requester_created;
CREATE INDEX idx_export_requests_requester_created
  ON data_export_requests (requester, created_at DESC);
DROP INDEX IF EXISTS idx_export_requests_state_created;
CREATE INDEX idx_export_requests_state_created
  ON data_export_requests (state, created_at DESC);
DROP INDEX IF EXISTS idx_export_requests_large;
CREATE INDEX idx_export_requests_large
  ON data_export_requests (requester, created_at DESC) WHERE approval_required;

-- ── 结构断言（半途建表 / 旧形状被静默放过时直接失败）
DO $$
DECLARE
  missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO missing
    FROM unnest(ARRAY['export_id','export_no','requester','requester_tenant','scope','format',
                      'reason','state','row_count','estimated_rows','contains_personal_data',
                      'approval_required','approver','approved_at','started_at','finished_at',
                      'expires_at','watermark','failure_reason','cancelled_at','cancelled_by',
                      'link_jti','link_consumed_at','idempotency_key','created_at','updated_at'])
      AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'data_export_requests' AND column_name = c);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'data_export_requests 结构与 1301 不符，缺列：%', missing;
  END IF;
END;
$$;

COMMIT;
