-- 1103 · M11 申诉（risk_appeals）
-- 规格：M11-risk-abuse.md §3（申诉状态机：submitted → in_review → upheld / overturned → closed）
--       §6 流程 3（30 天提交窗口 / 7 个工作日 SLA，超期自动升级 P1）
--       §5 数据所有权（迁移 1103，保留 ≥5 年）· INV-04（申诉期内不得清退）
--
-- 原则：
--   1) 同一案件同一时刻最多 1 条未结申诉（部分唯一索引 uq_appeals_open）——重复申诉 409/48003；
--   2) 提交窗口与 SLA 由应用层判定（APPEAL_WINDOW_D=30 / APPEAL_SLA_WORKDAYS=7），
--      本表只存时间事实（submitted_at / sla_due / closed_at），不存阈值；
--   3) 裁决人 ≠ 原处置人由应用层 403/48006 判定；本表记录 decided_by 供审计追溯；
--   4) 只追加：禁止 DELETE（案件 / 申诉保留 ≥5 年）。
BEGIN;

CREATE TABLE IF NOT EXISTS risk_appeals (
  appeal_id      UUID PRIMARY KEY,
  case_id        UUID NOT NULL REFERENCES risk_cases (case_id),
  tenant_id      TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'submitted',   -- submitted / in_review / upheld / overturned / closed
  reason         TEXT NOT NULL,                       -- 申诉理由（1..512，不含 PII 要求见 INV-05）
  submitted_at   TIMESTAMPTZ NOT NULL,
  sla_due        TIMESTAMPTZ NOT NULL,                -- 7 个工作日后（超期自动升级 P1）
  escalated_at   TIMESTAMPTZ,                         -- 超 SLA 升级时刻（P1）
  outcome        TEXT,                                -- upheld / overturned
  decision_reason TEXT,                               -- 裁决理由（INV-07 留痕）
  decided_by     TEXT,
  decided_at     TIMESTAMPTZ,
  closed_at      TIMESTAMPTZ,
  idempotency_key TEXT,                               -- 裁决幂等键（同键重放返回首次结果）
  recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT risk_appeals_status_ck CHECK
    (status IN ('submitted', 'in_review', 'upheld', 'overturned', 'closed')),
  CONSTRAINT risk_appeals_outcome_ck CHECK
    (outcome IS NULL OR outcome IN ('upheld', 'overturned')),
  CONSTRAINT risk_appeals_reason_ck CHECK (char_length(reason) BETWEEN 1 AND 512),
  CONSTRAINT risk_appeals_decision_reason_ck CHECK
    (decision_reason IS NULL OR char_length(decision_reason) BETWEEN 1 AND 512),
  CONSTRAINT risk_appeals_sla_ck CHECK (sla_due > submitted_at),
  CONSTRAINT risk_appeals_decided_ck CHECK (
    (status IN ('submitted', 'in_review')
       AND outcome IS NULL AND decided_by IS NULL AND decided_at IS NULL AND closed_at IS NULL)
    OR
    (status IN ('upheld', 'overturned', 'closed')
       AND outcome IS NOT NULL AND decided_by IS NOT NULL AND decided_at IS NOT NULL
       AND closed_at IS NOT NULL))
);

-- 重复申诉（同一案件同时最多 1 条未结）→ 409 / 48003
CREATE UNIQUE INDEX IF NOT EXISTS uq_appeals_open
  ON risk_appeals (case_id) WHERE status IN ('submitted', 'in_review');
-- SLA 扫描（超期未答复 → 升级 P1）
CREATE INDEX IF NOT EXISTS idx_appeals_sla
  ON risk_appeals (sla_due) WHERE status IN ('submitted', 'in_review');
CREATE UNIQUE INDEX IF NOT EXISTS risk_appeals_idem_uq
  ON risk_appeals (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_appeals_case ON risk_appeals (case_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_appeals_tenant ON risk_appeals (tenant_id, status, sla_due);

COMMENT ON TABLE risk_appeals IS
  'M11 申诉：30 天窗口 / 7 工作日 SLA / 裁决人≠原处置人；只追加保留 ≥5 年';

CREATE OR REPLACE FUNCTION m11_appeals_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'risk_appeals 只追加：禁止 DELETE（保留 ≥5 年）' USING ERRCODE = '42501';
  END IF;
  IF NEW.appeal_id IS DISTINCT FROM OLD.appeal_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.reason IS DISTINCT FROM OLD.reason
     OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
     OR NEW.sla_due IS DISTINCT FROM OLD.sla_due THEN
    RAISE EXCEPTION 'risk_appeals 身份字段不可变（只允许状态 / 裁决推进）' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('upheld', 'overturned', 'closed') AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'risk_appeals 终态不可再迁移：% → %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS risk_appeals_guard ON risk_appeals;
CREATE TRIGGER risk_appeals_guard BEFORE UPDATE OR DELETE ON risk_appeals
  FOR EACH ROW EXECUTE FUNCTION m11_appeals_guard();

DROP TRIGGER IF EXISTS risk_appeals_no_truncate ON risk_appeals;
CREATE TRIGGER risk_appeals_no_truncate BEFORE TRUNCATE ON risk_appeals
  FOR EACH STATEMENT EXECUTE FUNCTION m11_forbid_truncate();

COMMIT;
