-- 902 · M09 对账 · 差异台账（reconciliation_exceptions）+ INV-01 差同步 + INV-02 结构断言
-- 规格：M09-recon-reports.md §3.1 / §3.2 状态机 / §3.3 不变量
--       INV-01 diff_minor = 同 run 未关闭差异金额之和 → 由触发器实时同步，应用层无法写坏
--       INV-02 结构性差异一律 P0，与金额无关 → 库层 CHECK（kind 属白名单就必须 P0）
--       §5「差异 (run_id, status, sla_due)」索引 · 保留 5 年及以上
--
-- 原则：
--   1) 只加不改：本表只引用 reconciliation_runs(run_id)（同模块内 FK），不碰 M05/M06 表。
--   2) 差异不删（§3.1「open 到 closed；不删」）：DELETE 一律拒绝，closed 后不可重开。
--   3) 关闭必须有处置码 + 时间；adjust_journal 必须回填已入账的 journal_id（§6.2）。
BEGIN;

-- ────────────────────────────────────────────────────────────── 差异台账
CREATE TABLE IF NOT EXISTS reconciliation_exceptions (
  exception_id      UUID PRIMARY KEY,                 -- UUIDv7
  run_id            UUID NOT NULL REFERENCES reconciliation_runs(run_id),
  scope             TEXT NOT NULL,                    -- 冗余自 run（查询免 JOIN；写入时校验）
  kind              TEXT NOT NULL,                    -- receipt 5 类 / daily_close 2 类 / payment 9 类(T4)
  severity          TEXT NOT NULL,                    -- P0 / P1 / P2（03-facts §7）
  ref_type          TEXT,                             -- usage / receipt / node / unit_type / account …
  ref_id            TEXT,
  diff_minor        BIGINT NOT NULL DEFAULT 0,        -- 有符号：book - external
  owner             TEXT,                             -- 处置责任人（SLA 看板按人）
  sla_due           TIMESTAMPTZ NOT NULL,             -- 首响截止（分级模块算，§8.2）
  status            TEXT NOT NULL DEFAULT 'open',
  resolution_code   TEXT,                             -- adjust_journal / external_fix / write_off / false_positive
  resolution_journal_id TEXT,                         -- M06 调整分录（本模块只持引用，不写账本）
  root_cause        TEXT,
  evidence_ref      TEXT,
  resolved_by       TEXT,                             -- 处置人（与复核人分离留 T4 合同字段）
  resolve_idempotency_key TEXT,                       -- 处置幂等键（24h；追加列）
  closed_at         TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT reconciliation_exceptions_scope_ck CHECK (
    scope IN ('chain', 'psp', 'bank', 'receipt', 'daily_close')),
  CONSTRAINT reconciliation_exceptions_severity_ck CHECK (severity IN ('P0', 'P1', 'P2')),
  CONSTRAINT reconciliation_exceptions_status_ck CHECK (
    status IN ('open', 'investigating', 'escalated', 'resolved', 'accepted', 'closed')),
  CONSTRAINT reconciliation_exceptions_resolution_ck CHECK (
    resolution_code IS NULL
    OR resolution_code IN ('adjust_journal', 'external_fix', 'write_off', 'false_positive')),
  -- 关闭态与关闭时间成对：关闭必须有处置码与时间；未关闭不得有 closed_at
  CONSTRAINT reconciliation_exceptions_closed_ck CHECK (
    (status = 'closed' AND closed_at IS NOT NULL AND resolution_code IS NOT NULL)
    OR (status <> 'closed' AND closed_at IS NULL)),
  -- 调整分录必须回填 journal_id（§6.2 第 1 步）
  CONSTRAINT reconciliation_exceptions_journal_ck CHECK (
    resolution_code IS DISTINCT FROM 'adjust_journal' OR resolution_journal_id IS NOT NULL),
  CONSTRAINT reconciliation_exceptions_ref_ck CHECK (
    ref_id IS NULL OR char_length(ref_id) BETWEEN 1 AND 128),
  -- INV-02：结构性差异一律 P0，与金额无关（库层兜底，应用层写错也进不来）
  CONSTRAINT reconciliation_exceptions_structural_p0_ck CHECK (
    kind NOT IN ('signature_bad', 'only_node', 'duplicate_receipt', 'trial_imbalance',
                 'balance_drift')
    OR severity = 'P0')
);

-- §5：「差异 (run_id, status, sla_due)」—— 未结差异看板 / 签核阻断查询的主索引
CREATE INDEX IF NOT EXISTS reconciliation_exceptions_run_status_due_idx
  ON reconciliation_exceptions (run_id, status, sla_due);
CREATE INDEX IF NOT EXISTS reconciliation_exceptions_severity_status_idx
  ON reconciliation_exceptions (severity, status, sla_due);
CREATE INDEX IF NOT EXISTS reconciliation_exceptions_owner_idx
  ON reconciliation_exceptions (owner, status) WHERE owner IS NOT NULL;
CREATE INDEX IF NOT EXISTS reconciliation_exceptions_created_idx
  ON reconciliation_exceptions (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_exceptions_resolve_idem_uq
  ON reconciliation_exceptions (resolve_idempotency_key)
  WHERE resolve_idempotency_key IS NOT NULL;

-- ────────────────────────────────────────────── 状态机 + 不可变列护栏（§3.2）
CREATE OR REPLACE FUNCTION m09_exceptions_guard() RETURNS trigger AS $$
DECLARE
  v_mutable TEXT[] := ARRAY['status', 'resolution_code', 'resolution_journal_id', 'root_cause',
                            'evidence_ref', 'resolved_by', 'resolve_idempotency_key',
                            'closed_at', 'updated_at'];
  v_allowed TEXT[] := ARRAY['open->investigating', 'open->escalated', 'open->resolved',
                            'open->accepted', 'open->closed',
                            'investigating->escalated', 'investigating->resolved',
                            'investigating->accepted', 'investigating->closed',
                            'escalated->investigating', 'escalated->resolved',
                            'escalated->accepted', 'escalated->closed',
                            'resolved->closed', 'accepted->closed'];
  v_run_status TEXT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'reconciliation_exceptions is append-only: DELETE not allowed (M09 §3.1)'
      USING ERRCODE = '42501';
  END IF;

  IF (to_jsonb(NEW) - v_mutable) IS DISTINCT FROM (to_jsonb(OLD) - v_mutable) THEN
    RAISE EXCEPTION 'reconciliation_exceptions: only % may change (M09 §3.1)', v_mutable
      USING ERRCODE = '42501';
  END IF;

  -- 父 run 已签核 / 关闭 → 差异只读（§3.2「signed_off 后改数字必须新版本重出」）
  SELECT status INTO v_run_status FROM reconciliation_runs WHERE run_id = OLD.run_id;
  IF v_run_status IN ('signed_off', 'closed') THEN
    RAISE EXCEPTION 'reconciliation_exceptions is read-only: run % is % (M09 §3.2)',
      OLD.run_id, v_run_status USING ERRCODE = '42501';
  END IF;

  -- closed 后不可重开；非法迁移是契约错误（23514）
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'reconciliation_exceptions: illegal transition % -> % (M09 §3.2)',
      OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reconciliation_exceptions_guard ON reconciliation_exceptions;
CREATE TRIGGER reconciliation_exceptions_guard BEFORE UPDATE OR DELETE
  ON reconciliation_exceptions FOR EACH ROW EXECUTE FUNCTION m09_exceptions_guard();

-- 也拦 INSERT：已签核 / 已关闭的 run 不得再补差异（否则签核后的数字会被追加而无人复核）
CREATE OR REPLACE FUNCTION m09_exceptions_insert_guard() RETURNS trigger AS $$
DECLARE
  v_run_status TEXT;
  v_run_scope TEXT;
BEGIN
  SELECT status, scope INTO v_run_status, v_run_scope
    FROM reconciliation_runs WHERE run_id = NEW.run_id;
  IF v_run_status IS NULL THEN
    RAISE EXCEPTION 'reconciliation_exceptions: run % 不存在', NEW.run_id
      USING ERRCODE = '23503';
  END IF;
  IF v_run_status IN ('signed_off', 'closed') THEN
    RAISE EXCEPTION 'reconciliation_exceptions: run % 已 %，不得新增差异 (M09 §3.2)',
      NEW.run_id, v_run_status USING ERRCODE = '42501';
  END IF;
  IF NEW.scope IS DISTINCT FROM v_run_scope THEN
    RAISE EXCEPTION 'reconciliation_exceptions: scope % 与 run scope % 不一致',
      NEW.scope, v_run_scope USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reconciliation_exceptions_insert_guard ON reconciliation_exceptions;
CREATE TRIGGER reconciliation_exceptions_insert_guard BEFORE INSERT ON reconciliation_exceptions
  FOR EACH ROW EXECUTE FUNCTION m09_exceptions_insert_guard();
DROP TRIGGER IF EXISTS reconciliation_exceptions_no_truncate ON reconciliation_exceptions;
CREATE TRIGGER reconciliation_exceptions_no_truncate BEFORE TRUNCATE ON reconciliation_exceptions
  FOR EACH STATEMENT EXECUTE FUNCTION m09_forbid_truncate();

-- ───────────────────────────────────── INV-01：run.diff_minor 恒等于「未关闭差异之和」
-- 应用层不需要（也不允许）自己维护差：任何差异行的插入 / 状态变化都由本触发器重算。
CREATE OR REPLACE FUNCTION m09_sync_run_diff() RETURNS trigger AS $$
DECLARE
  v_run UUID;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_run := OLD.run_id;
  ELSE
    v_run := NEW.run_id;
  END IF;

  UPDATE reconciliation_runs r
     SET diff_minor = COALESCE((
           SELECT sum(e.diff_minor) FROM reconciliation_exceptions e
            WHERE e.run_id = v_run AND e.status <> 'closed'), 0),
         updated_at = now()
   WHERE r.run_id = v_run AND r.status NOT IN ('signed_off', 'closed');
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reconciliation_exceptions_diff_sync ON reconciliation_exceptions;
CREATE TRIGGER reconciliation_exceptions_diff_sync
  AFTER INSERT OR UPDATE OR DELETE ON reconciliation_exceptions
  FOR EACH ROW EXECUTE FUNCTION m09_sync_run_diff();

-- ────────────────────────────────────────────── 只读视图（M09 §5：视图命名 v_m09_*）
-- 未结差异（open / investigating / escalated）—— 签核阻断与 REP-02 的统一口径
CREATE OR REPLACE VIEW v_m09_open_exceptions AS
  SELECT e.exception_id, e.run_id, e.scope, e.kind, e.severity, e.ref_type, e.ref_id,
         e.diff_minor, e.owner, e.sla_due, e.status, e.created_at,
         (e.sla_due < now()) AS overdue,
         r.period_start, r.period_end, r.cutoff_at, r.tenant_id
    FROM reconciliation_exceptions e
    JOIN reconciliation_runs r ON r.run_id = e.run_id
   WHERE e.status <> 'closed';

-- 批次 + 差异汇总（详情接口 / REP-01 共用；口径只在这里写一次）
CREATE OR REPLACE VIEW v_m09_run_diff AS
  SELECT r.run_id, r.scope, r.status,
         count(*) FILTER (WHERE e.status <> 'closed')                              AS open_count,
         count(*) FILTER (WHERE e.status <> 'closed' AND e.severity IN ('P0','P1')) AS pending_p0_p1,
         count(*) FILTER (WHERE e.status <> 'closed' AND e.severity = 'P0')        AS open_p0,
         count(*) FILTER (WHERE e.status <> 'closed' AND e.severity = 'P1')        AS open_p1,
         count(*) FILTER (WHERE e.status <> 'closed' AND e.severity = 'P2')        AS open_p2,
         COALESCE(sum(e.diff_minor) FILTER (WHERE e.status <> 'closed'), 0)        AS open_diff_minor,
         count(*)                                                                   AS total_count
    FROM reconciliation_runs r
    LEFT JOIN reconciliation_exceptions e ON e.run_id = r.run_id
   GROUP BY r.run_id, r.scope, r.status;

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['exception_id','run_id','scope','kind','severity','ref_type','ref_id',
                      'diff_minor','owner','sla_due','status','resolution_code',
                      'resolution_journal_id','root_cause','evidence_ref','resolved_by',
                      'resolve_idempotency_key','closed_at','created_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'reconciliation_exceptions'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'reconciliation_exceptions 结构与 902 不符，缺列：%', v_missing;
  END IF;
  IF to_regclass('reconciliation_exceptions_run_status_due_idx') IS NULL THEN
    RAISE EXCEPTION 'reconciliation_exceptions 缺 (run_id, status, sla_due) 索引（902 / §5）';
  END IF;
END;
$$;

COMMIT;
