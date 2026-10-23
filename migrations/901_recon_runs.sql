-- 901 · M09 对账 · 对账批次（reconciliation_runs）+ 状态机护栏
-- 规格：product/v4/modules/M09-recon-reports.md §3.1 聚合 / §3.2 状态机 / §3.3 不变量
--       （INV-01 diff=未关闭差异之和 · INV-04 同 (scope,subject,period,cutoff) 唯一 run）
--       §5 数据所有权（reconciliation_runs，迁移 9xx，保留 5 年及以上）
--       product/v4/modules/03-facts.md §6（整数最小单位）/ §7（差异档位 / 容差）
--
-- 原则：
--   1) 只加不改：只建 M09 自己的对象，001–006 与 1xx/2xx/4xx/5xx/6xx/10xx/14xx 零改动。
--      对 M06（journal_entry / journal_line / account_balances / merkle_commitments）与
--      M05（usage_records / metering_receipts）**只读**，不建外键、不写、不改列。
--   2) 状态机由库层兜底（§3.2）：DELETE 一律拒绝；closed/signed_off 之后只读
--      （唯一放行 signed_off -> closed）；非法迁移用 23514 拒绝。
--   3) 可变列白名单 = 状态 / 金额差 / 计数 / 签核痕迹 / 报表引用；其余一律不可改，
--      防止「签核后改数字」（§3.2「signed_off 后改数字必须新版本重出」）。
--   4) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE；末尾结构断言保证
--      「已存在的表」与本文件同形，避免半途建表被静默放过。
BEGIN;

-- ────────────────────────────────────────────── 只追加 / 反 TRUNCATE 工具（本段共用）
-- TRUNCATE 绕过行级触发器：只追加表必须用语句级触发器单独拦（与 M05/M06/M16 同款）。
CREATE OR REPLACE FUNCTION m09_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M09 §3.2)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

-- ────────────────────────────────────────────────────────────── 对账批次
CREATE TABLE IF NOT EXISTS reconciliation_runs (
  run_id            UUID PRIMARY KEY,                 -- UUIDv7（00-conventions §2）
  scope             TEXT NOT NULL,                    -- chain / psp / bank / receipt / daily_close
  subject_ref       TEXT,                             -- 对账对象（节点 / 账户 / 钱包 / 单位…）
  period_start      TIMESTAMPTZ NOT NULL,             -- 业务期间 [start, end)
  period_end        TIMESTAMPTZ NOT NULL,
  cutoff_at         TIMESTAMPTZ NOT NULL,             -- 数据截止时刻（唯一键组成部分，INV-04）
  block_height      BIGINT,                           -- scope=chain 用（本轮不实现，留列）
  book_minor        BIGINT NOT NULL DEFAULT 0,        -- 账侧合计（整数最小单位，有符号）
  external_minor    BIGINT NOT NULL DEFAULT 0,        -- 外部侧合计
  diff_minor        BIGINT NOT NULL DEFAULT 0,        -- INV-01：同 run 未关闭差异金额之和
  matched_count     INTEGER NOT NULL DEFAULT 0,
  unmatched_count   INTEGER NOT NULL DEFAULT 0,       -- 本次扫描未匹配条目数（开差异时定稿）
  status            TEXT NOT NULL DEFAULT 'scheduled',
  rule_version      TEXT NOT NULL,                    -- 比较键 / 配对算法口径
  policy_version    TEXT,                             -- 档位 / 容差口径（03-facts §7）
  trigger_event_id  TEXT,                             -- 消费事件幂等（唯一，见下）
  report_ref        TEXT,                             -- 报表引用（T4 渲染后回填）
  metrics           JSONB NOT NULL DEFAULT '{}'::jsonb, -- 扫描口径指标（差异率 / 在途数；追加列）
  tenant_id         TEXT,                             -- 租户维度（追加列；NULL = 平台级）
  created_by        TEXT,                             -- 制单人（签核时要求 ≠ 复核人，INV-05）
  signed_off_by     TEXT,                             -- 复核人
  signed_off_at     TIMESTAMPTZ,
  reviewer_note     TEXT,
  signoff_idempotency_key TEXT,                       -- 签核幂等键（24h；追加列）
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT reconciliation_runs_scope_ck CHECK (
    scope IN ('chain', 'psp', 'bank', 'receipt', 'daily_close')),
  CONSTRAINT reconciliation_runs_status_ck CHECK (
    status IN ('scheduled', 'running', 'matched', 'exceptions_open', 'signed_off', 'closed')),
  CONSTRAINT reconciliation_runs_period_ck CHECK (period_end > period_start),
  CONSTRAINT reconciliation_runs_cutoff_ck CHECK (cutoff_at >= period_start),
  CONSTRAINT reconciliation_runs_counts_ck CHECK (
    matched_count >= 0 AND unmatched_count >= 0),
  CONSTRAINT reconciliation_runs_rule_version_ck CHECK (
    char_length(rule_version) BETWEEN 1 AND 64),
  CONSTRAINT reconciliation_runs_subject_ck CHECK (
    subject_ref IS NULL OR char_length(subject_ref) BETWEEN 1 AND 128),
  -- 签核痕迹与状态成对：signed_off / closed 必须有时间与人；反过来有时间就必须是这两态
  CONSTRAINT reconciliation_runs_signoff_ck CHECK (
    (status IN ('signed_off', 'closed') AND signed_off_at IS NOT NULL
       AND signed_off_by IS NOT NULL)
    OR (status NOT IN ('signed_off', 'closed') AND signed_off_at IS NULL
       AND signed_off_by IS NULL))
);

-- INV-04：同一 (scope, subject_ref, period_start, period_end, cutoff_at) 唯一 run。
-- subject_ref 可空 → 用 COALESCE 表达式索引把 NULL 归一成 ''（不依赖 PG15 的 NULLS NOT DISTINCT）。
CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_runs_unique
  ON reconciliation_runs (scope, COALESCE(subject_ref, ''), period_start, period_end, cutoff_at);

-- 事件幂等：同一触发事件只能落一个 run（§5「trigger_event_id 唯一」）
CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_runs_trigger_uq
  ON reconciliation_runs (trigger_event_id) WHERE trigger_event_id IS NOT NULL;

-- 签核幂等键（24h）：同键重放返回首次结果
CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_runs_signoff_idem_uq
  ON reconciliation_runs (signoff_idempotency_key) WHERE signoff_idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS reconciliation_runs_cutoff_idx
  ON reconciliation_runs (cutoff_at DESC, run_id DESC);
CREATE INDEX IF NOT EXISTS reconciliation_runs_scope_status_idx
  ON reconciliation_runs (scope, status);
CREATE INDEX IF NOT EXISTS reconciliation_runs_metrics_idx
  ON reconciliation_runs USING gin (metrics);
CREATE INDEX IF NOT EXISTS reconciliation_runs_tenant_idx
  ON reconciliation_runs (tenant_id, cutoff_at DESC) WHERE tenant_id IS NOT NULL;

-- ────────────────────────────────────────────── 状态机 + 只读护栏（§3.2）
CREATE OR REPLACE FUNCTION m09_recon_runs_guard() RETURNS trigger AS $$
DECLARE
  v_mutable TEXT[] := ARRAY['status', 'diff_minor', 'matched_count', 'unmatched_count',
                            'report_ref', 'signed_off_at', 'signed_off_by', 'reviewer_note',
                            'signoff_idempotency_key', 'updated_at'];
  v_allowed TEXT[] := ARRAY['scheduled->running', 'running->matched', 'running->exceptions_open',
                            'matched->signed_off', 'matched->exceptions_open',
                            'exceptions_open->matched', 'exceptions_open->signed_off',
                            'signed_off->closed'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'reconciliation_runs is append-only: DELETE not allowed (M09 §3.2)'
      USING ERRCODE = '42501';
  END IF;

  -- 不可变列（含 scope / 期间 / cutoff / 版本口径 / 两侧合计 / 制单人）
  IF (to_jsonb(NEW) - v_mutable) IS DISTINCT FROM (to_jsonb(OLD) - v_mutable) THEN
    RAISE EXCEPTION 'reconciliation_runs: only % may change (M09 §3.2)', v_mutable
      USING ERRCODE = '42501';
  END IF;

  -- 签核 / 关闭后只读：唯一放行 signed_off -> closed（§3.2「closed 后只读」）
  IF OLD.status IN ('signed_off', 'closed') THEN
    IF NEW.status IS DISTINCT FROM OLD.status
       AND NOT (OLD.status = 'signed_off' AND NEW.status = 'closed') THEN
      RAISE EXCEPTION 'reconciliation_runs: % -> % not allowed after sign-off (M09 §3.2)',
        OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['status', 'updated_at'])
       IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'updated_at']) THEN
      RAISE EXCEPTION 'reconciliation_runs is read-only after sign-off (M09 §3.2)'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  -- 状态迁移白名单（非法迁移是契约错误，不是权限问题 → 23514）
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'reconciliation_runs: illegal transition % -> % (M09 §3.2)',
      OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reconciliation_runs_guard ON reconciliation_runs;
CREATE TRIGGER reconciliation_runs_guard BEFORE UPDATE OR DELETE ON reconciliation_runs
  FOR EACH ROW EXECUTE FUNCTION m09_recon_runs_guard();
DROP TRIGGER IF EXISTS reconciliation_runs_no_truncate ON reconciliation_runs;
CREATE TRIGGER reconciliation_runs_no_truncate BEFORE TRUNCATE ON reconciliation_runs
  FOR EACH STATEMENT EXECUTE FUNCTION m09_forbid_truncate();

-- ────────────────────────────────────────────── 结构断言（半途建表不得静默放过）
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['run_id','scope','subject_ref','period_start','period_end','cutoff_at',
                      'block_height','book_minor','external_minor','diff_minor','matched_count',
                      'unmatched_count','status','rule_version','policy_version',
                      'trigger_event_id','report_ref','metrics','tenant_id','created_by',
                      'signed_off_by',
                      'signed_off_at','reviewer_note','signoff_idempotency_key','created_at',
                      'updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'reconciliation_runs'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'reconciliation_runs 结构与 901 不符，缺列：%', v_missing;
  END IF;
  IF to_regclass('reconciliation_runs_unique') IS NULL THEN
    RAISE EXCEPTION 'reconciliation_runs 缺 INV-04 唯一索引（901）';
  END IF;
END;
$$;

COMMIT;
