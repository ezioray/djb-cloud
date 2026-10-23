-- 1102 · M11 案件（risk_cases）+ 只读视图 v_risk_case_summary
-- 规格：M11-risk-abuse.md §3 案件状态机 · INV-03 / INV-04 / INV-05 / INV-06 / INV-07
--       §5 数据所有权（迁移 1102，保留 ≥5 年）· §6 流程 2
--
-- 原则：
--   1) **INV-03 证据必填**：evidence_refs 至少 1 条（DB CHECK 兜底），无证据不得开案 / 终局处置；
--   2) **INV-06 未结唯一**：部分唯一索引 uq_cases_open(subject_hash, risk_type)
--      WHERE status NOT IN ('closed','merged','dismissed')——重复触发在库层就写不进第二条；
--   3) **INV-05 零 PII**：subject_hash 只存加盐哈希 / 簇 ID；CHECK 拒绝邮箱 / IPv4 / 手机号形态；
--   4) **INV-01 零阈值**：本表只有 rule_key / rule_version / config_ref 引用，没有阈值 / 权重列；
--      迁移末尾结构断言兜底；
--   5) 处置历史只追加：decisions JSONB 由触发器保证不可删除 / 不可改写（INV-07 留痕）；
--   6) 终态（closed / merged / dismissed）不可再迁移；禁止 DELETE（保留 ≥5 年）。
BEGIN;

-- 逐案编号：RC-YYYYMMDD-NNNNNN（序列连续、不复用）
CREATE SEQUENCE IF NOT EXISTS risk_case_no_seq;

CREATE TABLE IF NOT EXISTS risk_cases (
  case_id        UUID PRIMARY KEY,
  case_no        TEXT NOT NULL UNIQUE
                 DEFAULT ('RC-' || to_char(now(), 'YYYYMMDD') || '-' ||
                          lpad(nextval('risk_case_no_seq')::text, 6, '0')),
  tenant_id      TEXT NOT NULL,                     -- 隔离域；跨租户一律 404
  subject_type   TEXT NOT NULL DEFAULT 'account',   -- account / node / key / address
  subject_hash   TEXT NOT NULL,                     -- 加盐哈希 / 簇 ID（INV-05，不存明文）
  risk_type      TEXT NOT NULL,                     -- §5 枚举（9 类）
  severity       TEXT NOT NULL,                     -- P0 / P1 / P2 / P3
  status         TEXT NOT NULL DEFAULT 'opened',    -- 状态机见 §3
  rule_key       TEXT,                              -- 命中规则引用（元数据，不含阈值）
  rule_version   INTEGER,                           -- 命中时规则版本（INV-01 只留版本）
  config_ref     TEXT,                              -- M10 risk.* 引用（阈值仍在 M10）
  evidence_refs  TEXT[] NOT NULL,                   -- ≥1 条：事件 id / 收据 id / 交易号 / 举报单
  decision       TEXT,                              -- 最近一次处置动作
  decisions      JSONB NOT NULL DEFAULT '[]'::jsonb, -- 处置历史（只追加，INV-07 留痕）
  decided_by     TEXT,                              -- 最近一次处置人
  decided_at     TIMESTAMPTZ,
  proposal_id    UUID,                              -- risk.action.requested 的 event_id
  merged_into    UUID,                              -- 并案目标（status='merged' 时必填）
  opened_by      TEXT NOT NULL,                     -- 开案主体（SoD：开案人不得自行终局处置）
  opened_at      TIMESTAMPTZ NOT NULL,
  closed_at      TIMESTAMPTZ,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT risk_cases_subject_type_ck CHECK
    (subject_type IN ('account', 'node', 'key', 'address')),
  CONSTRAINT risk_cases_risk_type_ck CHECK (risk_type IN
    ('self_trade', 'wash_volume', 'sybil', 'malicious_occupancy', 'receipt_mismatch',
     'key_leak', 'chargeback_abuse', 'payout_address', 'content_abuse')),
  CONSTRAINT risk_cases_severity_ck CHECK (severity IN ('P0', 'P1', 'P2', 'P3')),
  CONSTRAINT risk_cases_status_ck CHECK (status IN
    ('opened', 'triaged', 'actioned', 'appealed', 'in_review', 'closed', 'merged', 'dismissed')),
  CONSTRAINT risk_cases_decision_ck CHECK (decision IS NULL OR decision IN
    ('freeze', 'unfreeze', 'retire_proposal', 'dismiss', 'merge', 'close')),
  -- INV-03：每个案件至少 1 条证据引用
  CONSTRAINT risk_cases_evidence_ck CHECK (cardinality(evidence_refs) >= 1),
  -- INV-05：subject_hash 不得是明文邮箱 / IPv4 / 手机号（允许 sha256:… / cluster:… / 不透明 id）
  CONSTRAINT risk_cases_subject_hash_ck CHECK (
    char_length(subject_hash) BETWEEN 3 AND 128
    AND subject_hash !~ '@'
    AND subject_hash !~ '^\d{1,3}(\.\d{1,3}){3}$'
    AND subject_hash !~ '^1[3-9]\d{9}$'),
  -- INV-01：config_ref 只允许 M10 risk.* 命名空间
  CONSTRAINT risk_cases_config_ref_ck CHECK (config_ref IS NULL OR config_ref LIKE 'risk.%'),
  CONSTRAINT risk_cases_merged_ck CHECK (status <> 'merged' OR merged_into IS NOT NULL),
  CONSTRAINT risk_cases_closed_ck CHECK
    (status NOT IN ('closed', 'merged', 'dismissed') OR closed_at IS NOT NULL),
  CONSTRAINT risk_cases_rule_version_ck CHECK (rule_version IS NULL OR rule_version >= 1)
);

-- INV-06：同 subject + risk_type 的未结案件唯一（部分唯一索引，按 §5 命名）
CREATE UNIQUE INDEX IF NOT EXISTS uq_cases_open
  ON risk_cases (subject_hash, risk_type)
  WHERE status NOT IN ('closed', 'merged', 'dismissed');
CREATE INDEX IF NOT EXISTS idx_cases_status ON risk_cases (status, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_subject ON risk_cases (subject_hash, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_tenant ON risk_cases (tenant_id, status, opened_at DESC);

COMMENT ON TABLE risk_cases IS
  'M11 案件：证据 ≥1（INV-03）；同主体同类型未结唯一（INV-06）；只存哈希（INV-05）；阈值只留 config_ref（INV-01）';

-- 终态不可再迁移 + 处置历史只追加 + 身份字段不可变 + 禁止 DELETE
CREATE OR REPLACE FUNCTION m11_cases_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'risk_cases 只追加：禁止 DELETE（案件保留 ≥5 年）' USING ERRCODE = '42501';
  END IF;
  IF NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.case_no IS DISTINCT FROM OLD.case_no
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.subject_type IS DISTINCT FROM OLD.subject_type
     OR NEW.subject_hash IS DISTINCT FROM OLD.subject_hash
     OR NEW.risk_type IS DISTINCT FROM OLD.risk_type
     OR NEW.opened_by IS DISTINCT FROM OLD.opened_by
     OR NEW.opened_at IS DISTINCT FROM OLD.opened_at THEN
    RAISE EXCEPTION 'risk_cases 身份字段不可变（只允许状态 / 处置推进）' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('closed', 'merged', 'dismissed') AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'risk_cases 终态不可再迁移：% → %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;
  IF NOT (NEW.decisions @> OLD.decisions) THEN
    RAISE EXCEPTION 'risk_cases.decisions 只追加：不得删除或改写历史处置（INV-07）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.evidence_refs IS DISTINCT FROM OLD.evidence_refs
     AND NOT (NEW.evidence_refs @> OLD.evidence_refs) THEN
    RAISE EXCEPTION 'risk_cases.evidence_refs 只追加：不得删除已有证据（INV-03）'
      USING ERRCODE = '42501';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS risk_cases_guard ON risk_cases;
CREATE TRIGGER risk_cases_guard BEFORE UPDATE OR DELETE ON risk_cases
  FOR EACH ROW EXECUTE FUNCTION m11_cases_guard();

DROP TRIGGER IF EXISTS risk_cases_no_truncate ON risk_cases;
CREATE TRIGGER risk_cases_no_truncate BEFORE TRUNCATE ON risk_cases
  FOR EACH STATEMENT EXECUTE FUNCTION m11_forbid_truncate();

-- 只读视图：仅状态与计数（不含主体 / 证据 / 处置人——对外聚合用）
CREATE OR REPLACE VIEW v_risk_case_summary AS
  SELECT risk_type,
         severity,
         status,
         count(*)          AS case_count,
         min(opened_at)    AS first_opened_at,
         max(closed_at)    AS last_closed_at
    FROM risk_cases
   GROUP BY risk_type, severity, status;

COMMENT ON VIEW v_risk_case_summary IS
  'M11 只读视图：案件状态与计数（不含主体 / 证据 / 处置人）';

-- 结构断言（INV-01 库层兜底）
DO $$
DECLARE bad TEXT;
BEGIN
  SELECT string_agg(column_name, ', ') INTO bad
    FROM information_schema.columns
   WHERE table_schema = current_schema()
     AND table_name = 'risk_cases'
     AND (column_name ~ '(threshold|weight|blocklist|blacklist|allowlist|whitelist|score)');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'INV-01 违规：risk_cases 出现阈值/权重/名单列（%）', bad;
  END IF;
END $$;

COMMIT;
