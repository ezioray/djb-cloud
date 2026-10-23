-- 1100 · M11 风控规则元数据（risk_rules）
-- 规格：product/v4/modules/M11-risk-abuse.md §3 领域模型 / INV-01 / §5 数据所有权（迁移 1100，长期）
--       §8.1 配置键（数值只在 M10 私有 risk-config）· 00-conventions §7.2（只加列 / 表 / 索引）
--
-- 原则：
--   1) **INV-01 阈值不入库**：本表只有 rule_key / version / enabled / severity / action_class /
--      config_ref——没有任何 threshold / weight / blocklist 列；config_ref 只指向 M10 的 risk.* 键。
--      迁移末尾的结构断言让「以后有人加一列阈值」直接迁移失败（库层兜底，不只靠代码评审）。
--   2) **版本只加不改**：主键 (rule_key, version)；INSERT 新版本，禁止 UPDATE 身份 / 语义列，
--      禁止 DELETE；enable/disable 也走新版本（唯一允许原地改的是 created_at 之外的 enabled？
--      不——enabled 也不允许原地改，见触发器；调用方改开关= 注册新版本）。
--   3) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE / CREATE OR REPLACE；
--      重跑不会报错、不会改变已存在对象的形状。
BEGIN;

CREATE TABLE IF NOT EXISTS risk_rules (
  rule_key        TEXT NOT NULL,                    -- 规则标识（如 self_trade.ratio）
  version         INTEGER NOT NULL,                 -- 版本；同 rule_key 单调递增（只加不改）
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,    -- 是否启用（变更 = 新版本）
  severity        TEXT NOT NULL,                    -- P0 / P1 / P2 / P3
  action_class    TEXT NOT NULL,                    -- observe / throttle / freeze / retire / manual_review
  config_ref      TEXT,                             -- M10 配置键引用（risk.*）；阈值数值只在 M10
  created_by      TEXT NOT NULL,                    -- 注册人（管理面主体）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  idempotency_key TEXT,                             -- 注册幂等键（16..128）
  CONSTRAINT risk_rules_pk PRIMARY KEY (rule_key, version),
  CONSTRAINT risk_rules_key_ck CHECK (char_length(rule_key) BETWEEN 1 AND 128),
  CONSTRAINT risk_rules_version_ck CHECK (version >= 1),
  CONSTRAINT risk_rules_severity_ck CHECK (severity IN ('P0', 'P1', 'P2', 'P3')),
  CONSTRAINT risk_rules_action_ck CHECK (action_class IN
    ('observe', 'throttle', 'freeze', 'retire', 'manual_review')),
  -- INV-01：config_ref 只允许 M10 的 risk.* 命名空间（空 = 纯监控规则，不取阈值）
  CONSTRAINT risk_rules_config_ref_ck CHECK (config_ref IS NULL OR config_ref LIKE 'risk.%')
);

-- 幂等键唯一（只对非空；同键重放返回首次结果）
CREATE UNIQUE INDEX IF NOT EXISTS risk_rules_idem_uq
  ON risk_rules (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS risk_rules_key_idx ON risk_rules (rule_key, version DESC);

COMMENT ON TABLE risk_rules IS
  'M11 规则元数据：不含阈值/权重/名单（INV-01）；阈值只在 M10 私有 risk-config，本表只存 config_ref 与 version';

-- 只追加：禁止 DELETE
CREATE OR REPLACE FUNCTION m11_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '风控表只追加：禁止 TRUNCATE（M11 §5 / 00-conventions §7.5）'
    USING ERRCODE = '42501';
END $$;

-- 版本只加不改：身份列与语义列不可变
CREATE OR REPLACE FUNCTION m11_rules_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'risk_rules 只追加：禁止 DELETE（版本只加不改）' USING ERRCODE = '42501';
  END IF;
  IF NEW.rule_key IS DISTINCT FROM OLD.rule_key
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.enabled IS DISTINCT FROM OLD.enabled
     OR NEW.severity IS DISTINCT FROM OLD.severity
     OR NEW.action_class IS DISTINCT FROM OLD.action_class
     OR NEW.config_ref IS DISTINCT FROM OLD.config_ref
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'risk_rules 版本只加不改：变更须注册新 version（rule_key=%）', OLD.rule_key
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS risk_rules_guard ON risk_rules;
CREATE TRIGGER risk_rules_guard BEFORE UPDATE OR DELETE ON risk_rules
  FOR EACH ROW EXECUTE FUNCTION m11_rules_guard();

DROP TRIGGER IF EXISTS risk_rules_no_truncate ON risk_rules;
CREATE TRIGGER risk_rules_no_truncate BEFORE TRUNCATE ON risk_rules
  FOR EACH STATEMENT EXECUTE FUNCTION m11_forbid_truncate();

-- 结构断言（INV-01 库层兜底）：本表出现阈值 / 权重 / 名单列 → 迁移失败
DO $$
DECLARE bad TEXT;
BEGIN
  SELECT string_agg(column_name, ', ') INTO bad
    FROM information_schema.columns
   WHERE table_schema = current_schema()
     AND table_name = 'risk_rules'
     AND (column_name ~ '(threshold|weight|blocklist|blacklist|allowlist|whitelist|score)');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'INV-01 违规：risk_rules 出现阈值/权重/名单列（%）', bad;
  END IF;
END $$;

COMMIT;
