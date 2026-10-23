-- 1401 · M16 平台基础设施 · 每日 Merkle 根（audit_anchors）
-- 规格：M16-platform-infra.md §3（audit_anchor 聚合：period / merkle_root / sealed_at / alg / evidence_ref）
--       §5 数据所有权（audit_anchors.period 唯一；保留长期）· §6.3（verify --seal 写当日根）
--       ops/audit/verify.mjs --seal 的等价物（从 daily/<date>.root 换成一行锚点）
--
-- 语义：
--   1) **一天一行**：period = UTC 日（YYYY-MM-DD），唯一；同日重复封盘返回首次根（幂等）。
--   2) **只追加**：封盘后不得改删（UPDATE / DELETE / TRUNCATE 拒绝，SQLSTATE 42501）。
--      若重算根与已封盘根不一致 → 说明链在封盘后被改动，verify 报问题（不覆盖锚点）。
--   3) 根算法与 ops/audit/verify.mjs 一致：逐层 SHA256(hex(left) ‖ hex(right))，奇数复制末叶；
--      空日 = 'EMPTY'。算式写在 app/audit/merkle.py 的 docstring 与证据文件里。
BEGIN;

CREATE TABLE IF NOT EXISTS audit_anchors (
  period       TEXT          NOT NULL,                    -- UTC 日 YYYY-MM-DD
  merkle_root  TEXT          NOT NULL,
  sealed_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
  alg          TEXT          NOT NULL DEFAULT 'hmac-sha256',
  evidence_ref TEXT,                                      -- 归档证据引用（路径 / 对象键），不放正文
  entry_count  BIGINT        NOT NULL DEFAULT 0,          -- 当日条目数（只加列；便于证据核对）
  first_seq    BIGINT,
  last_seq     BIGINT,
  CONSTRAINT audit_anchors_period_uq UNIQUE (period)
);

ALTER TABLE audit_anchors DROP CONSTRAINT IF EXISTS audit_anchors_period_ck;
ALTER TABLE audit_anchors ADD CONSTRAINT audit_anchors_period_ck
  CHECK (period ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$') NOT VALID;

ALTER TABLE audit_anchors DROP CONSTRAINT IF EXISTS audit_anchors_root_ck;
ALTER TABLE audit_anchors ADD CONSTRAINT audit_anchors_root_ck
  CHECK (merkle_root = 'EMPTY' OR merkle_root ~ '^[0-9a-f]{64}$') NOT VALID;

ALTER TABLE audit_anchors DROP CONSTRAINT IF EXISTS audit_anchors_alg_ck;
ALTER TABLE audit_anchors ADD CONSTRAINT audit_anchors_alg_ck
  CHECK (alg = 'hmac-sha256') NOT VALID;

ALTER TABLE audit_anchors DROP CONSTRAINT IF EXISTS audit_anchors_count_ck;
ALTER TABLE audit_anchors ADD CONSTRAINT audit_anchors_count_ck
  CHECK (entry_count >= 0
     AND (first_seq IS NULL OR first_seq >= 1)
     AND (last_seq IS NULL OR last_seq >= 1)
     AND (first_seq IS NULL OR last_seq IS NULL OR last_seq >= first_seq)) NOT VALID;

ALTER TABLE audit_anchors DROP CONSTRAINT IF EXISTS audit_anchors_evidence_ck;
ALTER TABLE audit_anchors ADD CONSTRAINT audit_anchors_evidence_ck
  CHECK (evidence_ref IS NULL OR char_length(evidence_ref) BETWEEN 1 AND 512) NOT VALID;

-- 封盘时间线（排障 / 证据）：按日取
CREATE INDEX IF NOT EXISTS audit_anchors_sealed_at_idx
  ON audit_anchors (sealed_at);

-- ────────────────────────────────────────────────────────── 只追加护栏
DROP TRIGGER IF EXISTS audit_anchors_no_mutation ON audit_anchors;
CREATE TRIGGER audit_anchors_no_mutation BEFORE UPDATE OR DELETE ON audit_anchors
  FOR EACH ROW EXECUTE FUNCTION m16_audit_forbid_mutation();

DROP TRIGGER IF EXISTS audit_anchors_no_truncate ON audit_anchors;
CREATE TRIGGER audit_anchors_no_truncate BEFORE TRUNCATE ON audit_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION m16_forbid_truncate();

COMMENT ON TABLE audit_anchors IS
  'M16 每日 Merkle 根（M16 §5 / 迁移 1401）：一天一行、只追加；同日重复封盘幂等';
COMMENT ON COLUMN audit_anchors.merkle_root IS
  'SHA256 二叉 Merkle 根（叶子 = 条目 hash 的 hex）；空日 EMPTY；算式见 app/audit/merkle.py';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'audit_anchors_period_uq' AND connamespace = current_schema()::regnamespace
                    AND conrelid = 'audit_anchors'::regclass) THEN
    RAISE EXCEPTION '1401: 缺唯一约束 audit_anchors_period_uq';
  END IF;
END
$$;

COMMIT;
