-- 1400 · M16 平台基础设施 · 审计链热表（audit_log）
-- 规格：product/v4/modules/M16-platform-infra.md §3（audit_entry 聚合 / INV-M16-01/02）
--       §5 数据所有权（audit_log 的列 / 索引 / 保留）· §6.3 审计链流程 · §9 迁移验收
--       product/v4/modules/00-conventions.md §7.5（审计表只追加，不删）
--       product/v4/modules/05-security-observability.md S10（关键动作写审计链、不可自删）
--       spec-1.2.2 components.schemas.AuditEntry / AuditAppendRequest
--
-- 语义（与 ops/audit/append.mjs + verify.mjs 一致，只是从 JSONL 文件换成数据库热表）：
--   1) **只追加**：UPDATE / DELETE / TRUNCATE 一律拒绝（触发器，SQLSTATE 42501）。
--      保留期不靠热表删除，靠分区归档到 WORM（M16 §5「超期通过分区归档，不在热表 UPDATE/DELETE」）。
--   2) **唯一**：seq 主键、entry_id 唯一、hash 唯一、idempotency_key 唯一（幂等命中返回首次结果）。
--   3) **链**：alg 固定 'hmac-sha256'（spec AuditEntry.alg 唯一枚举值）；首条 prev_hash = 'GENESIS'；
--      hash / prev_hash 为 64 位小写 hex。哈希算式在 app/audit/canonical.py，库里只兜底"形状"。
--   4) **不存密钥 / 正文**：无 prompt / response / 金额列；before / after 只放运维事实（M16 §1「不做」）。
--   5) 幂等键是**传输元数据**：参与不了链哈希（spec AuditEntry 无此字段），只做写入去重。
BEGIN;

CREATE TABLE IF NOT EXISTS audit_log (
  seq             BIGINT         NOT NULL,
  entry_id        UUID           NOT NULL,
  ts              TIMESTAMPTZ(6) NOT NULL,                 -- 事实发生时间（UTC，微秒精度）
  actor           TEXT           NOT NULL,
  actor_type      TEXT           NOT NULL,
  role            TEXT           NOT NULL,
  action          TEXT           NOT NULL,                 -- 点分动作名（authorize.window …）
  target          TEXT           NOT NULL,
  before          JSONB,
  after           JSONB,
  reason_code     TEXT,
  ticket          TEXT,
  evidence        TEXT,                                    -- spec: string（路径 / 证据引用，非正文）
  approval_chain  JSONB          NOT NULL DEFAULT '[]'::jsonb,
  status          TEXT           NOT NULL DEFAULT 'recorded',
  alg             TEXT           NOT NULL,
  prev_hash       TEXT           NOT NULL,
  hash            TEXT           NOT NULL,
  idempotency_key TEXT,                                    -- 写入幂等键（scope=audit.append）
  created_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),   -- 落库时刻（不等于事实发生时间 ts）
  CONSTRAINT audit_log_pkey PRIMARY KEY (seq)
);

-- 枚举 / 形状兜底（NOT VALID：新表无存量行，后续插入仍逐行校验）
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_seq_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_seq_ck
  CHECK (seq >= 1) NOT VALID;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_alg_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_alg_ck
  CHECK (alg = 'hmac-sha256') NOT VALID;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_actor_type_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_type_ck
  CHECK (actor_type IN ('human', 'agent', 'service', 'lead')) NOT VALID;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_status_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_status_ck
  CHECK (status IN ('recorded', 'pending_approval', 'approved', 'rejected', 'revoked')) NOT VALID;

-- 链哈希形状：64 位小写 hex；prev_hash 允许首条 GENESIS
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_hash_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_hash_ck
  CHECK (hash ~ '^[0-9a-f]{64}$'
     AND (prev_hash = 'GENESIS' OR prev_hash ~ '^[0-9a-f]{64}$')) NOT VALID;

-- 文本长度（防止把正文 / 大块数据塞进审计表；证据用路径引用）
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_text_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_text_ck
  CHECK (char_length(actor) BETWEEN 1 AND 128
     AND char_length(role) BETWEEN 1 AND 64
     AND char_length(action) BETWEEN 1 AND 64
     AND char_length(target) BETWEEN 1 AND 256
     AND (reason_code IS NULL OR char_length(reason_code) BETWEEN 1 AND 64)
     AND (ticket IS NULL OR char_length(ticket) BETWEEN 1 AND 64)
     AND (evidence IS NULL OR char_length(evidence) BETWEEN 1 AND 512)
     AND (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 16 AND 128))
  NOT VALID;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_json_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_json_ck
  CHECK ((before IS NULL OR jsonb_typeof(before) = 'object')
     AND (after IS NULL OR jsonb_typeof(after) = 'object')
     AND jsonb_typeof(approval_chain) = 'array') NOT VALID;

-- 索引（M16 §5）：seq / entry_id / hash 唯一，另有 (action, target, ts)
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_entry_id_uq
  ON audit_log (entry_id);

CREATE UNIQUE INDEX IF NOT EXISTS audit_log_hash_uq
  ON audit_log (hash);

-- 幂等键唯一（scope = audit.append，表本身即 scope）
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_idempotency_uq
  ON audit_log (idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_log_action_target_ts_idx
  ON audit_log (action, target, ts);

-- 日根 / 归档按 UTC 日扫 ts
CREATE INDEX IF NOT EXISTS audit_log_ts_idx
  ON audit_log (ts);

-- ────────────────────────────────────────────────────────── 只追加护栏
CREATE OR REPLACE FUNCTION m16_audit_forbid_mutation() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'audit_log is append-only: UPDATE not allowed (M16 INV-M16-01)'
      USING ERRCODE = '42501';
  END IF;
  RAISE EXCEPTION 'audit_log is append-only: DELETE not allowed (M16 INV-M16-01)'
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_mutation ON audit_log;
CREATE TRIGGER audit_log_no_mutation BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION m16_audit_forbid_mutation();

CREATE OR REPLACE FUNCTION m16_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M16 INV-M16-01)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION m16_forbid_truncate();

COMMENT ON TABLE audit_log IS
  'M16 审计链热表（M16 §5 / 迁移 1400）：只追加；HMAC-SHA256 哈希链；retention 走 WORM 归档';
COMMENT ON COLUMN audit_log.hash IS
  'hmac_sha256(key, prev_hash + LF + canonical_json(entry 去掉 hash))；算式见 app/audit/canonical.py';
COMMENT ON COLUMN audit_log.prev_hash IS
  '上一条 hash；链首固定 GENESIS';
COMMENT ON COLUMN audit_log.idempotency_key IS
  '写入幂等键（X-DJB-Idempotency-Key，24h；缺省按请求体指纹 300s）。不参与链哈希';

-- 自检：迁移后对象必须存在（空库 / 重复执行都成立）
DO $$
BEGIN
  IF to_regclass('audit_log') IS NULL THEN
    RAISE EXCEPTION '1400: audit_log 未创建';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                   AND indexname = 'audit_log_action_target_ts_idx') THEN
    RAISE EXCEPTION '1400: 缺索引 audit_log_action_target_ts_idx';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_log_no_mutation') THEN
    RAISE EXCEPTION '1400: 缺只追加触发器 audit_log_no_mutation';
  END IF;
END
$$;

COMMIT;
