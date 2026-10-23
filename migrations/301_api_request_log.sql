-- 301 · M03 网关 · 请求元数据审计（api_request_log）+ 保留 / 只追加护栏
-- 规格：product/v4/modules/M03-gateway-protocol.md §5 数据所有权（api_request_log，迁移 300–399，
--       保留 7 天）· §3.2 INV-M03-02（只存元数据，不存正文/密钥/PII）· §6 事务边界
--       00-conventions §7.5（审计类表只追加）· §8.2（不记录正文）
--
-- 原则：
--   1) 只加不改：只建 M03 自己的表，001–006 / 1xx / 2xx / 4xx / 5xx / 6xx / 10xx 零改动。
--   2) 只存元数据（INV-M03-02）：没有 prompt / response / 密钥 / PII 列；列宽与枚举受限，
--      任何「把正文塞进 model」的尝试都会被长度约束挡住。
--   3) 唯一 request_id：客户端复用同一 X-Request-Id 时写入侧 ON CONFLICT DO NOTHING，
--      不会产生第二行，也不让请求失败。
--   4) 7 天保留（M03 §5）：**唯一允许的 DELETE** 是超过 7 天的行；UPDATE / TRUNCATE 一律拒绝。
--   5) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE / CREATE OR REPLACE；
--      末尾结构断言保证已存在的表与本节定义同形。
BEGIN;

-- ────────────────────────────────────────────────────────── 请求元数据
CREATE TABLE IF NOT EXISTS api_request_log (
  id            UUID PRIMARY KEY,                    -- UUIDv7（00-conventions §2）
  request_id    TEXT NOT NULL,                       -- X-Request-Id（spec，回显值）
  trace_id      TEXT,                                -- 全链路追踪
  account_id    UUID,                                -- M01 user_accounts（软引用，不建 FK）
  tenant_id     UUID,                                -- M01 租户（软引用）
  api_key_id    BIGINT,                              -- M01 api_keys（软引用）
  model         TEXT,                                -- 模型 slug（不可变）
  service_tier  TEXT NOT NULL DEFAULT 'realtime',    -- realtime / batch（M03 §5 枚举）
  stream        BOOLEAN NOT NULL DEFAULT false,      -- 是否流式
  status        TEXT NOT NULL,                       -- completed / failed / interrupted
  http_status   INTEGER NOT NULL,                    -- 对外 HTTP 状态
  error_code    INTEGER,                             -- 对外数字码（成功为 NULL）
  node_id       TEXT,                                -- M02 节点（软引用）
  latency_ms    INTEGER,                             -- 端到端耗时（毫秒）
  first_byte_ms INTEGER,                             -- 首字节耗时（毫秒；SLO 见 03-facts §10）
  tokens_in     INTEGER,                             -- 用量（计费权威在 M05）
  tokens_out    INTEGER,
  usage_source  TEXT,                                -- estimated / actual
  batch_id      UUID,                                -- 慢任务（T4）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_request_uq;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_request_uq UNIQUE (request_id);

ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_status_ck;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_status_ck
  CHECK (status IN ('completed', 'failed', 'interrupted')) NOT VALID;

ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_tier_ck;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_tier_ck
  CHECK (service_tier IN ('realtime', 'batch')) NOT VALID;

ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_usage_source_ck;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_usage_source_ck
  CHECK (usage_source IS NULL OR usage_source IN ('estimated', 'actual')) NOT VALID;

ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_http_ck;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_http_ck
  CHECK (http_status BETWEEN 100 AND 599) NOT VALID;

-- 元数据边界（INV-M03-02）：列宽受限，正文/堆栈不可能塞进来
ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_meta_ck;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_meta_ck
  CHECK ((model IS NULL OR char_length(model) BETWEEN 1 AND 128)
     AND (node_id IS NULL OR char_length(node_id) BETWEEN 1 AND 128)
     AND (trace_id IS NULL OR char_length(trace_id) BETWEEN 1 AND 128)
     AND char_length(request_id) BETWEEN 1 AND 128
     AND (latency_ms IS NULL OR latency_ms >= 0)
     AND (first_byte_ms IS NULL OR first_byte_ms >= 0)
     AND (tokens_in IS NULL OR tokens_in >= 0)
     AND (tokens_out IS NULL OR tokens_out >= 0)
     AND (error_code IS NULL OR error_code BETWEEN 1000 AND 99999)) NOT VALID;

-- 限额与排障查询（M03 §5 索引）
CREATE INDEX IF NOT EXISTS api_request_log_key_time_idx
  ON api_request_log (api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS api_request_log_account_time_idx
  ON api_request_log (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS api_request_log_batch_idx
  ON api_request_log (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS api_request_log_created_idx
  ON api_request_log (created_at);

-- ────────────────────────────────────────────────────────── 只追加 + 保留护栏
CREATE OR REPLACE FUNCTION m03_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '%: TRUNCATE not allowed (M03 §3.2 INV-M03-02)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION m03_request_log_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'api_request_log is append-only: UPDATE not allowed (INV-M03-02)'
      USING ERRCODE = '42501';
  END IF;
  -- 唯一允许的 DELETE：超过 7 天保留期（M03 §5）
  IF OLD.created_at > now() - INTERVAL '7 days' THEN
    RAISE EXCEPTION 'api_request_log: only rows older than 7 days may be deleted (retention)'
      USING ERRCODE = '42501';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS api_request_log_guard ON api_request_log;
CREATE TRIGGER api_request_log_guard BEFORE UPDATE OR DELETE ON api_request_log
  FOR EACH ROW EXECUTE FUNCTION m03_request_log_guard();

DROP TRIGGER IF EXISTS api_request_log_no_truncate ON api_request_log;
CREATE TRIGGER api_request_log_no_truncate BEFORE TRUNCATE ON api_request_log
  FOR EACH STATEMENT EXECUTE FUNCTION m03_forbid_truncate();

COMMENT ON TABLE api_request_log IS
  'M03 请求元数据（迁移 301）：只存元数据、保留 7 天；不存 prompt / response / 密钥 / PII';
COMMENT ON COLUMN api_request_log.first_byte_ms IS
  '首字节耗时（毫秒）；SLO 见 03-facts §10（P95 ≤1.2s，网关额外 ≤20ms）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'api_request_log' AND column_name = 'first_byte_ms') THEN
    RAISE EXCEPTION '301: api_request_log 缺列 first_byte_ms';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'api_request_log_request_uq') THEN
    RAISE EXCEPTION '301: 缺 request_id 唯一约束 api_request_log_request_uq';
  END IF;
END
$$;

COMMIT;
