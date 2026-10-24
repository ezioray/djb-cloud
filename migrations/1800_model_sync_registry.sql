-- 1800 · M18 model-sync（C17）：厂商模型注册表 / 签名 bundle / 事件 / 节点应用状态
-- 规格：M18-model-sync.md §3（数据模型 1800–1899）· §4（采集与发布：TTL 24h、回滚只改指针不改历史）
--       · §9（开关三字段默认关）· §10（只分发元数据 / 指纹，不分发厂商权重，不存正文）
--
-- 原则：
--   1) **只存元数据 / 指纹**：tokenizer_hash 是 family+version 的 sha256 占位，不是厂商权重；
--      event.detail / node drift 由 CHECK 兜底禁止出现正文 / 凭据类键；
--   2) **版本只增**：model_sync_bundles.version UNIQUE；回滚新建更高版本（不重写历史），
--      版本 / payload / payload_hash / source / created_at 由触发器守住不可改；
--   3) **历史只追加**：bundle 禁止 DELETE / TRUNCATE；事件表禁止 UPDATE / DELETE / TRUNCATE；
--   4) **不碰账本**：本迁移不创建、不修改任何 ledger_* / account_balances / loss_pool 对象，
--      也不新增科目或分录（tests/model_sync/test_migration.py 用结构+行摘要证明 diff=0）；
--   5) 只加不改：1800–1899 段独占，不动任何前置对象。
BEGIN;

-- ───────────────────────────────────────────────────────── vendor_models
CREATE TABLE IF NOT EXISTS vendor_models (
  id                UUID PRIMARY KEY,                       -- UUIDv7（应用生成）
  vendor            TEXT NOT NULL,                          -- openai / anthropic / deepseek …
  canonical         TEXT NOT NULL,                          -- 归一 slug（客户端按此匹配）
  aliases           TEXT[] NOT NULL DEFAULT '{}',           -- 厂商别名 / 历史 slug
  context_window    INTEGER NOT NULL,                       -- 上下文窗口（token）
  tokenizer_family  TEXT NOT NULL,                          -- 分词器家族（如 o200k_base）
  tokenizer_version TEXT NOT NULL,                          -- 家族内版本（如 2024-07）
  tokenizer_hash    TEXT NOT NULL,                          -- 指纹占位（sha256 hex，非权重）
  effective_at      TIMESTAMPTZ NOT NULL,                   -- 该版本生效时刻
  source            TEXT NOT NULL,                          -- vendor_api / sdk / admin
  state             TEXT NOT NULL DEFAULT 'active',         -- active / retired
  created_at        TIMESTAMPTZ NOT NULL,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT vendor_models_context_ck CHECK (context_window BETWEEN 1 AND 100000000),
  CONSTRAINT vendor_models_hash_ck CHECK (tokenizer_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT vendor_models_source_ck CHECK (source IN ('vendor_api', 'sdk', 'admin')),
  CONSTRAINT vendor_models_state_ck CHECK (state IN ('active', 'retired')),
  CONSTRAINT vendor_models_aliases_ck CHECK
    (aliases IS NULL OR cardinality(aliases) <= 16),
  CONSTRAINT vendor_models_vendor_ck CHECK (char_length(vendor) BETWEEN 1 AND 128),
  CONSTRAINT vendor_models_canonical_ck CHECK (char_length(canonical) BETWEEN 1 AND 128),
  CONSTRAINT vendor_models_tokenizer_ck CHECK
    (char_length(tokenizer_family) BETWEEN 1 AND 128
     AND char_length(tokenizer_version) BETWEEN 1 AND 128),
  CONSTRAINT vendor_models_uq UNIQUE (vendor, canonical, effective_at)
);

CREATE INDEX IF NOT EXISTS idx_vendor_models_lookup
  ON vendor_models (vendor, canonical, state, effective_at DESC);
CREATE INDEX IF NOT EXISTS idx_vendor_models_state
  ON vendor_models (state, effective_at DESC);

COMMENT ON TABLE vendor_models IS
  'M18 §3 厂商模型/tokenizer 版本注册表：只存元数据与占位指纹；'
  '(vendor, canonical, effective_at) 唯一；不存厂商 tokenizer 权重、不存凭据';

-- ───────────────────────────────────────────────────────── model_sync_bundles
CREATE TABLE IF NOT EXISTS model_sync_bundles (
  id           UUID PRIMARY KEY,                            -- UUIDv7
  version      BIGINT NOT NULL,                             -- 只增；UNIQUE
  payload      JSONB NOT NULL,                              -- {"format":1,"models":[…]}
  payload_hash TEXT NOT NULL,                               -- sha256(canonical JSON)
  signature    TEXT,                                        -- hmac-sha256:<64 hex>（draft 为空）
  source       TEXT NOT NULL,                               -- registry / vendor_api / sdk / admin / rollback
  published_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ,                                 -- published_at + 24h
  state        TEXT NOT NULL DEFAULT 'draft',               -- draft/published/revoked/rolled_back
  created_at   TIMESTAMPTZ NOT NULL,

  CONSTRAINT model_sync_bundles_version_uq UNIQUE (version),
  CONSTRAINT model_sync_bundles_version_ck CHECK (version > 0),
  CONSTRAINT model_sync_bundles_hash_ck CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT model_sync_bundles_signature_ck CHECK
    (signature IS NULL OR signature ~ '^hmac-sha256:[0-9a-f]{64}$'),
  CONSTRAINT model_sync_bundles_state_ck CHECK
    (state IN ('draft', 'published', 'revoked', 'rolled_back')),
  CONSTRAINT model_sync_bundles_source_ck CHECK
    (source IN ('registry', 'vendor_api', 'sdk', 'admin', 'rollback')),
  CONSTRAINT model_sync_bundles_payload_ck CHECK
    (jsonb_typeof(payload) = 'object' AND jsonb_typeof(payload -> 'models') = 'array'),
  -- 发布过（published / rolled_back / revoked）的行必须有签名与 TTL
  CONSTRAINT model_sync_bundles_published_ck CHECK
    (state = 'draft'
     OR (signature IS NOT NULL AND published_at IS NOT NULL AND expires_at IS NOT NULL)),
  CONSTRAINT model_sync_bundles_ttl_ck CHECK
    (expires_at IS NULL OR published_at IS NULL OR expires_at > published_at)
);

CREATE INDEX IF NOT EXISTS idx_bundles_state_version
  ON model_sync_bundles (state, version DESC);
CREATE INDEX IF NOT EXISTS idx_bundles_published
  ON model_sync_bundles (published_at DESC) WHERE state = 'published';

COMMENT ON TABLE model_sync_bundles IS
  'M18 §3 签名 bundle（只追加 + 状态机）：version 只增；回滚新建更高版本指向旧 payload；'
  'payload 只有元数据/指纹；签名 hmac-sha256（S3 换 Ed25519）';

-- ───────────────────────────────────────────────────────── model_sync_events
CREATE TABLE IF NOT EXISTS model_sync_events (
  seq        BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,    -- 插入序（同 ts 稳定排序）
  id         UUID PRIMARY KEY,
  bundle_id  UUID,                                          -- state_applied 为空
  version    BIGINT,                                        -- 关联版本（可空）
  event      TEXT NOT NULL,
  detail     JSONB NOT NULL DEFAULT '{}'::jsonb,            -- 只放计数 / 差异 / 错误类
  actor      TEXT NOT NULL,                                 -- admin:<id> / node:<id> / system:<job>
  created_at TIMESTAMPTZ NOT NULL,

  CONSTRAINT model_sync_events_event_ck CHECK
    (event IN ('draft', 'published', 'revoked', 'rolled_back', 'state_applied')),
  CONSTRAINT model_sync_events_actor_ck CHECK (char_length(actor) BETWEEN 1 AND 128),
  -- 0 表示「客户端从未同步」（首次上报 applied_version=0 是合法状态）
  CONSTRAINT model_sync_events_version_ck CHECK (version IS NULL OR version >= 0),
  -- 证据只放元数据：不得出现正文 / 凭据类键（DB 兜底，应用层另校验）
  CONSTRAINT model_sync_events_detail_ck CHECK (
    NOT (detail ?| ARRAY['content', 'messages', 'prompt', 'response', 'body', 'text',
                         'api_key', 'secret', 'password', 'token']))
);

CREATE INDEX IF NOT EXISTS idx_model_sync_events_bundle
  ON model_sync_events (bundle_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_sync_events_event
  ON model_sync_events (event, created_at DESC);

COMMENT ON TABLE model_sync_events IS
  'M18 §3 事件流水（只追加）：draft / published / revoked / rolled_back / state_applied；'
  'detail 只放计数、差异与错误类，不落正文';

-- ───────────────────────────────────────────────────────── node_model_sync_state
CREATE TABLE IF NOT EXISTS node_model_sync_state (
  node_id         TEXT PRIMARY KEY,                         -- 供应节点（M02）
  applied_version BIGINT NOT NULL DEFAULT 0,                -- 客户端已应用版本
  applied_at      TIMESTAMPTZ,
  drift           JSONB NOT NULL DEFAULT '{}'::jsonb,       -- 漂移摘要（模型名/版本差，不是正文）
  last_error      TEXT,                                     -- 错误类（≤64）
  updated_at      TIMESTAMPTZ NOT NULL,

  CONSTRAINT node_model_sync_state_version_ck CHECK (applied_version >= 0),
  CONSTRAINT node_model_sync_state_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT node_model_sync_state_error_ck CHECK
    (last_error IS NULL OR char_length(last_error) BETWEEN 1 AND 64),
  CONSTRAINT node_model_sync_state_drift_ck CHECK (jsonb_typeof(drift) = 'object'),
  CONSTRAINT node_model_sync_state_drift_keys_ck CHECK (
    NOT (drift ?| ARRAY['content', 'messages', 'prompt', 'response', 'body', 'text',
                        'api_key', 'secret', 'password', 'token']))
);

CREATE INDEX IF NOT EXISTS idx_node_model_sync_state_version
  ON node_model_sync_state (applied_version, updated_at DESC);

COMMENT ON TABLE node_model_sync_state IS
  'M18 §6 客户端应用状态：只存版本号 / 漂移摘要 / 错误类，不存正文与凭据';

-- ───────────────────────────────────────────────────────── 护栏
CREATE OR REPLACE FUNCTION m18_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% 只追加：禁止 TRUNCATE', TG_TABLE_NAME USING ERRCODE = '42501';
END $$;

-- bundle：版本 / payload / 来源不可改；状态机单向；禁止 DELETE
CREATE OR REPLACE FUNCTION m18_bundles_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'model_sync_bundles 禁止 DELETE（版本历史保留可查）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
     OR NEW.payload::text IS DISTINCT FROM OLD.payload::text
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'model_sync_bundles 的 id/version/payload/source/created_at 不可修改'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.state = 'draft' AND NEW.state NOT IN ('draft', 'published', 'revoked') THEN
    RAISE EXCEPTION '非法状态迁移: % -> %', OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  IF OLD.state = 'published' AND NEW.state NOT IN ('published', 'rolled_back', 'revoked') THEN
    RAISE EXCEPTION '非法状态迁移: % -> %', OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  IF OLD.state IN ('rolled_back', 'revoked') AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'bundle 处于终态 %：不可再迁移', OLD.state USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS model_sync_bundles_guard ON model_sync_bundles;
CREATE TRIGGER model_sync_bundles_guard BEFORE UPDATE OR DELETE
  ON model_sync_bundles FOR EACH ROW EXECUTE FUNCTION m18_bundles_guard();

DROP TRIGGER IF EXISTS model_sync_bundles_no_truncate ON model_sync_bundles;
CREATE TRIGGER model_sync_bundles_no_truncate BEFORE TRUNCATE
  ON model_sync_bundles FOR EACH STATEMENT EXECUTE FUNCTION m18_forbid_truncate();

-- 事件：只追加（禁止 UPDATE / DELETE / TRUNCATE）
CREATE OR REPLACE FUNCTION m18_events_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'model_sync_events 只追加：禁止 %', TG_OP USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS model_sync_events_guard ON model_sync_events;
CREATE TRIGGER model_sync_events_guard BEFORE UPDATE OR DELETE
  ON model_sync_events FOR EACH ROW EXECUTE FUNCTION m18_events_guard();

DROP TRIGGER IF EXISTS model_sync_events_no_truncate ON model_sync_events;
CREATE TRIGGER model_sync_events_no_truncate BEFORE TRUNCATE
  ON model_sync_events FOR EACH STATEMENT EXECUTE FUNCTION m18_forbid_truncate();

COMMIT;
