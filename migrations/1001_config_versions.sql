-- 1001 · M10 配置中心 · 不可变版本（config_versions）与只追加护栏
-- 规格：M10 §3 INV-01（digest 可复算 / version 单调递增不跳号不复用）· INV-03（复核人 ≠ 发起人）
--       INV-05（密钥形态 / secret-ref 只接受引用结构）· INV-09（回滚不改历史，只生成新版本）
--       §5 数据所有权（config_versions @ 1001；uq_versions / uq_idem）
--       product/v4/src/21-config-management.md §21.2.1（version 不可变）· §21.2.2（scope 优先级）
--
-- 原则：
--   1) 只追加：DELETE / TRUNCATE 一律拒绝；UPDATE 只放行状态机字段（status / effective_at /
--      published_by / approved_by），值、digest、version 一个字节都不许动（INV-01 / INV-09）。
--   2) 版本单调：同一 (key, scope, scope_id) 的 version 必须 = 当前最大值 + 1（不跳号、不复用）；
--      并发由唯一约束兜底（两个事务都算出 max+1 时，后插入者 23505）。
--   3) 幂等：uq_idem(scope, idempotency_key) —— 同键同载荷返回首次结果，同键不同载荷由应用层
--      比对 request_digest 后返回 409（40919）；库层保证「同键不可能落两条版本」。
--   4) 同 key 同时只允许一个 active 版本（INV-08 的存储前提；切换由 T3 用 CAS 完成）。
--   5) INV-03 下沉到库：draft → active 时 P0/P1 必须 approved_by 非空且 ≠ published_by。
--   6) 可重复执行：IF NOT EXISTS / DROP TRIGGER IF EXISTS + CREATE / CREATE OR REPLACE。
BEGIN;

CREATE TABLE IF NOT EXISTS config_versions (
  version_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace       TEXT        NOT NULL,
  key             TEXT        NOT NULL,
  scope           TEXT        NOT NULL DEFAULT 'global',
  scope_id        TEXT        NOT NULL DEFAULT '',
  version         INTEGER     NOT NULL,
  value_type      TEXT        NOT NULL,
  unit            TEXT        NOT NULL,
  schema_ref      TEXT        NOT NULL,
  value           JSONB,                                  -- 非敏感值（secret_ref_only 键必须 NULL）
  secret_ref      JSONB,                                  -- {scheme, path, inject, version}（INV-05）
  content_digest  TEXT        NOT NULL,                    -- sha256(canonical({key,value,schema_ref,unit}))
  request_digest  TEXT        NOT NULL,                    -- 幂等「同键同载荷」判定用的请求指纹
  status          TEXT        NOT NULL DEFAULT 'draft',
  effective_at    TIMESTAMPTZ,
  published_by    TEXT,
  approved_by     TEXT,
  rollback_to     INTEGER     NOT NULL DEFAULT 0,          -- INV-09：0 = 普通版本；>0 = 回滚目标版本
  reason          TEXT        NOT NULL,
  ticket          TEXT,
  idempotency_key TEXT,
  created_by      TEXT        NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- 注册表是唯一来源：版本必须挂在已注册的 key 上（复合外键 → config_items(ns,key)）
  CONSTRAINT config_versions_item_fk FOREIGN KEY (namespace, key)
    REFERENCES config_items (namespace, key) ON DELETE RESTRICT,
  -- §5：uq_versions(key, scope, scope_id, version)
  CONSTRAINT config_versions_key_scope_version_uq UNIQUE (key, scope, scope_id, version),
  CONSTRAINT config_versions_scope_ck CHECK (scope IN ('global', 'region', 'tenant')),
  CONSTRAINT config_versions_scope_id_ck CHECK (
    (scope = 'global' AND scope_id = '')
    OR (scope IN ('region', 'tenant') AND scope_id <> '')),
  CONSTRAINT config_versions_scope_id_shape_ck CHECK (
    scope_id = '' OR scope_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  CONSTRAINT config_versions_version_ck CHECK (version >= 1),
  CONSTRAINT config_versions_value_type_ck CHECK (
    value_type IN ('string', 'integer', 'number', 'boolean', 'json')),
  CONSTRAINT config_versions_status_ck CHECK (
    status IN ('draft', 'active', 'superseded', 'rolled_back', 'rejected', 'tombstoned')),
  CONSTRAINT config_versions_digest_ck CHECK (content_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT config_versions_request_digest_ck CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT config_versions_schema_ref_ck CHECK (schema_ref ~ '^[a-z][a-z0-9_.-]+@v[0-9]+$'),
  CONSTRAINT config_versions_reason_ck CHECK (char_length(reason) BETWEEN 4 AND 512),
  CONSTRAINT config_versions_actor_ck CHECK (char_length(created_by) BETWEEN 1 AND 128),
  CONSTRAINT config_versions_idem_ck CHECK (
    idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 8 AND 128),
  -- 版本必须携带内容：普通值或 secret_ref 至少一个（不会出现「空版本」）
  CONSTRAINT config_versions_payload_ck CHECK (value IS NOT NULL OR secret_ref IS NOT NULL),
  CONSTRAINT config_versions_secret_ref_ck CHECK (
    secret_ref IS NULL OR jsonb_typeof(secret_ref) = 'object'),
  -- 值的 JSON 类型必须与 value_type 一致（integer 不接受 1.0：防浮点，§21.3.2）
  CONSTRAINT config_versions_value_shape_ck CHECK (value IS NULL OR (
    (value_type = 'string' AND jsonb_typeof(value) = 'string')
    OR (value_type = 'integer' AND jsonb_typeof(value) = 'number' AND value::text ~ '^-?[0-9]+$')
    OR (value_type = 'number' AND jsonb_typeof(value) = 'number')
    OR (value_type = 'boolean' AND jsonb_typeof(value) = 'boolean')
    OR (value_type = 'json' AND jsonb_typeof(value) IN ('object', 'array'))
  )),
  -- INV-09：回滚目标必须是更早的版本；0 = 非回滚版本
  CONSTRAINT config_versions_rollback_ck CHECK (
    rollback_to = 0 OR (rollback_to >= 1 AND rollback_to < version)),
  CONSTRAINT config_versions_active_publisher_ck CHECK (
    status <> 'active' OR published_by IS NOT NULL)
);

-- §5：uq_idem(scope, idempotency_key)（部分唯一：未带幂等键的草稿不参与）
CREATE UNIQUE INDEX IF NOT EXISTS config_versions_idem_uq
  ON config_versions (scope, idempotency_key) WHERE idempotency_key IS NOT NULL;
-- INV-08 存储前提：同 key 同 scope 只允许一个 active 版本
CREATE UNIQUE INDEX IF NOT EXISTS config_versions_one_active_uq
  ON config_versions (key, scope, scope_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS config_versions_key_scope_idx
  ON config_versions (key, scope, scope_id, version DESC);
CREATE INDEX IF NOT EXISTS config_versions_status_idx ON config_versions (status, updated_at);

-- ───────────────────────────────────────────────────────────── 只追加护栏
CREATE OR REPLACE FUNCTION m10_versions_guard() RETURNS trigger AS $$
DECLARE
  v_risk TEXT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_versions is append-only: DELETE not allowed (INV-01/INV-09)'
      USING ERRCODE = '42501';
  END IF;

  -- 除状态机字段外一律不可变（值 / digest / version / key / scope / 幂等键…）
  IF (to_jsonb(NEW) - ARRAY['status', 'effective_at', 'published_by', 'approved_by', 'updated_at'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['status', 'effective_at', 'published_by', 'approved_by', 'updated_at'])
  THEN
    RAISE EXCEPTION 'config_versions is immutable: only status/effective_at/published_by/approved_by may change (% @v%, INV-01)',
      OLD.key, OLD.version
      USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT (
      (OLD.status = 'draft' AND NEW.status IN ('active', 'rejected', 'tombstoned'))
      OR (OLD.status = 'active' AND NEW.status IN ('superseded', 'rolled_back'))
    ) THEN
      RAISE EXCEPTION 'config_versions: illegal status transition % -> % (INV-09: rollback creates a new version)',
        OLD.status, NEW.status
        USING ERRCODE = '42501';
    END IF;
  END IF;

  -- 生效信息只在 draft -> active 时写；其余状态变化不得顺手改发布人 / 生效时间
  IF NOT (OLD.status = 'draft' AND NEW.status = 'active') THEN
    IF NEW.published_by IS DISTINCT FROM OLD.published_by
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.effective_at IS DISTINCT FROM OLD.effective_at THEN
      RAISE EXCEPTION 'config_versions: published_by/approved_by/effective_at only set when activating (% @v%)',
        OLD.key, OLD.version
        USING ERRCODE = '42501';
    END IF;
  ELSE
    -- INV-03：P0 / P1 的复核人必填且 ≠ 发起人（自批自核在库层就写不进去）
    SELECT risk_level INTO v_risk FROM config_items
     WHERE namespace = OLD.namespace AND key = OLD.key;
    IF v_risk IN ('P0', 'P1') THEN
      IF NEW.approved_by IS NULL OR NEW.approved_by = '' THEN
        RAISE EXCEPTION 'INV-03: % is %, approved_by is required before activation',
          OLD.key, v_risk
          USING ERRCODE = '23514';
      END IF;
      IF NEW.approved_by = NEW.published_by THEN
        RAISE EXCEPTION 'INV-03: approver must differ from publisher (% @v%)',
          OLD.key, OLD.version
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_versions_guard ON config_versions;
CREATE TRIGGER config_versions_guard BEFORE UPDATE OR DELETE ON config_versions
  FOR EACH ROW EXECUTE FUNCTION m10_versions_guard();

DROP TRIGGER IF EXISTS config_versions_no_truncate ON config_versions;
CREATE TRIGGER config_versions_no_truncate BEFORE TRUNCATE ON config_versions
  FOR EACH STATEMENT EXECUTE FUNCTION m10_forbid_truncate();

-- ───────────────────────────────────────────────────────────── 版本单调（INV-01）
CREATE OR REPLACE FUNCTION m10_versions_monotonic_trg() RETURNS trigger AS $$
DECLARE
  v_max INTEGER;
BEGIN
  SELECT COALESCE(max(version), 0) INTO v_max
    FROM config_versions
   WHERE key = NEW.key AND scope = NEW.scope AND scope_id = NEW.scope_id;
  IF NEW.version <> v_max + 1 THEN
    RAISE EXCEPTION 'config_versions: version must be % (max+1) for % [%/%], got % (INV-01: no gap / no reuse)',
      v_max + 1, NEW.key, NEW.scope, NEW.scope_id, NEW.version
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_versions_monotonic ON config_versions;
CREATE TRIGGER config_versions_monotonic BEFORE INSERT ON config_versions
  FOR EACH ROW EXECUTE FUNCTION m10_versions_monotonic_trg();

-- ───────────────────────────────────────────────────────────── 敏感 / secret-ref 下沉（INV-05）
CREATE OR REPLACE FUNCTION m10_versions_secret_trg() RETURNS trigger AS $$
DECLARE
  v_secret_only BOOLEAN;
BEGIN
  SELECT secret_ref_only INTO v_secret_only FROM config_items
   WHERE namespace = NEW.namespace AND key = NEW.key;
  IF v_secret_only THEN
    IF NEW.value IS NOT NULL THEN
      RAISE EXCEPTION 'INV-05: % is secret-ref-only, plaintext value not allowed', NEW.key
        USING ERRCODE = '23514';
    END IF;
    IF NEW.secret_ref IS NULL THEN
      RAISE EXCEPTION 'INV-05: % requires secret_ref {scheme,path,inject,version}', NEW.key
        USING ERRCODE = '23514';
    END IF;
    IF NOT (NEW.secret_ref ? 'scheme' AND NEW.secret_ref ? 'path'
            AND NEW.secret_ref ? 'inject' AND NEW.secret_ref ? 'version') THEN
      RAISE EXCEPTION 'INV-05: % secret_ref must be {scheme,path,inject,version}', NEW.key
        USING ERRCODE = '23514';
    END IF;
    IF (NEW.secret_ref - ARRAY['scheme', 'path', 'inject', 'version']) <> '{}'::jsonb THEN
      RAISE EXCEPTION 'INV-05: % secret_ref has undefined fields', NEW.key
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_versions_secret ON config_versions;
CREATE TRIGGER config_versions_secret BEFORE INSERT ON config_versions
  FOR EACH ROW EXECUTE FUNCTION m10_versions_secret_trg();

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['version_id','namespace','key','scope','scope_id','version','value_type','unit',
                      'schema_ref','value','secret_ref','content_digest','request_digest','status',
                      'effective_at','published_by','approved_by','rollback_to','reason','ticket',
                      'idempotency_key','created_by','created_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_versions' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_versions 结构与 1001 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
