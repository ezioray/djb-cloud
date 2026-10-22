-- 1000 · M10 配置中心 · 键元数据与契约（config_items）
-- 规格：product/v4/modules/M10-config-center.md §3（config_item 生命周期）· §5（数据所有权，迁移 1000）
--       product/v4/src/21-config-management.md §21.1.1（十域）· §21.2（模型）· §21.3.1（schema 与 x-djb-*）
--       §21.3.5（危险键）· 01-ownership §2（M10 拥有五表）
--
-- 原则：
--   1) 只加不改：只建 M10 新表，001–006 存量表零改动；本文件不写任何业务数据。
--   2) key 一经注册不可改名（§21.1.3）：改名 = 新 key + 旧 key tombstoned；DELETE 一律拒绝。
--   3) 元数据只由代码注册表落库（app.config_center.registry → store.sync_items），
--      后台不提供「直接改库」的入口（§21.11.4）。
--   4) 可重复执行：IF NOT EXISTS / DROP TRIGGER IF EXISTS + CREATE / CREATE OR REPLACE；
--      末尾结构断言保证「已存在的表」与本文件同形，半途建表不会被静默放过。
BEGIN;

-- ───────────────────────────────────────────────────────────── 键元数据
CREATE TABLE IF NOT EXISTS config_items (
  namespace       TEXT        NOT NULL,              -- 配置域命名空间（flag / billing / … / config / points）
  key             TEXT        NOT NULL,              -- 全名 = namespace.param[.subparam]（§21.1.3）
  value_type      TEXT        NOT NULL,              -- spec/openapi.yaml ConfigItem.value_type 五值
  unit            TEXT        NOT NULL,              -- bps / pct / usd / usd_minor / seconds / …（§21.3.2）
  schema_ref      TEXT        NOT NULL,              -- namespace.param@v1（§21.3.1：schema 也版本化）
  schema_body     JSONB       NOT NULL,              -- JSON Schema 2020-12 + 八个 x-djb-* 关键字
  risk_level      TEXT        NOT NULL,              -- P0 / P1 / P2（M10 §5 枚举）
  owner_role      TEXT        NOT NULL,              -- 发起角色组（域 owner；§21.1.1 域内互斥）
  allow_scope     TEXT[]      NOT NULL DEFAULT ARRAY['global']::TEXT[],
  consumers       TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],  -- x-djb-consumers：影响面分析来源
  dangerous       BOOLEAN     NOT NULL DEFAULT FALSE,           -- x-djb-dangerous：只读展示（INV-06）
  sensitive       BOOLEAN     NOT NULL DEFAULT FALSE,           -- 值默认脱敏（§21.10.2）
  secret_ref_only BOOLEAN     NOT NULL DEFAULT FALSE,           -- x-djb-secret-ref（INV-05）
  default_value   JSONB,                                        -- 声明默认；NULL = 未声明（发布前拒绝）
  default_source  TEXT        NOT NULL,                          -- facts:… / spec:… / policy:… / unset:…
  expire_required BOOLEAN     NOT NULL DEFAULT FALSE,           -- x-djb-expire-required
  state           TEXT        NOT NULL DEFAULT 'active',         -- item 生命周期（CR-2：与发布单状态分离）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- 主键即 §5 的 uq_config_items_key(namespace,key)
  CONSTRAINT config_items_pk PRIMARY KEY (namespace, key),
  CONSTRAINT config_items_key_shape_ck CHECK (key ~ '^[a-z][a-z0-9_.-]{2,127}$'),
  CONSTRAINT config_items_key_ns_ck CHECK (key LIKE namespace || '.%'),
  CONSTRAINT config_items_value_type_ck CHECK (
    value_type IN ('string', 'integer', 'number', 'boolean', 'json')),
  CONSTRAINT config_items_unit_ck CHECK (unit IN (
    'boolean', 'bps', 'pct', 'usd', 'usd_minor',
    'seconds', 'minutes', 'hours', 'days',
    'count', 'clock', 'window', 'enum', 'text', 'json')),
  CONSTRAINT config_items_risk_ck CHECK (risk_level IN ('P0', 'P1', 'P2')),
  CONSTRAINT config_items_state_ck CHECK (
    state IN ('draft', 'active', 'rolled_back', 'retired', 'tombstoned')),
  CONSTRAINT config_items_schema_body_ck CHECK (jsonb_typeof(schema_body) = 'object'),
  CONSTRAINT config_items_schema_ref_ck CHECK (schema_ref ~ '^[a-z][a-z0-9_.-]+@v[0-9]+$'),
  CONSTRAINT config_items_owner_ck CHECK (char_length(owner_role) BETWEEN 1 AND 32),
  CONSTRAINT config_items_default_source_ck CHECK (
    default_source ~ '^(facts|spec|policy|unset):'),
  -- 未声明默认值时来源必须是 unset:（防止「有默认却谎称没有」或反过来）
  CONSTRAINT config_items_default_source_pair_ck CHECK (
    (default_value IS NULL) = (default_source LIKE 'unset:%')),
  CONSTRAINT config_items_allow_scope_ck CHECK (
    array_length(allow_scope, 1) BETWEEN 1 AND 3
    AND allow_scope <@ ARRAY['global', 'region', 'tenant']::TEXT[]),
  CONSTRAINT config_items_consumers_ck CHECK (array_length(consumers, 1) IS NULL
    OR array_length(consumers, 1) BETWEEN 1 AND 16),
  -- 十域 + 两个辅助命名空间（config = M10 自管；points = M07 命名空间、M10 承载默认值）
  CONSTRAINT config_items_namespace_ck CHECK (namespace IN (
    'flag', 'billing', 'risk', 'quota', 'pool', 'routing', 'notify', 'content',
    'treasury', 'partner', 'exp', 'config', 'points'))
);

CREATE INDEX IF NOT EXISTS config_items_risk_idx ON config_items (risk_level, namespace);
CREATE INDEX IF NOT EXISTS config_items_dangerous_idx ON config_items (namespace)
  WHERE dangerous;

-- item 元数据可变（consumers / schema_ref 随代码 PR 演进），但 key 与 namespace 一经注册不可改；
-- DELETE 一律拒绝：历史版本与审计必须永远可解析到 key（§21.1.3「不可改名」）。
CREATE OR REPLACE FUNCTION m10_config_items_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_items is registry-only: DELETE not allowed (use state=tombstoned)'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.namespace IS DISTINCT FROM OLD.namespace OR NEW.key IS DISTINCT FROM OLD.key THEN
    RAISE EXCEPTION 'config_items: key/namespace is immutable once registered (% -> %)',
      OLD.key, NEW.key
      USING ERRCODE = '42501';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_items_guard ON config_items;
CREATE TRIGGER config_items_guard BEFORE UPDATE OR DELETE ON config_items
  FOR EACH ROW EXECUTE FUNCTION m10_config_items_guard();

CREATE OR REPLACE FUNCTION m10_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '%: TRUNCATE not allowed (M10 registry/append-only)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_items_no_truncate ON config_items;
CREATE TRIGGER config_items_no_truncate BEFORE TRUNCATE ON config_items
  FOR EACH STATEMENT EXECUTE FUNCTION m10_forbid_truncate();

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['namespace','key','value_type','unit','schema_ref','schema_body','risk_level',
                      'owner_role','allow_scope','consumers','dangerous','sensitive',
                      'secret_ref_only','default_value','default_source','expire_required','state',
                      'created_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_items' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_items 结构与 1000 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
