-- 1303 · M14 admin-data · 后台保存视图（admin_saved_views）
-- 规格：M14 §3 / §5（迁移 1303，长期保留）；01-ownership §2（M14 自有表）
-- 语义：软删除（active → deleted），行不物理删除；保存视图只放过滤条件 JSON，不放数据副本。
BEGIN;

CREATE TABLE IF NOT EXISTS admin_saved_views (
  view_id    UUID PRIMARY KEY,
  owner_id   TEXT NOT NULL,
  domain     TEXT NOT NULL,
  name       TEXT NOT NULL,
  filters    JSONB NOT NULL,
  shared     BOOLEAN NOT NULL DEFAULT false,
  state      TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE admin_saved_views DROP CONSTRAINT IF EXISTS admin_saved_views_shape_ck;
ALTER TABLE admin_saved_views ADD CONSTRAINT admin_saved_views_shape_ck
  CHECK (char_length(owner_id) BETWEEN 1 AND 128
     AND domain IN ('supply', 'account', 'content', 'risk', 'ledger', 'recon', 'reports',
                    'ticket', 'config', 'treasury', 'audit')
     AND char_length(name) BETWEEN 1 AND 64
     AND state IN ('active', 'deleted')
     AND jsonb_typeof(filters) = 'object') NOT VALID;

CREATE OR REPLACE FUNCTION m14_admin_saved_views_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.view_id IS DISTINCT FROM OLD.view_id
     OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
     OR NEW.domain IS DISTINCT FROM OLD.domain
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'admin_saved_views 归属字段不可改' USING ERRCODE = '42501';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (OLD.state = 'active' AND NEW.state = 'deleted') THEN
    RAISE EXCEPTION '保存视图只允许 active → deleted（软删除）' USING ERRCODE = '23514';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS admin_saved_views_guard ON admin_saved_views;
CREATE TRIGGER admin_saved_views_guard BEFORE UPDATE ON admin_saved_views
  FOR EACH ROW EXECUTE FUNCTION m14_admin_saved_views_guard();
DROP TRIGGER IF EXISTS admin_saved_views_no_delete ON admin_saved_views;
CREATE TRIGGER admin_saved_views_no_delete BEFORE DELETE ON admin_saved_views
  FOR EACH ROW EXECUTE FUNCTION m14_forbid_delete();
DROP TRIGGER IF EXISTS admin_saved_views_no_truncate ON admin_saved_views;
CREATE TRIGGER admin_saved_views_no_truncate BEFORE TRUNCATE ON admin_saved_views
  FOR EACH STATEMENT EXECUTE FUNCTION m14_forbid_truncate();

DROP INDEX IF EXISTS idx_admin_saved_views_owner_domain;
CREATE INDEX idx_admin_saved_views_owner_domain
  ON admin_saved_views (owner_id, domain);
DROP INDEX IF EXISTS uq_admin_saved_views_active_name;
CREATE UNIQUE INDEX uq_admin_saved_views_active_name
  ON admin_saved_views (owner_id, domain, name) WHERE state = 'active';

DO $$
DECLARE
  missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO missing
    FROM unnest(ARRAY['view_id','owner_id','domain','name','filters','shared','state',
                      'created_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'admin_saved_views' AND column_name = c);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'admin_saved_views 结构与 1303 不符，缺列：%', missing;
  END IF;
END;
$$;

COMMIT;
