-- 1003 · M10 配置中心 · 快照与回放（config_snapshots）
-- 规格：M10 §3 INV-08（快照 entries 覆盖全部 active key；policy_version = snapshot_digest 前 12 位）
--       §5 数据所有权（迁移 1003；保留 ≥3 年）· §6 事务边界（active 切换与快照写入同事务）
--       product/v4/src/21-config-management.md §21.5（发布语义 / 回放）
--
-- 只追加：快照是「某一刻全部 active 配置」的不可变证据，写入后任何字段都不得修改（DELETE 亦拒绝）。
-- policy_version 用生成列 = left(snapshot_digest, 12)：库层直接保证 INV-08，不依赖应用层自觉。
BEGIN;

CREATE TABLE IF NOT EXISTS config_snapshots (
  snapshot_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_digest   TEXT        NOT NULL,
  -- INV-08：policy_version 由 digest 派生（生成列，写不进去别的值）
  policy_version    TEXT        GENERATED ALWAYS AS (left(snapshot_digest, 12)) STORED,
  period            TEXT        NOT NULL,               -- 'YYYY-MM-DD'（日扫）或 'publish:<request_id>'
  entries           JSONB       NOT NULL,               -- [{key,scope,scope_id,version,content_digest}]
  entries_count     INTEGER     NOT NULL,
  publish_request_id UUID       REFERENCES config_publish_requests (publish_request_id)
                                ON DELETE RESTRICT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT config_snapshots_digest_uq UNIQUE (snapshot_digest),
  CONSTRAINT config_snapshots_digest_ck CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT config_snapshots_period_ck CHECK (char_length(period) BETWEEN 1 AND 64),
  CONSTRAINT config_snapshots_entries_ck CHECK (
    jsonb_typeof(entries) = 'array' AND jsonb_array_length(entries) = entries_count),
  CONSTRAINT config_snapshots_entries_count_ck CHECK (entries_count >= 1),
  CONSTRAINT config_snapshots_policy_version_ck CHECK (policy_version = left(snapshot_digest, 12))
);

CREATE INDEX IF NOT EXISTS config_snapshots_period_idx ON config_snapshots (period, created_at);
CREATE INDEX IF NOT EXISTS config_snapshots_policy_version_idx ON config_snapshots (policy_version);

-- 只追加：UPDATE / DELETE / TRUNCATE 全部拒绝（快照可回放的前提是不可改写）
CREATE OR REPLACE FUNCTION m10_snapshots_guard() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'config_snapshots is append-only: % not allowed (INV-08)', TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_snapshots_no_mutation ON config_snapshots;
CREATE TRIGGER config_snapshots_no_mutation BEFORE UPDATE OR DELETE ON config_snapshots
  FOR EACH ROW EXECUTE FUNCTION m10_snapshots_guard();

DROP TRIGGER IF EXISTS config_snapshots_no_truncate ON config_snapshots;
CREATE TRIGGER config_snapshots_no_truncate BEFORE TRUNCATE ON config_snapshots
  FOR EACH STATEMENT EXECUTE FUNCTION m10_forbid_truncate();

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['snapshot_id','snapshot_digest','policy_version','period','entries',
                      'entries_count','publish_request_id','created_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_snapshots' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_snapshots 结构与 1003 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
