-- 1004 · M10 配置中心 · 三源漂移（config_drifts）
-- 规格：M10 §3（config_drift 只追加，可标 resolved）· §5 数据所有权（迁移 1004；idx_drifts_detected）
--       §6 流程 4（desired / effective / running 三源对比）· §7（5 分钟 P1 / 15 分钟转「待节点确认」）
--       product/v4/src/21-config-management.md §21.11.5
--
-- 只追加 + 有限可变：记录写入后 desired/effective/running 与 expected/actual 不可改；
-- 只允许把 resolved_at / resolution 从 NULL 置一次（「可标 resolved」，不允许撤销或改结论）。
BEGIN;

CREATE TABLE IF NOT EXISTS config_drifts (
  drift_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace         TEXT        NOT NULL,
  key               TEXT        NOT NULL,
  scope             TEXT        NOT NULL DEFAULT 'global',
  scope_id          TEXT        NOT NULL DEFAULT '',
  desired_version   INTEGER,                        -- 配置仓清单（A）
  effective_version INTEGER,                        -- active 版本（B）
  running_version   INTEGER,                        -- 消费端 applied_version（C）
  expected          JSONB,                          -- 期望值（脱敏后的可比形态）
  actual            JSONB,                          -- 实际值
  detected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at       TIMESTAMPTZ,
  resolution        TEXT,                           -- 处置码 / 说明（与 resolved_at 同生共死）

  CONSTRAINT config_drifts_versions_ck CHECK (
    (desired_version IS NULL OR desired_version >= 1)
    AND (effective_version IS NULL OR effective_version >= 1)
    AND (running_version IS NULL OR running_version >= 1)),
  -- 至少要有两源可比较，否则不是漂移（单源为空 = 数据缺失，走告警不走漂移表）
  CONSTRAINT config_drifts_pairs_ck CHECK (
    (desired_version IS NOT NULL AND effective_version IS NOT NULL)
    OR (desired_version IS NOT NULL AND running_version IS NOT NULL)
    OR (effective_version IS NOT NULL AND running_version IS NOT NULL)),
  CONSTRAINT config_drifts_scope_ck CHECK (scope IN ('global', 'region', 'tenant')),
  CONSTRAINT config_drifts_scope_id_ck CHECK (
    (scope = 'global' AND scope_id = '')
    OR (scope IN ('region', 'tenant') AND scope_id <> '')),
  CONSTRAINT config_drifts_resolution_ck CHECK (
    (resolved_at IS NULL AND resolution IS NULL)
    OR (resolved_at IS NOT NULL AND resolution IS NOT NULL)),
  CONSTRAINT config_drifts_resolved_after_ck CHECK (
    resolved_at IS NULL OR resolved_at >= detected_at),
  CONSTRAINT config_drifts_resolution_len_ck CHECK (
    resolution IS NULL OR char_length(resolution) BETWEEN 2 AND 256)
);

CREATE INDEX IF NOT EXISTS config_drifts_detected_idx ON config_drifts (detected_at DESC);
CREATE INDEX IF NOT EXISTS config_drifts_key_idx ON config_drifts (key, detected_at DESC);
CREATE INDEX IF NOT EXISTS config_drifts_open_idx ON config_drifts (detected_at)
  WHERE resolved_at IS NULL;

-- 只追加 + 只允许「标 resolved」一次
CREATE OR REPLACE FUNCTION m10_drifts_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_drifts is append-only: DELETE not allowed'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['resolved_at', 'resolution'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['resolved_at', 'resolution']) THEN
    RAISE EXCEPTION 'config_drifts is append-only: only resolved_at/resolution may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.resolved_at IS NOT NULL THEN
    RAISE EXCEPTION 'config_drifts: drift % is already resolved (% -> rejected)',
      OLD.drift_id, OLD.resolved_at
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_drifts_guard ON config_drifts;
CREATE TRIGGER config_drifts_guard BEFORE UPDATE OR DELETE ON config_drifts
  FOR EACH ROW EXECUTE FUNCTION m10_drifts_guard();

DROP TRIGGER IF EXISTS config_drifts_no_truncate ON config_drifts;
CREATE TRIGGER config_drifts_no_truncate BEFORE TRUNCATE ON config_drifts
  FOR EACH STATEMENT EXECUTE FUNCTION m10_forbid_truncate();

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['drift_id','namespace','key','scope','scope_id','desired_version',
                      'effective_version','running_version','expected','actual','detected_at',
                      'resolved_at','resolution']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_drifts' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_drifts 结构与 1004 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
