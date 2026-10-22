-- 1007 · M10 配置中心 · T4：紧急版本（kill switch）+ 事件投递状态（DLQ）
-- 规格：M10 §6 流程 3（kill switch：ttl ≤86400、只收紧、单人可发、到期自动回上一生效版本）
--       §7（失败与补偿）· 02-events §2（至少一次投递 / 指数退避 / 8 次后进死信并告警）
--       01-ownership §2（config_versions / config_outbox 均归 M10）
--
-- 只加不改：给 1001 的 config_versions 加紧急版本四列、给 1005 的 config_outbox 加投递三列；
-- 用 CREATE OR REPLACE 升级两个护栏函数，并使 1001/1005 的触发器自动使用新函数体（OID 不变）：
--   · m10_versions_guard：紧急版本（emergency=true）与系统动作（published_by='system:*'）
--     不要求人工复核人（INV-03 的人工口径不适用于止损与自动恢复）；
--   · m10_outbox_guard：投递器可以改 delivery_attempts / last_error / dead_lettered_at，
--     以及 published_at 一次置位；其余列仍不可变。
BEGIN;

-- ───────────────────────────────────────────────────────────── 紧急版本（kill switch）
ALTER TABLE config_versions
  ADD COLUMN IF NOT EXISTS emergency             BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS kill_switch_ttl_s     INTEGER,
  ADD COLUMN IF NOT EXISTS kill_switch_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS kill_switch_prev_version INTEGER;

ALTER TABLE config_versions
  DROP CONSTRAINT IF EXISTS config_versions_emergency_ck;
ALTER TABLE config_versions
  ADD CONSTRAINT config_versions_emergency_ck CHECK (
    (NOT emergency AND kill_switch_ttl_s IS NULL AND kill_switch_expires_at IS NULL)
    OR (emergency AND kill_switch_ttl_s BETWEEN 1 AND 86400
        AND kill_switch_expires_at IS NOT NULL));

ALTER TABLE config_versions
  DROP CONSTRAINT IF EXISTS config_versions_kill_prev_ck;
ALTER TABLE config_versions
  ADD CONSTRAINT config_versions_kill_prev_ck CHECK (
    kill_switch_prev_version IS NULL OR kill_switch_prev_version >= 1);

CREATE INDEX IF NOT EXISTS config_versions_kill_active_idx
  ON config_versions (kill_switch_expires_at)
  WHERE emergency AND status = 'active';

-- 升级版本护栏：紧急/系统动作豁免「人工复核人」要求（其余规则一字不改）
CREATE OR REPLACE FUNCTION m10_versions_guard() RETURNS trigger AS $$
DECLARE
  v_risk TEXT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_versions is append-only: DELETE not allowed (INV-01/INV-09)'
      USING ERRCODE = '42501';
  END IF;

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

  IF NOT (OLD.status = 'draft' AND NEW.status = 'active') THEN
    IF NEW.published_by IS DISTINCT FROM OLD.published_by
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.effective_at IS DISTINCT FROM OLD.effective_at THEN
      RAISE EXCEPTION 'config_versions: published_by/approved_by/effective_at only set when activating (% @v%)',
        OLD.key, OLD.version
        USING ERRCODE = '42501';
    END IF;
  ELSE
    SELECT risk_level INTO v_risk FROM config_items
     WHERE namespace = OLD.namespace AND key = OLD.key;
    -- T4：紧急版本（kill switch）与系统动作（自动恢复）不走人工复核（§21.4.2 流程 3）
    IF v_risk IN ('P0', 'P1') AND NOT NEW.emergency
       AND NEW.published_by NOT LIKE 'system:%' THEN
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

-- 回滚发布单记录目标版本（幂等判定与事件生成都用它；只加列）
ALTER TABLE config_publish_requests
  ADD COLUMN IF NOT EXISTS rollback_target_version INTEGER;
ALTER TABLE config_publish_requests
  DROP CONSTRAINT IF EXISTS config_publish_requests_rollback_target_ck;
ALTER TABLE config_publish_requests
  ADD CONSTRAINT config_publish_requests_rollback_target_ck CHECK (
    rollback_target_version IS NULL OR rollback_target_version >= 1);

-- 漂移比较门槛：允许「消费端有版本、平台还没有 active」也算漂移（expected=null / actual=9），
-- 因此从「至少两源」放宽为「至少一源」（1004 的其余约束不动）。
ALTER TABLE config_drifts DROP CONSTRAINT IF EXISTS config_drifts_pairs_ck;
ALTER TABLE config_drifts
  ADD CONSTRAINT config_drifts_pairs_ck CHECK (
    desired_version IS NOT NULL OR effective_version IS NOT NULL OR running_version IS NOT NULL);

-- ───────────────────────────────────────────────────────────── 事件投递状态（DLQ）
ALTER TABLE config_outbox
  ADD COLUMN IF NOT EXISTS delivery_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_error        TEXT,
  ADD COLUMN IF NOT EXISTS dead_lettered_at  TIMESTAMPTZ;

ALTER TABLE config_outbox
  DROP CONSTRAINT IF EXISTS config_outbox_attempts_ck;
ALTER TABLE config_outbox
  ADD CONSTRAINT config_outbox_attempts_ck CHECK (delivery_attempts BETWEEN 0 AND 8);

ALTER TABLE config_outbox
  DROP CONSTRAINT IF EXISTS config_outbox_last_error_ck;
ALTER TABLE config_outbox
  ADD CONSTRAINT config_outbox_last_error_ck CHECK (
    last_error IS NULL OR char_length(last_error) BETWEEN 1 AND 512);

-- 待投递索引排除死信（死信只能人工重放，02-events §2）
DROP INDEX IF EXISTS config_outbox_pending_idx;
CREATE INDEX IF NOT EXISTS config_outbox_pending_idx
  ON config_outbox (created_at)
  WHERE published_at IS NULL AND dead_lettered_at IS NULL;

-- 升级 outbox 护栏：投递器可改三列；published_at / dead_lettered_at 只能 NULL→NOT NULL
CREATE OR REPLACE FUNCTION m10_outbox_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_outbox is append-only: DELETE not allowed'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['published_at', 'delivery_attempts', 'last_error', 'dead_lettered_at'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['published_at', 'delivery_attempts', 'last_error', 'dead_lettered_at'])
  THEN
    RAISE EXCEPTION 'config_outbox is append-only: only delivery fields may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
    RAISE EXCEPTION 'config_outbox: published_at is write-once (% -> %)',
      OLD.published_at, NEW.published_at
      USING ERRCODE = '42501';
  END IF;
  IF OLD.dead_lettered_at IS NOT NULL AND NEW.dead_lettered_at IS DISTINCT FROM OLD.dead_lettered_at THEN
    RAISE EXCEPTION 'config_outbox: dead_lettered_at is write-once'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.delivery_attempts < OLD.delivery_attempts THEN
    RAISE EXCEPTION 'config_outbox: delivery_attempts must not decrease (% -> %)',
      OLD.delivery_attempts, NEW.delivery_attempts
      USING ERRCODE = '42501';
  END IF;
  IF NEW.published_at IS NOT NULL AND NEW.dead_lettered_at IS NOT NULL THEN
    RAISE EXCEPTION 'config_outbox: event cannot be both published and dead-lettered'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['emergency', 'kill_switch_ttl_s', 'kill_switch_expires_at',
                      'kill_switch_prev_version']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_versions' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_versions 结构与 1007 不符，缺列：%', v_missing;
  END IF;

  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['rollback_target_version']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_publish_requests'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_publish_requests 结构与 1007 不符，缺列：%', v_missing;
  END IF;

  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['delivery_attempts', 'last_error', 'dead_lettered_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_outbox' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_outbox 结构与 1007 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
