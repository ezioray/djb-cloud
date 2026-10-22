-- 1006 · M10 配置中心 · 发布单流程约束（T3：状态机 + step-up 不复用 + INV-07 在飞唯一）
-- 规格：M10 §3 发布单状态机与「禁止迁移」（pending_approval → active / expired → approved / active → draft）
--       INV-03（复核 ≠ 发起）· INV-04（冷却，应用层）· INV-07（同 key 单未完结发布单）
--       §6 流程 1（九步）· §7（过期不放行、收口结论入单）
--       product/v4/src/21-config-management.md §21.4.2 / §21.4.3（P0 四件套：step-up 发布与审批各一次）
--
-- 为什么另开 1006：1002 已合并（只加不改），而 1002 的注释明确「状态机触发器留给 T3」。
-- 本文件只做**加列 / 加索引 / 加触发器**，不改 1002 已有列与约束：
--   · publish_step_up_ref / approval_step_up_ref：P0/P1 的两次 step-up 不得复用（§21.4.3）
--   · decision_reason / observation：驳回理由、收口观测结论入单（§6 第 5 步）
--   · uq_inflight：INV-07 的库层保证（在飞 = pending_approval / approved / scheduled / rolling_out）
--   · m10_requests_guard：状态机与不可变列（§3 禁止迁移 + 终止态不可复活）
BEGIN;

ALTER TABLE config_publish_requests
  ADD COLUMN IF NOT EXISTS publish_step_up_ref   TEXT,
  ADD COLUMN IF NOT EXISTS approval_step_up_ref  TEXT,
  ADD COLUMN IF NOT EXISTS decision_reason       TEXT,
  ADD COLUMN IF NOT EXISTS observation           TEXT;

ALTER TABLE config_publish_requests
  DROP CONSTRAINT IF EXISTS config_publish_requests_stepup_ck;
ALTER TABLE config_publish_requests
  ADD CONSTRAINT config_publish_requests_stepup_ck CHECK (
    publish_step_up_ref IS NULL OR approval_step_up_ref IS NULL
    OR publish_step_up_ref <> approval_step_up_ref);

ALTER TABLE config_publish_requests
  DROP CONSTRAINT IF EXISTS config_publish_requests_decision_reason_ck;
ALTER TABLE config_publish_requests
  ADD CONSTRAINT config_publish_requests_decision_reason_ck CHECK (
    decision_reason IS NULL OR char_length(decision_reason) BETWEEN 2 AND 512);

ALTER TABLE config_publish_requests
  DROP CONSTRAINT IF EXISTS config_publish_requests_observation_ck;
ALTER TABLE config_publish_requests
  ADD CONSTRAINT config_publish_requests_observation_ck CHECK (
    observation IS NULL OR char_length(observation) BETWEEN 2 AND 2048);

-- 进入「已复核及之后」的状态，P0/P1 必须有复核人与 approve 决定（P2 单人可发）
ALTER TABLE config_publish_requests
  DROP CONSTRAINT IF EXISTS config_publish_requests_approval_ck;
ALTER TABLE config_publish_requests
  ADD CONSTRAINT config_publish_requests_approval_ck CHECK (
    status NOT IN ('approved', 'scheduled', 'rolling_out', 'active', 'closed')
    OR risk_level = 'P2'
    OR (decision = 'approve' AND cardinality(approved_by) >= 1));

-- INV-07：同 key 同 scope 只允许一个未完结发布单（active 不阻塞下一次发布，收口靠 close）
CREATE UNIQUE INDEX IF NOT EXISTS config_publish_requests_inflight_uq
  ON config_publish_requests (key, scope, scope_id)
  WHERE status IN ('pending_approval', 'approved', 'scheduled', 'rolling_out');

-- ───────────────────────────────────────────────────────────── 状态机（§3）
CREATE OR REPLACE FUNCTION m10_requests_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_publish_requests: DELETE not allowed (发布单保留 ≥3 年)'
      USING ERRCODE = '42501';
  END IF;

  -- 除状态机字段外一律不可变（key / versions / risk / 发起人 / 理由 / 幂等键…）
  IF (to_jsonb(NEW) - ARRAY['status', 'approved_by', 'decision', 'decision_reason', 'gray_plan',
                            'snapshot_before', 'snapshot_after', 'expires_at', 'effective_at',
                            'closed_at', 'observation', 'approval_step_up_ref', 'updated_at'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['status', 'approved_by', 'decision', 'decision_reason', 'gray_plan',
                            'snapshot_before', 'snapshot_after', 'expires_at', 'effective_at',
                            'closed_at', 'observation', 'approval_step_up_ref', 'updated_at'])
  THEN
    RAISE EXCEPTION 'config_publish_requests is immutable: only lifecycle fields may change (% @%)',
      OLD.key, OLD.publish_request_id
      USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT (
      (OLD.status = 'draft' AND NEW.status IN ('pending_approval', 'rejected', 'cancelled'))
      OR (OLD.status = 'pending_approval'
          AND NEW.status IN ('approved', 'rejected', 'cancelled', 'expired'))
      OR (OLD.status = 'approved'
          AND NEW.status IN ('scheduled', 'active', 'cancelled', 'expired'))
      OR (OLD.status = 'scheduled'
          AND NEW.status IN ('rolling_out', 'active', 'failed', 'cancelled', 'expired'))
      OR (OLD.status = 'rolling_out' AND NEW.status IN ('active', 'failed', 'rolled_back'))
      OR (OLD.status = 'active' AND NEW.status IN ('closed', 'rolled_back', 'failed'))
    ) THEN
      RAISE EXCEPTION 'config_publish_requests: illegal transition % -> % (M10 §3)',
        OLD.status, NEW.status
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.status IN ('approved', 'scheduled', 'rolling_out', 'active', 'closed')
     AND NEW.risk_level IN ('P0', 'P1')
     AND (NEW.decision IS DISTINCT FROM 'approve' OR cardinality(NEW.approved_by) = 0) THEN
    RAISE EXCEPTION 'config_publish_requests: P0/P1 must be approved (decision=approve + approved_by) before %',
      NEW.status
      USING ERRCODE = '23514';
  END IF;
  IF NEW.status = 'rejected' AND NEW.decision IS DISTINCT FROM 'reject' THEN
    RAISE EXCEPTION 'config_publish_requests: rejected requires decision=reject'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.status = 'closed' AND (NEW.closed_at IS NULL OR NEW.observation IS NULL) THEN
    RAISE EXCEPTION 'config_publish_requests: closed requires closed_at + observation（收口结论入单）'
      USING ERRCODE = '23514';
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_publish_requests_guard ON config_publish_requests;
CREATE TRIGGER config_publish_requests_guard
  BEFORE UPDATE OR DELETE ON config_publish_requests
  FOR EACH ROW EXECUTE FUNCTION m10_requests_guard();

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['publish_step_up_ref', 'approval_step_up_ref', 'decision_reason',
                      'observation']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_publish_requests'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_publish_requests 结构与 1006 不符，缺列：%', v_missing;
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_indexes
       WHERE schemaname = current_schema()
         AND indexname = 'config_publish_requests_inflight_uq') THEN
    RAISE EXCEPTION 'config_publish_requests 缺 INV-07 在飞唯一索引';
  END IF;
END;
$$;

COMMIT;
