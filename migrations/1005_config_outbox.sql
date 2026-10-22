-- 1005 · M10 配置中心 · 事件 outbox（config_outbox）
-- 规格：M10 §5（config_outbox @ 1005，保留「已发布 30 天」）· §6 事务边界
--       （version + publish_request + 本模块 outbox 同一事务）· §4.2 三个生产事件
--       01-ownership §2（R-4 已裁决：<module>_outbox 登记为 config_outbox）
--       02-events §1 信封 / §2 至少一次投递 / §3 事件目录
--
-- 设计（与 604 m06_outbox 同款）：
--   1) 写入只追加：DELETE / TRUNCATE 拒绝；唯一允许的变化是 published_at 由 NULL 置为投递完成时刻。
--   2) 事件契约在库里兜底：type 白名单（本模块只生产三个）、producer 固定 M10、aggregate_type
--      固定 config_key、payload 必含 02-events §3 的业务键。
--   3) 投递重试由投递器负责（02-events §2 指数退避），失败不得回滚已提交的业务事务。
BEGIN;

CREATE TABLE IF NOT EXISTS config_outbox (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),      -- 消费侧幂等键（02-events §1）
  type            TEXT NOT NULL,                                   -- 领域.对象.过去式
  version         INT  NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  producer        TEXT NOT NULL DEFAULT 'M10',
  aggregate_type  TEXT NOT NULL,                                   -- 本模块统一 config_key
  aggregate_id    TEXT NOT NULL,                                   -- key（同 key 内有序）
  correlation_id  TEXT,                                            -- 关联发布单 / 扫描批次
  causation_id    UUID,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,                                   -- 生产侧业务幂等键
  payload         JSONB NOT NULL,                                  -- 只放事实字段（无正文 / PII / 密钥）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at    TIMESTAMPTZ,                                     -- NULL = 待投递

  CONSTRAINT config_outbox_idem_uq UNIQUE (idempotency_key),
  CONSTRAINT config_outbox_version_ck CHECK (version >= 1),
  CONSTRAINT config_outbox_producer_ck CHECK (producer = 'M10'),
  CONSTRAINT config_outbox_aggregate_type_ck CHECK (aggregate_type = 'config_key'),
  CONSTRAINT config_outbox_type_ck CHECK (
    type IN ('config.published', 'config.rolled_back', 'config.drift_detected')),
  CONSTRAINT config_outbox_aggregate_id_ck CHECK (char_length(aggregate_id) BETWEEN 1 AND 128),
  CONSTRAINT config_outbox_trace_ck CHECK (char_length(trace_id) BETWEEN 1 AND 128),
  CONSTRAINT config_outbox_idem_len_ck CHECK (char_length(idempotency_key) BETWEEN 1 AND 200),
  CONSTRAINT config_outbox_payload_object_ck CHECK (jsonb_typeof(payload) = 'object'),
  -- 02-events §3 / M10 §4.2：每个事件的必含业务键
  CONSTRAINT config_outbox_payload_ck CHECK (
    (type = 'config.published'
       AND payload ?& ARRAY['namespace', 'key', 'version', 'risk_level', 'policy_version',
                            'effective_at'])
    OR (type = 'config.rolled_back'
       AND payload ?& ARRAY['namespace', 'key', 'version', 'rollback_to', 'reason_code'])
    OR (type = 'config.drift_detected'
       AND payload ?& ARRAY['namespace', 'key', 'expected', 'actual', 'detected_at'])
  )
);

CREATE INDEX IF NOT EXISTS config_outbox_pending_idx
  ON config_outbox (created_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS config_outbox_aggregate_idx
  ON config_outbox (aggregate_type, aggregate_id, created_at);

-- 投递标记：只允许 published_at 由 NULL 变非 NULL；其余列一律不得改；DELETE 永远拒绝
CREATE OR REPLACE FUNCTION m10_outbox_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'config_outbox is append-only: DELETE not allowed'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - 'published_at') IS DISTINCT FROM (to_jsonb(OLD) - 'published_at') THEN
    RAISE EXCEPTION 'config_outbox is append-only: only published_at may change'
      USING ERRCODE = '42501';
  END IF;
  IF NOT (OLD.published_at IS NULL AND NEW.published_at IS NOT NULL) THEN
    RAISE EXCEPTION 'config_outbox: only published_at NULL -> NOT NULL is allowed, got % -> %',
      OLD.published_at, NEW.published_at
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_outbox_no_mutation ON config_outbox;
CREATE TRIGGER config_outbox_no_mutation BEFORE UPDATE OR DELETE ON config_outbox
  FOR EACH ROW EXECUTE FUNCTION m10_outbox_guard();

DROP TRIGGER IF EXISTS config_outbox_no_truncate ON config_outbox;
CREATE TRIGGER config_outbox_no_truncate BEFORE TRUNCATE ON config_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m10_forbid_truncate();

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['event_id','type','version','occurred_at','producer','aggregate_type',
                      'aggregate_id','correlation_id','causation_id','trace_id','idempotency_key',
                      'payload','created_at','published_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_outbox' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_outbox 结构与 1005 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
