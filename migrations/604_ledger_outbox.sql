-- 604 · M06 账本 · 本地事件投递（m06_outbox）
-- 规格：01-ownership.md §2「每个模块自己的 outbox：<module>_outbox」；M06-ledger.md §5（m06_outbox @ 604）
--       §6 事务边界（凭证 + 行 + 分录 + 余额 + outbox 同一事务）；02-events.md §1 信封 / §2 至少一次投递
--       §3 事件目录（M06 只生产 journal.posted / ledger.reversed / merkle.anchored）
--
-- 设计：
--   1) 写入只追加：DELETE 一律拒绝；唯一允许的变化是 published_at 由 NULL 置为投递完成时刻。
--   2) 事件契约在库里兜底：type 白名单、aggregate_type 与 type 一致、payload 必含信封要求的业务键。
--   3) 投递失败重试由投递器负责（02-events §2：指数退避，不阻塞已提交事务），本表不记重试次数。
BEGIN;

CREATE TABLE IF NOT EXISTS m06_outbox (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),      -- 消费侧幂等键（02-events §1）
  type            TEXT NOT NULL,                                   -- 领域.对象.过去式
  version         INT  NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  producer        TEXT NOT NULL DEFAULT 'M06',
  aggregate_type  TEXT NOT NULL,                                   -- journal_entry / merkle_commitment
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,                                   -- 生产侧业务幂等键
  payload         JSONB NOT NULL,                                  -- 只放事实字段（无正文 / PII / 密钥）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at    TIMESTAMPTZ,                                     -- NULL = 待投递；写入即完成投递标记

  CONSTRAINT m06_outbox_idem_uq UNIQUE (idempotency_key),
  CONSTRAINT m06_outbox_version_ck CHECK (version >= 1),
  CONSTRAINT m06_outbox_producer_ck CHECK (producer = 'M06'),
  CONSTRAINT m06_outbox_type_ck CHECK (
    type IN ('journal.posted', 'ledger.reversed', 'merkle.anchored')   -- 本模块只生产这三个
  ),
  CONSTRAINT m06_outbox_aggregate_ck CHECK (
    (type IN ('journal.posted', 'ledger.reversed') AND aggregate_type = 'journal_entry')
    OR (type = 'merkle.anchored' AND aggregate_type = 'merkle_commitment')
  ),
  CONSTRAINT m06_outbox_aggregate_id_ck CHECK (length(aggregate_id) BETWEEN 1 AND 128),
  CONSTRAINT m06_outbox_trace_ck CHECK (length(trace_id) BETWEEN 1 AND 128),
  CONSTRAINT m06_outbox_idem_len_ck CHECK (length(idempotency_key) BETWEEN 1 AND 200),
  CONSTRAINT m06_outbox_payload_object_ck CHECK (jsonb_typeof(payload) = 'object'),
  -- 02-events §3 / M06 §4.2：每个事件的必含业务键
  CONSTRAINT m06_outbox_payload_ck CHECK (
    (type = 'journal.posted'
       AND payload ?& ARRAY['journal_id', 'event_type', 'amount_minor', 'ref_id'])
    OR (type = 'ledger.reversed'
       AND payload ?& ARRAY['journal_id', 'reverse_of', 'reason_code'])
    OR (type = 'merkle.anchored'
       AND payload ?& ARRAY['root', 'kind', 'period', 'anchored_at'])
  )
);

CREATE INDEX IF NOT EXISTS m06_outbox_pending_idx
  ON m06_outbox (created_at) WHERE published_at IS NULL;

-- 投递标记：只允许 published_at 由 NULL 变非 NULL，其余列一律不得改；DELETE 永远拒绝
CREATE OR REPLACE FUNCTION m06_outbox_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'm06_outbox is append-only: DELETE not allowed (INV-08)'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - 'published_at') IS DISTINCT FROM (to_jsonb(OLD) - 'published_at') THEN
    RAISE EXCEPTION 'm06_outbox is append-only: only published_at may change (INV-08)'
      USING ERRCODE = '42501';
  END IF;
  IF NOT (OLD.published_at IS NULL AND NEW.published_at IS NOT NULL) THEN
    RAISE EXCEPTION 'm06_outbox: only published_at NULL -> NOT NULL is allowed, got % -> %',
      OLD.published_at, NEW.published_at
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS m06_outbox_no_mutation ON m06_outbox;
CREATE TRIGGER m06_outbox_no_mutation BEFORE UPDATE OR DELETE ON m06_outbox
  FOR EACH ROW EXECUTE FUNCTION m06_outbox_guard();
DROP TRIGGER IF EXISTS m06_outbox_no_truncate ON m06_outbox;
CREATE TRIGGER m06_outbox_no_truncate BEFORE TRUNCATE ON m06_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m06_forbid_truncate();   -- 函数在 600 定义

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['event_id','type','version','occurred_at','producer','aggregate_type','aggregate_id',
                      'correlation_id','causation_id','trace_id','idempotency_key','payload',
                      'created_at','published_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'm06_outbox' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'm06_outbox 结构与 604 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
