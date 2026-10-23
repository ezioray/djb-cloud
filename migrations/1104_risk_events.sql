-- 1104 · M11 信号流水（risk_events）+ 事件发件箱（risk_outbox）
-- 规格：M11-risk-abuse.md §3（risk_events：signal_type / subject_hash / cluster_id /
--       amount_minor / occurred_at，只追加，12 个月滚动）· §4.2 事件表 · §6 流程 1
--       02-events.md §1（信封）/ §2（本地事务 + outbox，至少一次）/ §5（按 event_id 幂等）
--
-- 说明：
--   1) risk_events 是**信号流水**：只存哈希 / 簇 ID / 金额 / 时间（INV-05），
--      不存明文 IP / 邮箱 / 卡号，也不存阈值（INV-01）——DB CHECK 直接拒绝敏感 / 阈值键；
--   2) risk_outbox 是**基础设施表**（02-events §2 要求）：业务写入与事件入队同事务；
--      type 只允许 02-events 已登记的 4 个 risk.* 事件（未登记事件写不进来）；
--   3) 消费幂等：risk_events.source_event_id 唯一（重放同一 event_id 不重复落库）。
BEGIN;

CREATE TABLE IF NOT EXISTS risk_events (
  event_id        UUID PRIMARY KEY,                  -- 信号流水 id（UUIDv7 由应用生成）
  signal_type     TEXT NOT NULL,                     -- 信号类型（usage / payment_failed / request_failed / device …）
  subject_hash    TEXT NOT NULL,                     -- 加盐哈希 / 簇 ID（INV-05）
  cluster_id      TEXT,                              -- 关联簇（设备 / 支付方式 / 地址族）
  amount_minor    BIGINT,                            -- 金额（MINOR；可空）
  currency        TEXT,
  occurred_at     TIMESTAMPTZ NOT NULL,              -- 事实发生时间
  source_event_id UUID,                              -- 上游事件 id（消费幂等键）
  source_module   TEXT,                              -- 上游模块（M03 / M05 / M08 / M09）
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb, -- 只放元数据（id / 原因码 / 时间）
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT risk_events_signal_ck CHECK (char_length(signal_type) BETWEEN 1 AND 64),
  CONSTRAINT risk_events_subject_ck CHECK (
    char_length(subject_hash) BETWEEN 3 AND 128
    AND subject_hash !~ '@'
    AND subject_hash !~ '^\d{1,3}(\.\d{1,3}){3}$'
    AND subject_hash !~ '^1[3-9]\d{9}$'),
  CONSTRAINT risk_events_amount_ck CHECK (amount_minor IS NULL OR amount_minor >= 0),
  CONSTRAINT risk_events_currency_ck CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
  -- INV-01 / INV-05：payload 不得出现阈值 / 权重 / 名单 / 明文 PII 键
  CONSTRAINT risk_events_payload_ck CHECK (
    NOT (payload ?| ARRAY['threshold', 'thresholds', 'weight', 'weights', 'blocklist',
                          'blacklist', 'allowlist', 'whitelist', 'score_weight',
                          'ip', 'email', 'phone', 'card', 'card_no', 'pan']))
);

-- 消费幂等：source_event_id 唯一（PG 中 NULL 互不相等，无来源事件的流水不受影响）
CREATE UNIQUE INDEX IF NOT EXISTS risk_events_source_uq
  ON risk_events (source_event_id);
CREATE INDEX IF NOT EXISTS idx_events_subject
  ON risk_events (subject_hash, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_signal
  ON risk_events (signal_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_cluster
  ON risk_events (cluster_id, occurred_at DESC) WHERE cluster_id IS NOT NULL;

COMMENT ON TABLE risk_events IS
  'M11 信号流水（只追加，12 个月滚动）：只存哈希 / 簇 ID / 金额 / 时间；无阈值、无明文 PII';

-- 事件发件箱（02-events §2：业务事务 + outbox 同提交，至少一次投递）
CREATE TABLE IF NOT EXISTS risk_outbox (
  id              BIGSERIAL PRIMARY KEY,
  event_id        UUID NOT NULL UNIQUE,              -- 事件信封 event_id（UUIDv7，消费幂等键）
  type            TEXT NOT NULL,                     -- 已登记事件类型（见 CHECK）
  version         INTEGER NOT NULL DEFAULT 1,
  producer        TEXT NOT NULL DEFAULT 'M11',
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT,
  idempotency_key TEXT NOT NULL UNIQUE,              -- 生产侧业务幂等键
  payload         JSONB NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',   -- pending / published / dead
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ,
  published_at    TIMESTAMPTZ,
  last_error      TEXT,
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT risk_outbox_type_ck CHECK (type IN
    ('risk.case.opened', 'risk.case.closed', 'risk.limit.hit', 'risk.action.requested')),
  CONSTRAINT risk_outbox_status_ck CHECK (status IN ('pending', 'published', 'dead')),
  CONSTRAINT risk_outbox_version_ck CHECK (version >= 1),
  CONSTRAINT risk_outbox_attempts_ck CHECK (attempts BETWEEN 0 AND 8),
  CONSTRAINT risk_outbox_aggregate_ck CHECK (char_length(aggregate_id) BETWEEN 1 AND 128),
  -- INV-01：事件 payload 不得出现阈值 / 权重 / 名单键
  CONSTRAINT risk_outbox_payload_ck CHECK (
    NOT (payload ?| ARRAY['threshold', 'thresholds', 'weight', 'weights', 'blocklist',
                          'blacklist', 'allowlist', 'whitelist', 'score_weight']))
);

CREATE INDEX IF NOT EXISTS risk_outbox_pending_idx
  ON risk_outbox (status, next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS risk_outbox_aggregate_idx
  ON risk_outbox (aggregate_type, aggregate_id, occurred_at DESC);

COMMENT ON TABLE risk_outbox IS
  'M11 事件发件箱（基础设施表）：只允许 02-events 已登记的 4 个 risk.* 事件；与业务写入同事务';

-- 信封不可改写：只允许投递状态机字段变化
CREATE OR REPLACE FUNCTION m11_outbox_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'risk_outbox 只追加：禁止 DELETE（投递失败进 dead，人工重放）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.type IS DISTINCT FROM OLD.type
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.payload IS DISTINCT FROM OLD.payload
     OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at THEN
    RAISE EXCEPTION 'risk_outbox 信封不可改写（02-events §1）' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS risk_outbox_guard ON risk_outbox;
CREATE TRIGGER risk_outbox_guard BEFORE UPDATE OR DELETE ON risk_outbox
  FOR EACH ROW EXECUTE FUNCTION m11_outbox_guard();

DROP TRIGGER IF EXISTS risk_outbox_no_truncate ON risk_outbox;
CREATE TRIGGER risk_outbox_no_truncate BEFORE TRUNCATE ON risk_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m11_forbid_truncate();

-- 信号流水只追加
DROP TRIGGER IF EXISTS risk_events_no_truncate ON risk_events;
CREATE TRIGGER risk_events_no_truncate BEFORE TRUNCATE ON risk_events
  FOR EACH STATEMENT EXECUTE FUNCTION m11_forbid_truncate();

CREATE OR REPLACE FUNCTION m11_events_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'risk_events 只追加：禁止 %（12 个月滚动由保留任务负责）', TG_OP
    USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS risk_events_guard ON risk_events;
CREATE TRIGGER risk_events_guard BEFORE UPDATE OR DELETE ON risk_events
  FOR EACH ROW EXECUTE FUNCTION m11_events_guard();

COMMIT;
