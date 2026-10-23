-- 1402 · M16 平台基础设施 · 事件 outbox（m16_outbox）
-- 规格：01-ownership.md §2「每个模块自己的 outbox：<module>_outbox」
--       M16-platform-infra.md §4.2（生产 audit.appended）§5（outbox 经 m16_outbox 投递）
--       §6 事务边界（审计条目与 m16_outbox 同本地事务；审计追加独立且先于对外宣告）
--       02-events.md §1 信封 / §2 至少一次投递 / §3 目录（audit.appended: audit_id, actor, action, hash）
--
-- 语义：
--   1) **同事务**：审计条目与事件在同一事务里落库；事务失败则事件不存在（不撤销已提交的审计）。
--   2) **只追加**：写入后信封不可改；唯一允许的变化是 published_at 由 NULL 置为投递完成时刻。
--   3) **事件白名单**：本模块 S1 只生产 audit.appended（deploy.completed / backup.completed 属 T6，
--      落地时走新迁移追加枚举值——只加不改）。
--   4) **幂等**：idempotency_key 唯一；消费侧再按 event_id 幂等（02-events §2.1）。
--   5) payload 只放运维事实：audit_id / actor / action / hash / seq，不含正文与凭据。
BEGIN;

CREATE TABLE IF NOT EXISTS m16_outbox (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type            TEXT        NOT NULL,
  version         INTEGER     NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  producer        TEXT        NOT NULL DEFAULT 'M16',
  aggregate_type  TEXT        NOT NULL,
  aggregate_id    TEXT        NOT NULL,
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT        NOT NULL,
  idempotency_key TEXT        NOT NULL,
  payload         JSONB       NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at    TIMESTAMPTZ                              -- NULL = 待投递
);

ALTER TABLE m16_outbox DROP CONSTRAINT IF EXISTS m16_outbox_type_ck;
ALTER TABLE m16_outbox ADD CONSTRAINT m16_outbox_type_ck
  CHECK (type IN ('audit.appended')) NOT VALID;

ALTER TABLE m16_outbox DROP CONSTRAINT IF EXISTS m16_outbox_producer_ck;
ALTER TABLE m16_outbox ADD CONSTRAINT m16_outbox_producer_ck
  CHECK (producer = 'M16') NOT VALID;

ALTER TABLE m16_outbox DROP CONSTRAINT IF EXISTS m16_outbox_aggregate_ck;
ALTER TABLE m16_outbox ADD CONSTRAINT m16_outbox_aggregate_ck
  CHECK (aggregate_type = 'audit_entry') NOT VALID;

ALTER TABLE m16_outbox DROP CONSTRAINT IF EXISTS m16_outbox_version_ck;
ALTER TABLE m16_outbox ADD CONSTRAINT m16_outbox_version_ck
  CHECK (version >= 1) NOT VALID;

ALTER TABLE m16_outbox DROP CONSTRAINT IF EXISTS m16_outbox_text_ck;
ALTER TABLE m16_outbox ADD CONSTRAINT m16_outbox_text_ck
  CHECK (char_length(aggregate_id) BETWEEN 1 AND 128
     AND char_length(trace_id) BETWEEN 1 AND 128
     AND char_length(idempotency_key) BETWEEN 1 AND 200
     AND (correlation_id IS NULL OR char_length(correlation_id) BETWEEN 1 AND 128)) NOT VALID;

-- 02-events §3 + M16 §4.2：audit.appended 的必含业务键
ALTER TABLE m16_outbox DROP CONSTRAINT IF EXISTS m16_outbox_payload_ck;
ALTER TABLE m16_outbox ADD CONSTRAINT m16_outbox_payload_ck
  CHECK (jsonb_typeof(payload) = 'object'
     AND payload ?& ARRAY['audit_id', 'actor', 'action', 'hash', 'seq']) NOT VALID;

DROP INDEX IF EXISTS m16_outbox_idempotency_uq;
CREATE UNIQUE INDEX m16_outbox_idempotency_uq
  ON m16_outbox (idempotency_key);

DROP INDEX IF EXISTS m16_outbox_pending_idx;
CREATE INDEX m16_outbox_pending_idx
  ON m16_outbox (occurred_at) WHERE published_at IS NULL;

DROP INDEX IF EXISTS m16_outbox_aggregate_idx;
CREATE INDEX m16_outbox_aggregate_idx
  ON m16_outbox (aggregate_id, occurred_at DESC);

-- ────────────────────────────────────────────────────────── 投递护栏
CREATE OR REPLACE FUNCTION m16_outbox_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['published_at'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'm16_outbox is append-only: DELETE not allowed' USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'm16_outbox: envelope is immutable, only published_at may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
    RAISE EXCEPTION 'm16_outbox: published_at cannot be changed once set' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS m16_outbox_guard ON m16_outbox;
CREATE TRIGGER m16_outbox_guard BEFORE UPDATE OR DELETE ON m16_outbox
  FOR EACH ROW EXECUTE FUNCTION m16_outbox_guard();

DROP TRIGGER IF EXISTS m16_outbox_no_truncate ON m16_outbox;
CREATE TRIGGER m16_outbox_no_truncate BEFORE TRUNCATE ON m16_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m16_forbid_truncate();

COMMENT ON TABLE m16_outbox IS
  'M16 事件 outbox（M16 §5 / 迁移 1402）：与审计条目同事务写入；至少一次投递；只追加';
COMMENT ON COLUMN m16_outbox.payload IS
  'audit.appended 只放 audit_id / actor / action / hash / seq（02-events §1：不放正文与凭据）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                   AND indexname = 'm16_outbox_idempotency_uq') THEN
    RAISE EXCEPTION '1402: 缺唯一索引 m16_outbox_idempotency_uq';
  END IF;
END
$$;

COMMIT;
