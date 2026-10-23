-- 403 · M04 scheduler-pricing · 成交锁（bookings）
-- 规格：M04 §3 Booking 聚合 / §5 数据所有权（保留 90 天）· §6 流程 1（撮合，同步）
--       §8.2 booking TTL 60 s · 02-events booking.created / booking.expired
--       INV-01（可成交）· INV-02（成交价落在交集内）
--
-- 设计要点
--   1) 撮合在同一事务里完成三件事：写 bookings(held) + quotes.state=consumed
--      + 发 booking.created（事件经注入的 publisher，见 app/scheduling/events.py）。
--   2) 生命周期：held → consumed（业务消费完成）/ expired（TTL 到期）；禁止回退。
--   3) 价格是**成交事实**：不可变；改价只能新建 booking。
BEGIN;

CREATE TABLE IF NOT EXISTS bookings (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- 对外 booking_id（UUID 串）
  quote_id     UUID NOT NULL REFERENCES quotes(id) ON DELETE RESTRICT,
  bid_id       UUID          REFERENCES bids(id)   ON DELETE RESTRICT,
  node_id      TEXT NOT NULL,
  tenant_id    UUID NOT NULL,
  request_id   TEXT,                                          -- 02-events booking.created.request_id
  price_minor  BIGINT NOT NULL,
  strategy     TEXT NOT NULL,
  state        TEXT NOT NULL DEFAULT 'held',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  consumed_at  TIMESTAMPTZ,

  CONSTRAINT bookings_state_ck   CHECK (state IN ('held', 'consumed', 'expired')),
  CONSTRAINT bookings_price_ck   CHECK (price_minor >= 0),
  CONSTRAINT bookings_expiry_ck  CHECK (expires_at > created_at),
  CONSTRAINT bookings_strategy_ck CHECK (strategy IN ('mid', 'floor', 'ceiling')),
  CONSTRAINT bookings_consumed_ck
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL)),
  CONSTRAINT bookings_node_len_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT bookings_request_len_ck
    CHECK (request_id IS NULL OR char_length(request_id) BETWEEN 1 AND 128)
);

-- M04 §5 索引：bookings(expires_at)（过期清理 1 min）；另加同事务查询用索引
CREATE INDEX IF NOT EXISTS bookings_expiry_idx   ON bookings (expires_at) WHERE state = 'held';
CREATE INDEX IF NOT EXISTS bookings_node_idx     ON bookings (node_id, state);
CREATE INDEX IF NOT EXISTS bookings_tenant_idx   ON bookings (tenant_id, state);
CREATE INDEX IF NOT EXISTS bookings_quote_idx    ON bookings (quote_id);

-- 只追加 + 状态机守卫：成交价与归属不可变；held 只能前进到 consumed / expired
CREATE OR REPLACE FUNCTION m04_bookings_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'bookings 只追加：禁止 DELETE（M04 §3）';
  END IF;

  IF NEW.id <> OLD.id
     OR NEW.quote_id <> OLD.quote_id
     OR NEW.bid_id IS DISTINCT FROM OLD.bid_id
     OR NEW.node_id <> OLD.node_id
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.price_minor <> OLD.price_minor
     OR NEW.strategy <> OLD.strategy
     OR NEW.created_at <> OLD.created_at
     OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION 'bookings 不可变列被修改（只能改 state / consumed_at）';
  END IF;

  IF OLD.state <> 'held' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'bookings 状态机禁止回退：% → %（M04 §3）', OLD.state, NEW.state;
  END IF;

  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS bookings_guard_trg ON bookings;
CREATE TRIGGER bookings_guard_trg
  BEFORE UPDATE OR DELETE ON bookings
  FOR EACH ROW EXECUTE FUNCTION m04_bookings_guard();

COMMENT ON TABLE bookings IS 'M04 成交锁：held → consumed / expired；TTL 60 s（§8.2）；90 天保留';

COMMIT;
