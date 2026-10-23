-- 402 · M04 scheduler-pricing · 用方出价簿（bids）
-- 规格：M04 §3 Bid 聚合 / §5 数据所有权（保留 90 天）· INV-01 / INV-02 / INV-13
--       04-api-contracts §2 · spec BidRequest（min_price 缺省 0、max_price 缺省不设上限）
--
-- 设计要点
--   1) 只追加 + 版本化：bid_version 与报价簿同款语义（内容不变不升版本），
--      新版本通过更高 bid_version 遮蔽旧版本；旧行 TTL 到期转 expired。
--   2) 区间：min_price_minor = b_lo（缺省 0），max_price_minor = b_hi（NULL = +∞）。
--   3) 状态机：active → expired（§3 生命周期）；不出现 consumed——成交锁由 bookings 承担，
--      「本端点不锁量」（spec BidRequest 描述）。
BEGIN;

CREATE TABLE IF NOT EXISTS bids (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- 对外 bid_id（UUID 串）
  tenant_id        UUID NOT NULL,                                -- M01 租户（不建 FK：跨模块只读）
  model            TEXT NOT NULL,
  min_price_minor  BIGINT NOT NULL DEFAULT 0,                     -- 区间下界 b_lo
  max_price_minor  BIGINT,                                        -- 区间上界 b_hi；NULL = +∞
  strategy         TEXT NOT NULL DEFAULT 'mid',                   -- mid / floor / ceiling
  currency         TEXT NOT NULL DEFAULT 'USD',
  state            TEXT NOT NULL DEFAULT 'active',
  bid_version      BIGINT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,

  CONSTRAINT bids_strategy_ck CHECK (strategy IN ('mid', 'floor', 'ceiling')),
  CONSTRAINT bids_currency_ck CHECK (currency = 'USD'),
  CONSTRAINT bids_state_ck    CHECK (state IN ('active', 'expired')),
  CONSTRAINT bids_price_ck    CHECK (min_price_minor >= 0),
  CONSTRAINT bids_price_max_ck CHECK (max_price_minor IS NULL OR max_price_minor >= 0),
  CONSTRAINT bids_interval_ck
    CHECK (max_price_minor IS NULL OR max_price_minor >= min_price_minor),
  CONSTRAINT bids_version_ck  CHECK (bid_version >= 1),
  CONSTRAINT bids_expiry_ck   CHECK (expires_at > created_at),
  CONSTRAINT bids_model_len_ck CHECK (char_length(model) BETWEEN 1 AND 200),
  CONSTRAINT bids_version_uq UNIQUE (tenant_id, model, bid_version)
);

-- M04 §5 索引：bids(tenant_id, model, state)
CREATE INDEX IF NOT EXISTS bids_tenant_model_state_idx ON bids (tenant_id, model, state);
CREATE INDEX IF NOT EXISTS bids_book_idx   ON bids (model, state, bid_version DESC);
CREATE INDEX IF NOT EXISTS bids_expiry_idx ON bids (expires_at) WHERE state = 'active';

-- 只追加 + 状态机守卫（与 401 同款）
CREATE OR REPLACE FUNCTION m04_bids_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'bids 只追加：禁止 DELETE（M04 §3）';
  END IF;

  IF NEW.id <> OLD.id
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.model <> OLD.model
     OR NEW.min_price_minor <> OLD.min_price_minor
     OR NEW.max_price_minor IS DISTINCT FROM OLD.max_price_minor
     OR NEW.strategy <> OLD.strategy
     OR NEW.currency <> OLD.currency
     OR NEW.bid_version <> OLD.bid_version
     OR NEW.created_at <> OLD.created_at
     OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION 'bids 不可变列被修改（只能改 state；新内容请新建版本）';
  END IF;

  IF OLD.state <> 'active' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'bids 状态机禁止回退：% → %（M04 §3）', OLD.state, NEW.state;
  END IF;

  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS bids_guard_trg ON bids;
CREATE TRIGGER bids_guard_trg
  BEFORE UPDATE OR DELETE ON bids
  FOR EACH ROW EXECUTE FUNCTION m04_bids_guard();

COMMENT ON TABLE  bids IS 'M04 用方出价簿：只追加 + 版本化；不锁量（成交锁在 bookings）；90 天保留';
COMMENT ON COLUMN bids.min_price_minor IS '区间下界 b_lo（缺省 0）';
COMMENT ON COLUMN bids.max_price_minor IS '区间上界 b_hi；NULL = 不设上限（INV-01 单边退化）';

COMMIT;
