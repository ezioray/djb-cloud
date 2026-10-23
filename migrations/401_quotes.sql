-- 401 · M04 scheduler-pricing · 供方报价簿（quotes）
-- 规格：M04 §3 Quote 聚合 / §5 数据所有权（保留 90 天）· §6 流程 1（撮合）
--       §8.1 配置键 · §8.2 本模块常量（报价簿刷新 60 s）· INV-01 / INV-02 / INV-13
--       00-conventions §3.1（金额一律整数最小单位）· §7.2（只加不改）
--
-- 设计要点
--   1) **只追加 + 版本化**：quote_version 是整个报价簿的单调版本号（不是单节点版本），
--      内容完全相同的重复报价**不升版本**（不写新行），由 app/scheduling/quotes.py 保证。
--   2) **区间**：ask_price_minor 是供方要价**下界** a_lo（M04 §5 的字段名），
--      price_max_minor 是上界 a_hi（NULL = 不设上限），INV-01 的可成交判定用这两列。
--   3) **状态机**：active → consumed（成交）/ expired（TTL 到期）；禁止回退；
--      superseded 不是状态——新版本通过「更高 quote_version」遮蔽旧版本，旧行自然过期。
--   4) 不建到 nodes(id) 的外键：跨模块只读依赖只能走视图（01-ownership §2），
--      node_id 的存在性由 v_supply_node_snapshot 在写入前校验，DDL 层不耦合 M02 基表。
BEGIN;

CREATE TABLE IF NOT EXISTS quotes (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- 对外 quote_id（UUID 串）
  node_id          TEXT NOT NULL,
  access           TEXT NOT NULL,                                -- A1 / A2 / B（与 02-events 同源）
  model            TEXT NOT NULL,
  unit             TEXT NOT NULL,                                -- token / gpu_second / gb_hour
  ask_price_minor  BIGINT NOT NULL,                              -- 区间下界 a_lo（USD 分）
  price_max_minor  BIGINT,                                       -- 区间上界 a_hi；NULL = +∞
  currency         TEXT NOT NULL DEFAULT 'USD',                   -- INV-13：S1 仅 USD
  ttl_s            INT  NOT NULL,
  state            TEXT NOT NULL DEFAULT 'active',
  quote_version    BIGINT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  consumed_at      TIMESTAMPTZ,

  CONSTRAINT quotes_access_ck   CHECK (access IN ('A1', 'A2', 'B')),
  CONSTRAINT quotes_currency_ck CHECK (currency = 'USD'),
  CONSTRAINT quotes_state_ck    CHECK (state IN ('active', 'consumed', 'expired')),
  CONSTRAINT quotes_price_ck    CHECK (ask_price_minor >= 0),
  CONSTRAINT quotes_price_max_ck CHECK (price_max_minor IS NULL OR price_max_minor >= 0),
  -- 区间必须非空（INV-01）：上界缺省 = 不设上限
  CONSTRAINT quotes_interval_ck
    CHECK (price_max_minor IS NULL OR price_max_minor >= ask_price_minor),
  CONSTRAINT quotes_ttl_ck      CHECK (ttl_s BETWEEN 1 AND 86400),
  CONSTRAINT quotes_version_ck  CHECK (quote_version >= 1),
  CONSTRAINT quotes_expiry_ck   CHECK (expires_at > created_at),
  CONSTRAINT quotes_consumed_ck
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL)),
  CONSTRAINT quotes_node_len_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT quotes_model_len_ck CHECK (char_length(model) BETWEEN 1 AND 200),
  CONSTRAINT quotes_unit_len_ck CHECK (char_length(unit) BETWEEN 1 AND 64),
  -- 同一 (node, access, model, unit) 在同一个版本号上只能有一条
  CONSTRAINT quotes_version_uq UNIQUE (node_id, access, model, unit, quote_version)
);

-- M04 §5 索引：quotes(node_id, model, state)
CREATE INDEX IF NOT EXISTS quotes_node_model_state_idx ON quotes (node_id, model, state);
-- 报价簿取数（按模型/接入方式取最新有效版本）与过期清理（1 min job）
CREATE INDEX IF NOT EXISTS quotes_book_idx      ON quotes (model, access, state, quote_version DESC);
CREATE INDEX IF NOT EXISTS quotes_expiry_idx    ON quotes (expires_at) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS quotes_created_idx   ON quotes (created_at);

-- 只追加 + 状态机守卫：DELETE 永久拒绝；UPDATE 只允许 active → consumed / expired，
-- 且不可变列（价格、区间、版本、TTL、归属）一律不得改动（M04 §3「禁止回退，只能新建」）。
CREATE OR REPLACE FUNCTION m04_quotes_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'quotes 只追加：禁止 DELETE（M04 §3）';
  END IF;

  IF NEW.id <> OLD.id
     OR NEW.node_id <> OLD.node_id
     OR NEW.access <> OLD.access
     OR NEW.model <> OLD.model
     OR NEW.unit <> OLD.unit
     OR NEW.ask_price_minor <> OLD.ask_price_minor
     OR NEW.price_max_minor IS DISTINCT FROM OLD.price_max_minor
     OR NEW.currency <> OLD.currency
     OR NEW.ttl_s <> OLD.ttl_s
     OR NEW.quote_version <> OLD.quote_version
     OR NEW.created_at <> OLD.created_at
     OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION 'quotes 不可变列被修改（只能改 state / consumed_at；新内容请新建版本）';
  END IF;

  IF OLD.state <> 'active' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'quotes 状态机禁止回退：% → %（M04 §3）', OLD.state, NEW.state;
  END IF;

  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS quotes_guard_trg ON quotes;
CREATE TRIGGER quotes_guard_trg
  BEFORE UPDATE OR DELETE ON quotes
  FOR EACH ROW EXECUTE FUNCTION m04_quotes_guard();

COMMENT ON TABLE  quotes IS 'M04 供方报价簿：只追加 + 版本化（内容不变不升版本）；90 天保留';
COMMENT ON COLUMN quotes.ask_price_minor IS '区间下界 a_lo（USD 分，M04 §5 字段名）';
COMMENT ON COLUMN quotes.price_max_minor IS '区间上界 a_hi；NULL = 不设上限（INV-01 单边退化）';
COMMENT ON COLUMN quotes.quote_version IS '报价簿版本：新内容 = max(quote_version)+1；相同内容复用既有版本';
COMMENT ON COLUMN quotes.state IS 'active → consumed（成交）/ expired（TTL）；禁止回退';

COMMIT;
