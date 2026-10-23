-- 800 · M08 支付订单与尝试（payment_orders / payment_attempts）
-- 规格：product/v4/modules/M08-payments-treasury.md §3 领域模型（payment_order / payment_attempt
--       状态机）· §4.1 API（下单 / 查询 / 取消 / 回调）· §5 数据所有权（迁移 800）
--       · §7 失败与降级 · INV-07（整数最小单位 / 一单一币种）· INV-08（provider_txn_id 唯一）
--       产品 §19.6.5.3/19.6.5.4/19.6.5.5（UPG / GIFPay 字段与回调）、§19.10.4 错误码。
--
-- 原则：
--   1) **无真钱、无密钥**：本表只有订单 / 尝试事实，没有卡号、PSP 密钥、完整报文；
--      验签材料只在 KMS，签名结果只记 signature_verified 与 payload_hash。
--   2) **金额一律整数最小单位**：amount_minor 是 USD 分（03-facts §6 金额标度，unit_scale=2），
--      CHECK 拒绝非正数；一单一币种（currency 三字母大写）；不接受浮点（BIGINT 列本身兜底）。
--   3) **状态机只前进**：created → pending → paid → credited，failed / closed / expired 为终态；
--      触发器拒绝终态回退与身份字段改写（应用层再拦一次）。
--   4) **幂等**：下单按 `X-DJB-Idempotency-Key`（scope = 端点）唯一；回调按 provider_txn_id 唯一。
--   5) 可重复执行：IF NOT EXISTS / ADD COLUMN IF NOT EXISTS / CREATE OR REPLACE。
BEGIN;

-- 语句级只追加护栏（TRUNCATE 绕过行级触发器；本模块自带一份，避免依赖 005 的函数）
CREATE OR REPLACE FUNCTION m08_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed（M08）', TG_TABLE_NAME
    USING ERRCODE = '42501';
END $$;

-- 对外单号：PO-YYYYMMDD-NNNNNN（≤32 字符、全局唯一、创建后不变，00-conventions §2）
CREATE SEQUENCE IF NOT EXISTS payment_order_no_seq;

CREATE TABLE IF NOT EXISTS payment_orders (
  order_id        UUID PRIMARY KEY,                       -- UUIDv7（应用生成）
  order_no        TEXT NOT NULL UNIQUE
                  DEFAULT ('PO-' || to_char(now(), 'YYYYMMDD') || '-' ||
                           lpad(nextval('payment_order_no_seq')::text, 6, '0')),
  account_id      TEXT NOT NULL,                          -- M01 账户 id（隔离键）
  tenant_id       TEXT,                                   -- 账户所属租户（可选，便于后台聚合）
  amount_minor    BIGINT NOT NULL,                        -- USD 分（03-facts §6）
  currency        TEXT NOT NULL,                          -- ISO-4217（USD）
  method          TEXT NOT NULL,                          -- card / bank_transfer / wechat / alipay
  provider        TEXT NOT NULL,                          -- mock / upg / gifpay（适配器 id）
  status          TEXT NOT NULL DEFAULT 'created',
  credited_minor  BIGINT NOT NULL DEFAULT 0,              -- 已入账金额（分；重复回调不累加）
  description     TEXT,
  policy_version  TEXT NOT NULL,
  idempotency_key TEXT,                                   -- X-DJB-Idempotency-Key（16..128）
  request_hash    TEXT,                                   -- 下单载荷指纹（同键不同载荷 → 409）
  trace_id        TEXT NOT NULL,
  created_by      TEXT NOT NULL,
  expires_at      TIMESTAMPTZ,                            -- 订单有效期（过期 → expired）
  paid_at         TIMESTAMPTZ,
  credited_at     TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payment_orders_amount_ck CHECK (amount_minor > 0),
  CONSTRAINT payment_orders_credited_ck CHECK (credited_minor >= 0 AND credited_minor <= amount_minor),
  CONSTRAINT payment_orders_currency_ck CHECK (currency ~ '^[A-Z]{3}$'),
  CONSTRAINT payment_orders_method_ck CHECK
    (method IN ('card', 'bank_transfer', 'wechat', 'alipay')),
  CONSTRAINT payment_orders_status_ck CHECK (status IN
    ('created', 'pending', 'paid', 'credited', 'failed', 'closed', 'expired')),
  CONSTRAINT payment_orders_no_ck CHECK (char_length(order_no) BETWEEN 3 AND 32),
  -- paid / credited 必须有 paid_at；credited 必须有 credited_at（状态与时间戳一致）
  CONSTRAINT payment_orders_paid_ck CHECK (status NOT IN ('paid', 'credited') OR paid_at IS NOT NULL),
  CONSTRAINT payment_orders_credited_at_ck CHECK (status <> 'credited' OR credited_at IS NOT NULL),
  CONSTRAINT payment_orders_credited_status_ck CHECK
    (credited_minor = 0 OR status IN ('credited', 'paid'))
);

CREATE UNIQUE INDEX IF NOT EXISTS payment_orders_idem_uq
  ON payment_orders (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS payment_orders_account_idx
  ON payment_orders (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS payment_orders_status_idx
  ON payment_orders (status, created_at DESC);
CREATE INDEX IF NOT EXISTS payment_orders_provider_idx
  ON payment_orders (provider, created_at DESC);

COMMENT ON TABLE payment_orders IS
  'M08 支付订单：整数分 / 一单一币种 / 状态只前进（INV-07）；无卡号、无密钥、无完整报文';

CREATE OR REPLACE FUNCTION m08_orders_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['created->pending', 'created->failed', 'created->closed',
                            'created->expired', 'pending->paid', 'pending->failed',
                            'pending->closed', 'pending->expired', 'paid->credited'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'payment_orders 只追加：禁止 DELETE（对账 / 审计需要）' USING ERRCODE = '42501';
  END IF;
  IF NEW.order_id IS DISTINCT FROM OLD.order_id
     OR NEW.order_no IS DISTINCT FROM OLD.order_no
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
     OR NEW.currency IS DISTINCT FROM OLD.currency
     OR NEW.method IS DISTINCT FROM OLD.method
     OR NEW.provider IS DISTINCT FROM OLD.provider
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'payment_orders 身份字段不可变（订单号 / 金额 / 币种 / 方式）' USING ERRCODE = '42501';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'payment_orders 非法状态迁移：% -> %（§3）', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS payment_orders_guard ON payment_orders;
CREATE TRIGGER payment_orders_guard BEFORE UPDATE OR DELETE ON payment_orders
  FOR EACH ROW EXECUTE FUNCTION m08_orders_guard();

DROP TRIGGER IF EXISTS payment_orders_no_truncate ON payment_orders;
CREATE TRIGGER payment_orders_no_truncate BEFORE TRUNCATE ON payment_orders
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 支付尝试
CREATE TABLE IF NOT EXISTS payment_attempts (
  attempt_id       UUID PRIMARY KEY,
  order_id         UUID NOT NULL REFERENCES payment_orders (order_id),
  provider         TEXT NOT NULL,
  provider_txn_id  TEXT,                                  -- 通道单号（唯一：INV-08）
  provider_status  TEXT NOT NULL,                          -- 通道原始状态（字符串，仅留痕）
  status           TEXT NOT NULL DEFAULT 'initiated',      -- initiated / succeeded / failed
  amount_minor     BIGINT NOT NULL,
  fee_minor        BIGINT NOT NULL DEFAULT 0,
  net_minor        BIGINT NOT NULL DEFAULT 0,
  currency         TEXT NOT NULL,
  signature_verified BOOLEAN NOT NULL DEFAULT FALSE,       -- 回调验签结果（不存签名原文）
  payload_hash     TEXT,                                   -- 原始报文 SHA256（去敏留痕）
  failure_code     TEXT,                                   -- 失败原因码（内部 / 通道码）
  query_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,         -- 回调后「查询二次确认」是否成功
  query_result     TEXT,                                   -- 查询返回的通道状态（留痕，冲突时以查询为准）
  settled_minor    BIGINT,                                 -- E4 到账净额（分）
  settlement_fee_minor BIGINT,                             -- E4 平台补足手续费（分）
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payment_attempts_status_ck CHECK (status IN ('initiated', 'succeeded', 'failed')),
  CONSTRAINT payment_attempts_amount_ck CHECK (amount_minor > 0),
  CONSTRAINT payment_attempts_fee_ck CHECK (fee_minor >= 0 AND net_minor >= 0),
  CONSTRAINT payment_attempts_currency_ck CHECK (currency ~ '^[A-Z]{3}$'),
  CONSTRAINT payment_attempts_txn_ck CHECK
    (provider_txn_id IS NULL OR char_length(provider_txn_id) BETWEEN 1 AND 128),
  CONSTRAINT payment_attempts_settlement_ck CHECK
    (settled_minor IS NULL OR (settlement_fee_minor IS NOT NULL AND settled_minor >= 0
                               AND settlement_fee_minor >= 0))
);

-- INV-08：provider_txn_id 全局唯一（同一通道单号只允许一条尝试 → 重复回调不重复入账）
CREATE UNIQUE INDEX IF NOT EXISTS payment_attempts_txn_uq
  ON payment_attempts (provider, provider_txn_id) WHERE provider_txn_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS payment_attempts_order_idx
  ON payment_attempts (order_id, created_at DESC);
CREATE INDEX IF NOT EXISTS payment_attempts_status_idx
  ON payment_attempts (status, created_at DESC);

COMMENT ON TABLE payment_attempts IS
  'M08 每次向 PSP 发起：provider_txn_id 唯一（INV-08）；只记验签结果与报文哈希，不存签名 / 卡号';

CREATE OR REPLACE FUNCTION m08_attempts_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'payment_attempts 只追加：禁止 DELETE' USING ERRCODE = '42501';
  END IF;
  IF NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
     OR NEW.order_id IS DISTINCT FROM OLD.order_id
     OR NEW.provider IS DISTINCT FROM OLD.provider
     OR (OLD.provider_txn_id IS NOT NULL AND NEW.provider_txn_id IS DISTINCT FROM OLD.provider_txn_id)
     OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
     OR NEW.currency IS DISTINCT FROM OLD.currency
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'payment_attempts 身份字段不可变' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'initiated' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'payment_attempts 终态不可回退：% -> %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS payment_attempts_guard ON payment_attempts;
CREATE TRIGGER payment_attempts_guard BEFORE UPDATE OR DELETE ON payment_attempts
  FOR EACH ROW EXECUTE FUNCTION m08_attempts_guard();

DROP TRIGGER IF EXISTS payment_attempts_no_truncate ON payment_attempts;
CREATE TRIGGER payment_attempts_no_truncate BEFORE TRUNCATE ON payment_attempts
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

COMMIT;