-- 803 · M08 退款申请（refund_requests）
-- 规格：M08 §3（refund_request requested → approved → executing → succeeded / failed / cancelled；
--       窗口 14 天）· §5 数据所有权（迁移 803）· §6 流程 5（申请 → 双人 + 24h 冷却 → 原路打款 → E11
--       → refund.completed；失败转工单，不换路）
--       · INV-12（只回原路、≤14 天、≤已付未消耗；不向第三方地址退款）
--       · 03-facts §5（退款 14 天 / 原路 / 扣渠道费与网络费 / 唯一 refund_request）
--       · 产品 §19.9.2、§19.6.5.6、§19.10.4（40917 退款处理中 / 40918 退款失败）
--
-- 原则：
--   1) 同一订单同一时刻最多 1 条未结退款（部分唯一索引）——重复申请 409 / 40917；
--   2) 原路信息 immutable：original_route_hash 与 original_route 一经写入不可改（不得改第三方地址）；
--   3) 双人：approved_by ≠ requested_by（INV-12）；24h 冷却由 cooldown_until 表达；
--   4) E11 的 journal_id 只作引用（账本由 M06 落，本模块不写 journal_*）。
BEGIN;

CREATE SEQUENCE IF NOT EXISTS refund_no_seq;

CREATE TABLE IF NOT EXISTS refund_requests (
  refund_request_id UUID PRIMARY KEY,
  refund_no         TEXT NOT NULL UNIQUE
                    DEFAULT ('RF-' || to_char(now(), 'YYYYMMDD') || '-' ||
                             lpad(nextval('refund_no_seq')::text, 6, '0')),
  account_id        TEXT NOT NULL,
  order_no          TEXT NOT NULL,
  payment_ref       TEXT NOT NULL,                       -- PSP provider_txn_id / 链上 tx_hash
  amount_minor      BIGINT NOT NULL,                     -- 申请金额（USD 分）
  currency          TEXT NOT NULL,
  reason_code       TEXT NOT NULL,
  evidence_ref      TEXT,                                -- 证据引用（不存正文）
  original_route    TEXT NOT NULL,                       -- 原路信息（卡令牌引用 / 原地址）
  original_route_hash TEXT NOT NULL,                     -- 原路指纹（不可改；用于「改第三方地址」拦截）
  status            TEXT NOT NULL DEFAULT 'requested',
  deadline_at       TIMESTAMPTZ NOT NULL,                -- 原订单 paid_at + 14 天（窗口）
  requested_by      TEXT NOT NULL,
  approved_by       TEXT,
  approved_at       TIMESTAMPTZ,
  cooldown_until    TIMESTAMPTZ NOT NULL,                -- 申请时刻 + 24h（REFUND_COOLDOWN_H）
  executing_at      TIMESTAMPTZ,
  succeeded_at      TIMESTAMPTZ,
  failed_at         TIMESTAMPTZ,
  failure_code      TEXT,
  journal_id        UUID,                                -- E11 记账结果（M06）
  idempotency_key   TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT refund_requests_status_ck CHECK (status IN
    ('requested', 'approved', 'executing', 'succeeded', 'failed', 'cancelled')),
  CONSTRAINT refund_requests_amount_ck CHECK (amount_minor > 0),
  CONSTRAINT refund_requests_currency_ck CHECK (currency ~ '^[A-Z]{3}$'),
  CONSTRAINT refund_requests_reason_ck CHECK (char_length(reason_code) BETWEEN 1 AND 64),
  -- INV-12：双人（审批人 ≠ 申请人）
  CONSTRAINT refund_requests_sod_ck CHECK
    (approved_by IS NULL OR approved_by <> requested_by),
  CONSTRAINT refund_requests_approved_ck CHECK
    (status NOT IN ('approved', 'executing', 'succeeded')
     OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)),
  CONSTRAINT refund_requests_succeeded_ck CHECK (status <> 'succeeded' OR succeeded_at IS NOT NULL),
  CONSTRAINT refund_requests_failed_ck CHECK (status <> 'failed' OR failed_at IS NOT NULL),
  CONSTRAINT refund_requests_window_ck CHECK (deadline_at > created_at - INTERVAL '1 day')
);

-- 同一订单同一时刻最多 1 条未结退款（唯一 refund_request 的落点）
CREATE UNIQUE INDEX IF NOT EXISTS uq_refund_open
  ON refund_requests (order_no)
  WHERE status IN ('requested', 'approved', 'executing');
CREATE UNIQUE INDEX IF NOT EXISTS refund_requests_idem_uq
  ON refund_requests (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS refund_requests_account_idx
  ON refund_requests (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS refund_requests_status_idx
  ON refund_requests (status, deadline_at);

COMMENT ON TABLE refund_requests IS
  'M08 退款申请（唯一申请表）：14 天窗口 / 原路 / 双人 24h 冷却（INV-12）；账本结果只存 journal_id';

CREATE OR REPLACE FUNCTION m08_refunds_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['requested->approved', 'requested->cancelled', 'requested->failed',
                            'approved->executing', 'approved->cancelled',
                            'executing->succeeded', 'executing->failed'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'refund_requests 只追加：禁止 DELETE（退款凭证保留 ≥5 年）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.refund_request_id IS DISTINCT FROM OLD.refund_request_id
     OR NEW.refund_no IS DISTINCT FROM OLD.refund_no
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.order_no IS DISTINCT FROM OLD.order_no
     OR NEW.payment_ref IS DISTINCT FROM OLD.payment_ref
     OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
     OR NEW.currency IS DISTINCT FROM OLD.currency
     OR NEW.original_route IS DISTINCT FROM OLD.original_route
     OR NEW.original_route_hash IS DISTINCT FROM OLD.original_route_hash
     OR NEW.deadline_at IS DISTINCT FROM OLD.deadline_at
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'refund_requests 身份 / 原路字段不可变（不得改第三方地址，INV-12）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'refund_requests 非法状态迁移：% -> %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_refunds_guard ON refund_requests;
CREATE TRIGGER m08_refunds_guard BEFORE UPDATE OR DELETE ON refund_requests
  FOR EACH ROW EXECUTE FUNCTION m08_refunds_guard();

DROP TRIGGER IF EXISTS refund_requests_no_truncate ON refund_requests;
CREATE TRIGGER refund_requests_no_truncate BEFORE TRUNCATE ON refund_requests
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

CREATE OR REPLACE VIEW v_m08_refund_open AS
  SELECT refund_no, order_no, amount_minor, currency, status, deadline_at, cooldown_until
    FROM refund_requests
   WHERE status IN ('requested', 'approved', 'executing');

COMMENT ON VIEW v_m08_refund_open IS 'M08 只读视图：未结退款（客服 / 后台查看用，不含原路明细）';

COMMIT;
