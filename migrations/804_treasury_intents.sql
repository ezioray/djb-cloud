-- 804 · M08 资金意图与签名（treasury_intents / signing_intents / signing_events）
-- 规格：M08 §3（treasury_intent proposed → signing → executed / expired；kind ∈ 8 值（含
--       WALLET_PROVISION）；signing_request pending → signed / expired；签名六事件
--       requested→presented→signed→verified→co_signed→broadcast）
--       · §5 数据所有权（迁移 804）· §8.2（SIGNING_TTL_S=1800；WALLET_PROVISION 放宽 86400）
--       · 产品 §19.5.2（EIP-712 TreasuryIntent 结构）/ §19.5.6（批次签）/ §19.11.4（六事件字段）
--       · INV-10（2/3 签名）；「只 propose，不持钥」：本表只存引用与哈希。
--
-- 原则：
--   1) **不存任何私钥 / 助记词 / 完整签名**：只有 signature_hash / auth_hash / 引用；
--   2) nonce 单调（全局序列）→ 链上 / 服务端双重防重放；
--   3) expiresAt：普通动作 ≤30 分钟，WALLET_PROVISION ≤24h（库层 CHECK 兜底）；
--   4) 六事件只追加、事件齐备才能进入下一阶段（应用层判定，库层只保唯一与顺序）；
--   5) 只加不改 / 可重复执行。
BEGIN;

CREATE SEQUENCE IF NOT EXISTS treasury_intent_nonce_seq;

CREATE TABLE IF NOT EXISTS treasury_intents (
  intent_id        UUID PRIMARY KEY,
  kind             TEXT NOT NULL,
  chain_id         TEXT NOT NULL DEFAULT 'polygon',
  asset            TEXT NOT NULL DEFAULT 'USDT',
  total_amount_minor BIGINT NOT NULL DEFAULT 0,           -- 金额（USD 分）
  item_count       INTEGER NOT NULL DEFAULT 0,
  recipients_hash  TEXT,                                  -- 收款人 Merkle 根
  nonce            BIGINT NOT NULL DEFAULT nextval('treasury_intent_nonce_seq'),
  status           TEXT NOT NULL DEFAULT 'proposed',
  auth_object_type TEXT,                                  -- intentHash / multisigTxHash（二选一）
  auth_hash        TEXT,
  policy_version   TEXT NOT NULL,
  memo_hash        TEXT,
  created_by       TEXT NOT NULL,
  correlation_id   TEXT,                                  -- 关联单号（batch_no / refund_no）
  idempotency_key  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT treasury_intents_kind_ck CHECK (kind IN
    ('PAYOUT', 'REFUND', 'SWEEP', 'REBALANCE', 'GAS_TOPUP', 'POLICY_CHANGE', 'RECOVERY',
     'WALLET_PROVISION')),
  CONSTRAINT treasury_intents_status_ck CHECK
    (status IN ('proposed', 'signing', 'executed', 'expired')),
  CONSTRAINT treasury_intents_auth_ck CHECK
    (auth_object_type IS NULL OR auth_object_type IN ('intentHash', 'multisigTxHash')),
  CONSTRAINT treasury_intents_amount_ck CHECK
    (total_amount_minor >= 0 AND item_count >= 0),
  CONSTRAINT treasury_intents_ttl_ck CHECK (expires_at > created_at),
  -- §19.5.2：普通动作 ≤30 分钟；WALLET_PROVISION 不动钱、只开容量，放宽到 ≤24h
  CONSTRAINT treasury_intents_window_ck CHECK (
    (kind = 'WALLET_PROVISION' AND expires_at <= created_at + INTERVAL '24 hours')
    OR (kind <> 'WALLET_PROVISION' AND expires_at <= created_at + INTERVAL '30 minutes')),
  CONSTRAINT treasury_intents_hash_ck CHECK
    (recipients_hash IS NULL OR recipients_hash ~ '^[0-9a-f]{16,128}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS treasury_intents_nonce_uq ON treasury_intents (nonce);
CREATE UNIQUE INDEX IF NOT EXISTS treasury_intents_idem_uq
  ON treasury_intents (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS treasury_intents_corr_idx
  ON treasury_intents (correlation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS treasury_intents_status_idx
  ON treasury_intents (status, expires_at);

COMMENT ON TABLE treasury_intents IS
  'M08 资金意图（EIP-712 摘要字段）：nonce 单调 / 普通 ≤30min / WALLET_PROVISION ≤24h；不持钥';

CREATE OR REPLACE FUNCTION m08_intents_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'treasury_intents 只追加：禁止 DELETE' USING ERRCODE = '42501';
  END IF;
  IF NEW.intent_id IS DISTINCT FROM OLD.intent_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.chain_id IS DISTINCT FROM OLD.chain_id
     OR NEW.asset IS DISTINCT FROM OLD.asset
     OR NEW.total_amount_minor IS DISTINCT FROM OLD.total_amount_minor
     OR NEW.item_count IS DISTINCT FROM OLD.item_count
     OR NEW.recipients_hash IS DISTINCT FROM OLD.recipients_hash
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'treasury_intents 身份字段不可变（签名绑定：改任一字段 = 新 intent）'
      USING ERRCODE = '42501';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_intents_guard ON treasury_intents;
CREATE TRIGGER m08_intents_guard BEFORE UPDATE OR DELETE ON treasury_intents
  FOR EACH ROW EXECUTE FUNCTION m08_intents_guard();

DROP TRIGGER IF EXISTS treasury_intents_no_truncate ON treasury_intents;
CREATE TRIGGER treasury_intents_no_truncate BEFORE TRUNCATE ON treasury_intents
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 签名请求
CREATE TABLE IF NOT EXISTS signing_intents (
  signing_request_id UUID PRIMARY KEY,
  intent_id        UUID NOT NULL REFERENCES treasury_intents (intent_id),
  kind             TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending',        -- pending / signed / expired / failed
  signer_set_ref   TEXT,                                   -- 签名人集合引用（决策人/复核人/HSM）
  threshold_n      INTEGER NOT NULL DEFAULT 2,             -- 2-of-3（INV-10 / §8.2）
  signer_count_n   INTEGER NOT NULL DEFAULT 3,
  signed_count     INTEGER NOT NULL DEFAULT 0,
  policy_version   TEXT NOT NULL,
  requested_at     TIMESTAMPTZ NOT NULL,
  presented_at     TIMESTAMPTZ,
  signed_at        TIMESTAMPTZ,
  verified_at      TIMESTAMPTZ,
  co_signed_at     TIMESTAMPTZ,
  broadcast_at     TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ NOT NULL,
  auth_hash        TEXT,
  txid             TEXT,
  created_by       TEXT NOT NULL,
  idempotency_key  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT signing_intents_status_ck CHECK
    (status IN ('pending', 'signed', 'expired', 'failed')),
  CONSTRAINT signing_intents_threshold_ck CHECK
    (threshold_n >= 1 AND signer_count_n >= threshold_n AND signed_count BETWEEN 0 AND signer_count_n),
  CONSTRAINT signing_intents_ttl_ck CHECK (expires_at > requested_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS signing_intents_idem_uq
  ON signing_intents (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS signing_intents_status_idx
  ON signing_intents (status, expires_at);
CREATE INDEX IF NOT EXISTS signing_intents_intent_idx
  ON signing_intents (intent_id);

COMMENT ON TABLE signing_intents IS
  'M08 签名请求：2-of-3 门限；≤30min（WALLET_PROVISION ≤24h）；不存完整签名 / 私钥';

DROP TRIGGER IF EXISTS signing_intents_no_truncate ON signing_intents;
CREATE TRIGGER signing_intents_no_truncate BEFORE TRUNCATE ON signing_intents
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 签名六事件（只追加）
CREATE TABLE IF NOT EXISTS signing_events (
  seq               BIGSERIAL PRIMARY KEY,
  signing_event_id  UUID NOT NULL UNIQUE,
  signing_request_id UUID NOT NULL REFERENCES signing_intents (signing_request_id),
  event             TEXT NOT NULL,
  signer_type       TEXT NOT NULL,                        -- owner / reviewer / company
  signer_ref        TEXT,                                 -- 签名人引用（内部 id，不存设备私钥）
  signature_hash    TEXT,                                 -- 只存 hash（不存签名原文）
  device_id         TEXT,
  auth_hash         TEXT,
  txid              TEXT,
  error_code        TEXT,
  occurred_at       TIMESTAMPTZ NOT NULL,
  recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT signing_events_event_ck CHECK (event IN
    ('requested', 'presented', 'signed', 'verified', 'co_signed', 'broadcast')),
  CONSTRAINT signing_events_signer_ck CHECK (signer_type IN ('owner', 'reviewer', 'company')),
  CONSTRAINT signing_events_hash_ck CHECK
    (signature_hash IS NULL OR signature_hash ~ '^[0-9a-f]{16,128}$')
);

-- 六事件幂等：同一请求同一事件同一签名人只允许一次（重放不重复推进）
CREATE UNIQUE INDEX IF NOT EXISTS signing_events_stage_uq
  ON signing_events (signing_request_id, event, signer_type);
CREATE INDEX IF NOT EXISTS signing_events_request_idx
  ON signing_events (signing_request_id, seq);

COMMENT ON TABLE signing_events IS
  'M08 签名六事件（只追加）：requested→presented→signed→verified→co_signed→broadcast';

CREATE OR REPLACE FUNCTION m08_signing_events_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'signing_events 只追加：禁止 %（六事件必须按序留痕）', TG_OP
    USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS signing_events_guard ON signing_events;
CREATE TRIGGER signing_events_guard BEFORE UPDATE OR DELETE ON signing_events
  FOR EACH ROW EXECUTE FUNCTION m08_signing_events_guard();

DROP TRIGGER IF EXISTS signing_events_no_truncate ON signing_events;
CREATE TRIGGER signing_events_no_truncate BEFORE TRUNCATE ON signing_events
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

CREATE OR REPLACE VIEW v_m08_signing_progress AS
  SELECT s.signing_request_id, s.intent_id, s.kind, s.status, s.threshold_n, s.signed_count,
         count(*) FILTER (WHERE e.event = 'signed')      AS owner_signed,
         count(*) FILTER (WHERE e.event = 'verified')    AS hsm_verified,
         count(*) FILTER (WHERE e.event = 'co_signed')   AS co_signed,
         count(*) FILTER (WHERE e.event = 'broadcast')   AS broadcast,
         max(e.occurred_at)                              AS last_event_at
    FROM signing_intents s
    LEFT JOIN signing_events e ON e.signing_request_id = s.signing_request_id
   GROUP BY s.signing_request_id;

COMMENT ON VIEW v_m08_signing_progress IS 'M08 只读视图：签名六事件进度（不含签名正文）';

COMMIT;
