-- 802 · M08 分润出款（payout_batches / payout_items）+ 收款地址白名单（payout_addresses）
-- 规格：M08 §3（payout_batch draft→prepared→checked→signed→broadcast→settled/partial/failed；
--       payout_item pending→sent/carried/failed；fee > gross → carried 滚存）
--       · §5 数据所有权（迁移 802）· §6 流程 3（制单 ≤50 笔 → 复核（M09 attestation）→ 意图 + 推送签名
--       ≤30 分钟 → HSM 联签广播 → 达确认 → payout.paid）
--       · INV-10（出款四要素：审批链 + 有效 attestation + 白名单生效 + 2/3 签名）
--       · INV-11（出款 ≤ 应付；只发 USDT；一期仅 Polygon）
--       · INV-13（白名单 72h 冷却 + 首笔 ≤100 USDT 试转 + 出款前 7 天禁改）
--       · INV-14（gas 模式按批次快照，下一批生效、不追溯）
--       · 产品 §19.8.1–19.8.6、§19.10.4（40914 / 40916 / 42210 / 42211）
--
-- 表归属说明（CR-P6，报 Lead）：`payout_addresses` 是 M08 §5 表清单**未列出**的新表，
-- 但从 §4.1「POST /api/v1/provider/payout-address（72h 冷却）」与 INV-13 看，白名单状态必须有
-- 持久化落点；本模块不写 accounts（M01），也不把白名单塞进 deposit_address（收款用途不同）。
-- 已按「新增对象先登记」的纪律登记为变更请求，由 Lead 决定是否并入 01-ownership 表清单。
BEGIN;

-- ────────────────────────────────────────────────────────────── 分润批次
CREATE SEQUENCE IF NOT EXISTS payout_batch_no_seq;

CREATE TABLE IF NOT EXISTS payout_batches (
  batch_id         UUID PRIMARY KEY,
  batch_no         TEXT NOT NULL UNIQUE
                   DEFAULT ('PB-' || to_char(now(), 'YYYYMMDD') || '-' ||
                            lpad(nextval('payout_batch_no_seq')::text, 6, '0')),
  status           TEXT NOT NULL DEFAULT 'draft',
  total_gross_minor BIGINT NOT NULL DEFAULT 0,
  total_fee_minor  BIGINT NOT NULL DEFAULT 0,
  total_net_minor  BIGINT NOT NULL DEFAULT 0,
  item_count       INTEGER NOT NULL DEFAULT 0,
  items_hash       TEXT,                                  -- 明细 Merkle 根（决策人签的摘要含净额）
  attestation_ref  TEXT,                                  -- M09 recon_attestation（复核凭证引用）
  attestation_valid BOOLEAN NOT NULL DEFAULT FALSE,        -- 校验结论快照（凭证本身在 M09）
  gas_mode         TEXT NOT NULL DEFAULT 'INTERNAL',       -- 批次快照；下一批生效，不追溯（INV-14）
  policy_version   TEXT NOT NULL,
  maker_id         TEXT NOT NULL,                          -- 制单人（Step 1）
  checker_id       TEXT,                                   -- 复核人（Step 2；≠ 制单人）
  checked_at       TIMESTAMPTZ,
  signed_at        TIMESTAMPTZ,
  broadcast_at     TIMESTAMPTZ,
  settled_at       TIMESTAMPTZ,
  chain_tx_id      TEXT,
  signing_request_id UUID,
  intent_id        UUID,
  failure_reason   TEXT,
  idempotency_key  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payout_batches_status_ck CHECK (status IN
    ('draft', 'prepared', 'checked', 'signed', 'broadcast', 'settled', 'partial', 'failed')),
  CONSTRAINT payout_batches_items_ck CHECK (item_count BETWEEN 0 AND 50),
  CONSTRAINT payout_batches_totals_ck CHECK
    (total_gross_minor >= 0 AND total_fee_minor >= 0 AND total_net_minor >= 0),
  CONSTRAINT payout_batches_net_ck CHECK (total_net_minor = total_gross_minor - total_fee_minor),
  CONSTRAINT payout_batches_gas_ck CHECK
    (gas_mode IN ('INTERNAL', 'EXTERNAL_PLATFORM', 'EXTERNAL_PAYER')),
  -- SoD：复核人 ≠ 制单人（INV-10 / §19.11.2 硬规则）
  CONSTRAINT payout_batches_sod_ck CHECK (checker_id IS NULL OR checker_id <> maker_id),
  -- 进入 checked 必须有 attestation 引用（INV-10：无 attestation 不放款）
  CONSTRAINT payout_batches_attestation_ck CHECK
    (status NOT IN ('checked', 'signed', 'broadcast', 'settled', 'partial')
     OR attestation_ref IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS payout_batches_idem_uq
  ON payout_batches (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS payout_batches_status_idx ON payout_batches (status, created_at DESC);
CREATE INDEX IF NOT EXISTS payout_batches_maker_idx ON payout_batches (maker_id, created_at DESC);

COMMENT ON TABLE payout_batches IS
  'M08 分润批次：审批后明细冻结（改单 = 新批次）；无 attestation 不得进入 checked（INV-10）';

CREATE OR REPLACE FUNCTION m08_payouts_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['draft->prepared', 'prepared->checked', 'checked->signed',
                            'signed->broadcast', 'broadcast->settled', 'broadcast->partial',
                            'broadcast->failed', 'signed->failed', 'checked->failed',
                            'prepared->failed', 'draft->failed'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'payout_batches 只追加：禁止 DELETE' USING ERRCODE = '42501';
  END IF;
  IF NEW.batch_id IS DISTINCT FROM OLD.batch_id
     OR NEW.batch_no IS DISTINCT FROM OLD.batch_no
     OR NEW.maker_id IS DISTINCT FROM OLD.maker_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'payout_batches 身份字段不可变（批次号 / 制单人）' USING ERRCODE = '42501';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'payout_batches 非法状态迁移：% -> %（§3 / §19.8.3）',
      OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;
  -- 审批后明细冻结：checked 之后总额 / 明细哈希 / 笔数不可变（改单 = 新批次）
  IF OLD.status NOT IN ('draft', 'prepared') AND (
       NEW.total_gross_minor IS DISTINCT FROM OLD.total_gross_minor
       OR NEW.total_fee_minor IS DISTINCT FROM OLD.total_fee_minor
       OR NEW.total_net_minor IS DISTINCT FROM OLD.total_net_minor
       OR NEW.items_hash IS DISTINCT FROM OLD.items_hash
       OR NEW.item_count IS DISTINCT FROM OLD.item_count) THEN
    RAISE EXCEPTION 'payout_batches 审批后明细冻结：改单须新批次（§19.8.3）'
      USING ERRCODE = '42501';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_payouts_guard ON payout_batches;
CREATE TRIGGER m08_payouts_guard BEFORE UPDATE OR DELETE ON payout_batches
  FOR EACH ROW EXECUTE FUNCTION m08_payouts_guard();

DROP TRIGGER IF EXISTS payout_batches_no_truncate ON payout_batches;
CREATE TRIGGER payout_batches_no_truncate BEFORE TRUNCATE ON payout_batches
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 批次明细
CREATE TABLE IF NOT EXISTS payout_items (
  item_id          UUID PRIMARY KEY,
  batch_id         UUID NOT NULL REFERENCES payout_batches (batch_id),
  payee_account_id TEXT NOT NULL,
  payee_address    TEXT NOT NULL,
  gross_minor      BIGINT NOT NULL,                       -- 应付（USD 分）
  fee_minor        BIGINT NOT NULL DEFAULT 0,             -- 网络费 / gas 分摊（分）
  net_minor        BIGINT NOT NULL,                       -- 实付 = gross - fee
  status           TEXT NOT NULL DEFAULT 'pending',
  gas_mode         TEXT NOT NULL DEFAULT 'INTERNAL',
  policy_version   TEXT NOT NULL,
  address_id       UUID,                                  -- payout_addresses 引用（不建 FK，见下）
  carry_of_item_id UUID,                                  -- 滚存来源（fee > gross → carried）
  carried_to_batch_id UUID,
  chain_tx_id      TEXT,
  journal_id       UUID,                                  -- E8 记账结果（M06）
  failure_reason   TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payout_items_status_ck CHECK (status IN ('pending', 'sent', 'carried', 'failed')),
  CONSTRAINT payout_items_amounts_ck CHECK (gross_minor >= 0 AND fee_minor >= 0 AND net_minor >= 0),
  -- 正常笔：net = gross - fee；滚存笔（fee >= gross）不出款，net 记 0
  CONSTRAINT payout_items_net_ck CHECK (
    (status = 'carried' AND net_minor = 0)
    OR (status <> 'carried' AND net_minor = gross_minor - fee_minor)),
  CONSTRAINT payout_items_gas_ck CHECK
    (gas_mode IN ('INTERNAL', 'EXTERNAL_PLATFORM', 'EXTERNAL_PAYER')),
  CONSTRAINT payout_items_address_ck CHECK (payee_address = lower(payee_address)),
  -- fee >= gross → 该笔不出款、滚存下批（不出现负数应付；滚入批次可为空，待下批回填）
  CONSTRAINT payout_items_carried_ck CHECK
    (status <> 'carried' OR (fee_minor >= gross_minor AND net_minor = 0)),
  CONSTRAINT payout_items_min_ck CHECK (gross_minor >= 0)
);

CREATE INDEX IF NOT EXISTS payout_items_batch_idx ON payout_items (batch_id, status);
CREATE INDEX IF NOT EXISTS payout_items_payee_idx
  ON payout_items (payee_account_id, created_at DESC);
-- 同一批次内同一收款地址只允许一笔（拆单规避的直接拦截）
CREATE UNIQUE INDEX IF NOT EXISTS payout_items_batch_payee_uq
  ON payout_items (batch_id, payee_account_id, payee_address);

COMMENT ON TABLE payout_items IS
  'M08 批次明细：净额公式 gross - fee = net；fee > gross → carried 滚存（§19.8.5）';

-- payout_items.address_id 不建 FK：白名单行可能被 revoke，历史明细必须永久可解析（同 005 的理由）

-- ────────────────────────────────────────────────────────────── 收款地址白名单（CR-P6）
CREATE TABLE IF NOT EXISTS payout_addresses (
  address_id        UUID PRIMARY KEY,
  account_id        TEXT NOT NULL,                        -- 共享方账户（M01）
  chain_id          TEXT NOT NULL DEFAULT 'polygon',
  address           TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'pending',      -- pending / whitelisted / rejected / revoked
  ownership_challenge_ref TEXT,                           -- 所有权挑战签名引用（不存签名原文）
  ownership_verified_at  TIMESTAMPTZ,
  risk_level        TEXT,                                 -- low / medium / high（由 M11 结果快照）
  cooldown_until    TIMESTAMPTZ NOT NULL,                 -- 生效时间 = 验证时刻 + 72h（INV-13）
  first_transfer_at TIMESTAMPTZ,                          -- 首笔试转（≤100 USDT）
  first_transfer_minor BIGINT,
  changed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),    -- 最近一次地址变更（出款前 7 天禁改）
  previous_address  TEXT,                                 -- 旧地址（保留 ≥90 天监听由保留任务负责）
  approved_by       TEXT,
  approved_at       TIMESTAMPTZ,
  rejected_reason   TEXT,
  label             TEXT,                                  -- 地址标签（人类可读，不含 PII）
  idempotency_key   TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payout_addresses_status_ck CHECK
    (status IN ('pending', 'whitelisted', 'rejected', 'revoked')),
  CONSTRAINT payout_addresses_chain_ck CHECK (chain_id IN ('polygon')),
  CONSTRAINT payout_addresses_addr_ck CHECK
    (address = lower(address) AND char_length(address) BETWEEN 20 AND 64),
  -- 首笔试转 ≤100 USDT（10,000 分）
  CONSTRAINT payout_addresses_first_transfer_ck CHECK
    (first_transfer_minor IS NULL OR first_transfer_minor <= 10000),
  CONSTRAINT payout_addresses_approved_ck CHECK
    (status <> 'whitelisted' OR (ownership_verified_at IS NOT NULL
                                 AND approved_at IS NOT NULL AND approved_by IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS payout_addresses_key_uq
  ON payout_addresses (account_id, chain_id, address);
CREATE INDEX IF NOT EXISTS payout_addresses_account_idx
  ON payout_addresses (account_id, status);
ALTER TABLE payout_addresses ADD COLUMN IF NOT EXISTS label TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS payout_addresses_idem_uq
  ON payout_addresses (idempotency_key) WHERE idempotency_key IS NOT NULL;

COMMENT ON TABLE payout_addresses IS
  'M08 出款地址白名单（CR-P6 待登记）：72h 冷却 + 首笔 ≤100 USDT + 出款前 7 天禁改（INV-13）';

CREATE OR REPLACE FUNCTION m08_payout_addresses_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'payout_addresses 只追加：禁止 DELETE（旧地址监听 ≥90 天）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.address_id IS DISTINCT FROM OLD.address_id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.address IS DISTINCT FROM OLD.address
     OR NEW.chain_id IS DISTINCT FROM OLD.chain_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'payout_addresses 身份字段不可变（地址 / 账户 / 链）' USING ERRCODE = '42501';
  END IF;
  IF OLD.status = 'revoked' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'payout_addresses 已 revoked，不可复活（须新增一条）' USING ERRCODE = '23514';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_payout_addresses_guard ON payout_addresses;
CREATE TRIGGER m08_payout_addresses_guard BEFORE UPDATE OR DELETE ON payout_addresses
  FOR EACH ROW EXECUTE FUNCTION m08_payout_addresses_guard();

DROP TRIGGER IF EXISTS payout_addresses_no_truncate ON payout_addresses;
CREATE TRIGGER payout_addresses_no_truncate BEFORE TRUNCATE ON payout_addresses
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

COMMIT;