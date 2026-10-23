-- 502 · M05 计量收据 · 双签原始凭证（metering_receipts）+ 只追加护栏
-- 规格：product/v4/modules/M05-metering-receipt.md §3 不变量（INV-01/INV-02/INV-03/INV-10）
--       §5 数据所有权（receipts，迁移 502，保留 5 年）· §6 流程 1 · §8.2 常量（签名算法/6 字段）
--       product/v4/modules/04-api-contracts.md §1（收据签名钉死 hmac-sha256 + 6 字段 + 原样字符串）
--
-- ⚠ 表名（需要 Lead 在合并时裁决，已在证据「风险/CR」登记）：
--   M05 §5 把本表叫 ``receipts``，但 **001_init.sql 的 ``receipts`` 已被 legacy adapter
--   ``app/api.py`` 占用**（列形状完全不同：id UUID / consumer_id / amount_micro / ts_start…，
--   还有 ``request_id UNIQUE`` 与 app/reconcile.py 的 FULL OUTER JOIN 对账口径）。
--   00-conventions §7.1「001–005 的存量表名冻结，不改名、不重建」优先，因此本模块新建
--   **独立自有表 metering_receipts**，对 legacy ``receipts`` / ``node_receipts`` 零改动
--   （不 ALTER、不 JOIN、不写）。与 M06 的 CR-L5（ledger_entry vs ledger_entries_compat）
--   同一处理方式：规范名加模块前缀，旧表留到 S1 末。
--
-- 不变量落点：
--   INV-01 双签缺一即拒收 → 只接受 state='accepted' 且两侧签名均符合 hmac-sha256:<64hex>；
--   INV-03 receipt_id 全局唯一（部分唯一索引，只对 accepted 生效）→ 重复提交返回首次结果；
--   INV-02 逐条受理 → rejected / expired 也留痕（state + rejected_code），不回滚整批；
--   INV-10 不带正文/凭据 → 表里只有元数据、原样字符串与 HMAC 摘要，没有 prompt/response/密钥。
BEGIN;

-- ────────────────────────────────────────────────────────── 双签原始凭证（只追加）
CREATE TABLE IF NOT EXISTS metering_receipts (
  submission_id  UUID PRIMARY KEY,               -- 每次提交一行（失败可重提 → 追加，不改历史）
  receipt_id     TEXT NOT NULL,                  -- 规范字段 1（INV-03：accepted 行全局唯一）
  usage_id       UUID,                           -- 仅 accepted 行有值（1:1 指向 usage_records）
  node_id        TEXT NOT NULL,                  -- 供方节点（M02，软引用）
  task_id        TEXT NOT NULL,                  -- 规范字段 2
  access         TEXT NOT NULL,                  -- 规范字段 3（A1/A2/B）
  usage_amount   TEXT NOT NULL,                  -- 规范字段 4（上报原样字符串）
  usage_unit     TEXT NOT NULL,                  -- 规范字段 5（上报原样字符串）
  price_amount   TEXT NOT NULL,                  -- 规范字段 6（上报原样字符串）
  price_minor    BIGINT NOT NULL,                -- price_amount 的整数分（超精度在入口拒绝）
  signature_alg  TEXT NOT NULL DEFAULT 'hmac-sha256',
  sig_provider   TEXT NOT NULL,                  -- 供方签名（accepted 行必须是 hmac-sha256:<64hex>）
  sig_consumer   TEXT NOT NULL,                  -- 需方签名（同上；两侧密钥必须不同）
  state          TEXT NOT NULL,                  -- accepted / rejected / expired
  rejected_code  INTEGER,                        -- 拒收数字码（40001 / 46001 …）
  reject_reason  TEXT,                           -- 机器可读原因（不含内部细节）
  reported_at    TIMESTAMPTZ NOT NULL,           -- 上报的发生时间（24h 窗口的判定输入）
  received_at    TIMESTAMPTZ NOT NULL,           -- 服务端受理时间
  trace_id       TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_access_ck;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_access_ck
  CHECK (access IN ('A1', 'A2', 'B')) NOT VALID;

ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_state_ck;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_state_ck
  CHECK (state IN ('accepted', 'rejected', 'expired')) NOT VALID;

-- 受理态与拒绝码成对：accepted 不能带拒绝码；非 accepted 必须有码且没有 usage
ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_state_ck2;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_state_ck2
  CHECK ((state = 'accepted' AND usage_id IS NOT NULL
                            AND rejected_code IS NULL AND reject_reason IS NULL)
      OR (state <> 'accepted' AND usage_id IS NULL AND rejected_code IS NOT NULL))
  NOT VALID;

-- 签名算法钉死（CR-2）：accepted 行的两侧签名必须形如 hmac-sha256:<64hex>；
-- 被拒行保留原样（可能是 "bad" 之类），便于节点自查与失败率统计。
ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_sig_ck;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_sig_ck
  CHECK (state <> 'accepted'
      OR (sig_provider  ~ '^hmac-sha256:[0-9a-f]{64}$'
      AND sig_consumer  ~ '^hmac-sha256:[0-9a-f]{64}$'
      AND signature_alg = 'hmac-sha256')) NOT VALID;

ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_price_ck;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_price_ck
  CHECK (price_minor >= 0) NOT VALID;

ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_text_ck;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_text_ck
  CHECK (char_length(receipt_id) BETWEEN 1 AND 128
     AND char_length(node_id) BETWEEN 1 AND 128
     AND char_length(task_id) BETWEEN 1 AND 128
     AND char_length(usage_unit) BETWEEN 1 AND 32
     AND char_length(usage_amount) BETWEEN 1 AND 38
     AND char_length(price_amount) BETWEEN 1 AND 38
     AND (trace_id IS NULL OR char_length(trace_id) BETWEEN 1 AND 128)
     AND (reject_reason IS NULL OR char_length(reject_reason) BETWEEN 1 AND 128)) NOT VALID;

-- INV-03：receipt_id 只在被受理时全局唯一（被拒可改正后重提，仍留痕）
DROP INDEX IF EXISTS metering_receipts_accepted_uq;
CREATE UNIQUE INDEX metering_receipts_accepted_uq
  ON metering_receipts (receipt_id) WHERE state = 'accepted';

-- 一张用量最多一条被受理的凭证
DROP INDEX IF EXISTS metering_receipts_usage_uq;
CREATE UNIQUE INDEX metering_receipts_usage_uq
  ON metering_receipts (usage_id) WHERE usage_id IS NOT NULL;

DROP INDEX IF EXISTS metering_receipts_node_time_idx;
CREATE INDEX metering_receipts_node_time_idx ON metering_receipts (node_id, received_at DESC);

DROP INDEX IF EXISTS metering_receipts_receipt_idx;
CREATE INDEX metering_receipts_receipt_idx ON metering_receipts (receipt_id, received_at DESC);

-- 只追加：凭证是原始证据，任何 UPDATE / DELETE / TRUNCATE 都不允许（P0 审计口径）
DROP TRIGGER IF EXISTS metering_receipts_no_mutation ON metering_receipts;
CREATE TRIGGER metering_receipts_no_mutation BEFORE UPDATE OR DELETE ON metering_receipts
  FOR EACH ROW EXECUTE FUNCTION m05_forbid_mutation();

DROP TRIGGER IF EXISTS metering_receipts_no_truncate ON metering_receipts;
CREATE TRIGGER metering_receipts_no_truncate BEFORE TRUNCATE ON metering_receipts
  FOR EACH STATEMENT EXECUTE FUNCTION m05_forbid_truncate();

-- 时间不倒挂（00-conventions §4.4：时间比较只用服务端时间）：域层对「未来上报时间」按
-- 服务端 now 截断后再落库，因此这里要求 reported_at <= received_at 严格成立，不留容差常量。
ALTER TABLE metering_receipts DROP CONSTRAINT IF EXISTS metering_receipts_time_ck;
ALTER TABLE metering_receipts ADD CONSTRAINT metering_receipts_time_ck
  CHECK (reported_at <= received_at) NOT VALID;

COMMENT ON TABLE metering_receipts IS
  'M05 双签原始凭证（M05 §5 / 迁移 502）：只追加；accepted 行 receipt_id 全局唯一（INV-03）';
COMMENT ON COLUMN metering_receipts.usage_amount IS
  '规范字段 4 的上报原样字符串（参与签名），不是 NUMERIC 回读值（M05 §8.2 / CR-2）';
COMMENT ON COLUMN metering_receipts.price_amount IS
  '规范字段 6 的上报原样字符串（参与签名）；price_minor 是解析后的整数分';

DO $$
DECLARE
  missing TEXT;
BEGIN
  SELECT string_agg(col, ',') INTO missing
    FROM unnest(ARRAY['submission_id','receipt_id','usage_id','node_id','task_id','access',
                      'usage_amount','usage_unit','price_amount','price_minor','signature_alg',
                      'sig_provider','sig_consumer','state','rejected_code','reject_reason',
                      'reported_at','received_at','trace_id','created_at']) AS col
   WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns
                      WHERE table_schema = current_schema()
                        AND table_name = 'metering_receipts' AND column_name = col);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION '502: metering_receipts 缺列：%', missing;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'metering_receipts_accepted_uq') THEN
    RAISE EXCEPTION '502: 缺部分唯一索引 metering_receipts_accepted_uq（INV-03）';
  END IF;
END
$$;

COMMIT;
