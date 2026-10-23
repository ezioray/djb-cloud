-- 501 · M05 计量收据 · 可计费用量（usage_records）+ 状态机 / 只追加护栏
-- 规格：product/v4/modules/M05-metering-receipt.md §3 不变量（INV-04/INV-05/INV-06/INV-11）
--       §5 数据所有权（usage_records，迁移 501，保留 5 年）· §6 流程 1/2 · §8.2 常量
--       product/v4/modules/03-facts.md §6（记账单位：整数最小单位 USD 分；不 UPDATE/DELETE）
--       00-conventions §3（金额整数最小单位、超精度拒绝）· §7.5（账本/事件/审计只追加）
--
-- 原则：
--   1) 只加不改：只建 M05 自己的表，001–006 与 1xx/2xx/4xx/6xx/10xx 的对象与数据零改动。
--   2) 唯一计费（INV-04 / INV-11）：UNIQUE(request_id, attempt_no)——一次请求的一个尝试最多
--      一条可计费用量；UNIQUE(usage_id) 主键；receipt_id 唯一（部分索引，见 502）。
--   3) 只追加 + 状态机（INV-06）：金额 / 用量 / 归属列一律不可改；只有
--      recorded → settled / recorded → corrected 两条合法迁移，且 UPDATE/DELETE 一律拒绝。
--   4) 金额口径（INV-05）：amount_minor 是**整数最小单位（USD 分）**，只存整数；
--      上报原样字符串留在 usage_amount，用于复算与签名核对，避免 NUMERIC 回读漂移。
--   5) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE / CREATE OR REPLACE；
--      末尾结构断言保证「已存在的表」与本节定义同形，避免半途建表被静默放过。
BEGIN;

-- ────────────────────────────────────────────── 只追加护栏（本段所有表共用）
-- 严格版：任何 UPDATE / DELETE 直接报错（SQLSTATE 42501）。错误信息保留 "append-only"
-- 字样，便于运维与日志检索（与 600 · M06 同款语义）。
CREATE OR REPLACE FUNCTION m05_forbid_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % not allowed (M05 §3 INV-06)', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

-- TRUNCATE 绕过行级触发器：只追加表必须用语句级触发器单独拦。
CREATE OR REPLACE FUNCTION m05_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M05 §3 INV-06)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

-- ────────────────────────────────────────────────────────── 可计费用量（唯一计费事实）
CREATE TABLE IF NOT EXISTS usage_records (
  usage_id       UUID PRIMARY KEY,                 -- UUIDv7（00-conventions §2）
  request_id     TEXT NOT NULL,                    -- M03 网关请求号（跨模块软引用，不建 FK）
  attempt_no     INTEGER NOT NULL DEFAULT 1,       -- 第几次尝试（INV-04：最终成功的那次计费）
  account_id     UUID NOT NULL,                    -- 需方账户（M01 user_accounts，软引用）
  node_id        TEXT NOT NULL,                    -- 供方节点（M02 nodes，软引用；只经只读视图校验）
  model          TEXT NOT NULL,
  access         TEXT NOT NULL,                    -- A1 / A2 / B（M05 §5 枚举）
  tokens_in      BIGINT NOT NULL DEFAULT 0,
  tokens_out     BIGINT NOT NULL DEFAULT 0,
  usage_amount   TEXT NOT NULL,                    -- 上报原样字符串（计量值，参与签名）
  usage_unit     TEXT NOT NULL,                    -- 计量单位（token / request …）
  amount_minor   BIGINT NOT NULL,                  -- 整数最小单位（USD 分，INV-05）
  usage_source   TEXT NOT NULL,                    -- client_reported / server_measured / dual / estimated
  state          TEXT NOT NULL DEFAULT 'recorded', -- recorded → settled / corrected
  receipt_id     TEXT,                             -- 双签收据号（1:1；部分唯一，见 502）
  correction_id  TEXT,                             -- state=corrected 时指向追加的校正
  recorded_at    TIMESTAMPTZ NOT NULL,             -- 业务发生时间（UTC；汇总/明细按它分桶）
  settled_at     TIMESTAMPTZ,
  corrected_at   TIMESTAMPTZ,
  trace_id       TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 枚举（M05 §5）
ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_access_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_access_ck
  CHECK (access IN ('A1', 'A2', 'B')) NOT VALID;

ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_source_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_source_ck
  CHECK (usage_source IN ('client_reported', 'server_measured', 'dual', 'estimated')) NOT VALID;

ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_state_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_state_ck
  CHECK (state IN ('recorded', 'settled', 'corrected')) NOT VALID;

-- 金额与用量（INV-05：整数最小单位、非负、超精度在入口拒绝）
ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_amount_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_amount_ck
  CHECK (amount_minor >= 0) NOT VALID;

ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_tokens_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_tokens_ck
  CHECK (tokens_in >= 0 AND tokens_out >= 0) NOT VALID;

ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_attempt_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_attempt_ck
  CHECK (attempt_no >= 1) NOT VALID;

-- 长度守卫：与 app/metering/facts.py 的 MAX_* 逐条对齐（先卡 DB，再卡域层）
ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_text_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_text_ck
  CHECK (char_length(request_id) BETWEEN 1 AND 128
     AND char_length(node_id) BETWEEN 1 AND 128
     AND char_length(model) BETWEEN 1 AND 128
     AND char_length(usage_unit) BETWEEN 1 AND 32
     AND char_length(usage_amount) BETWEEN 1 AND 38
     AND (receipt_id IS NULL OR char_length(receipt_id) BETWEEN 1 AND 128)
     AND (correction_id IS NULL OR char_length(correction_id) BETWEEN 1 AND 128)
     AND (trace_id IS NULL OR char_length(trace_id) BETWEEN 1 AND 128)) NOT VALID;

-- 状态列与时间戳成对（避免「settled 了却没有 settled_at」这类半成品）
ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_state_time_ck;
ALTER TABLE usage_records ADD CONSTRAINT usage_records_state_time_ck
  CHECK ((state = 'recorded'  AND settled_at IS NULL AND corrected_at IS NULL
                            AND correction_id IS NULL)
      OR (state = 'settled'   AND settled_at IS NOT NULL AND corrected_at IS NULL)
      OR (state = 'corrected' AND corrected_at IS NOT NULL AND correction_id IS NOT NULL))
  NOT VALID;

-- 唯一计费（INV-04 / INV-11）
DROP INDEX IF EXISTS usage_records_request_attempt_uq;
CREATE UNIQUE INDEX usage_records_request_attempt_uq
  ON usage_records (request_id, attempt_no);

-- 一张收据最多一条用量（INV-03：重复收据不重复计量）
DROP INDEX IF EXISTS usage_records_receipt_uq;
CREATE UNIQUE INDEX usage_records_receipt_uq
  ON usage_records (receipt_id) WHERE receipt_id IS NOT NULL;

-- 汇总 / 明细的取数路径（M05 §5 索引：usage_records(account_id, created_at)）
DROP INDEX IF EXISTS usage_records_account_time_idx;
CREATE INDEX usage_records_account_time_idx ON usage_records (account_id, created_at DESC);

-- ────────────────────────────────────────────────────────── 状态机 + 只追加触发器
-- 允许的唯一 UPDATE 形状：state / settled_at / corrected_at / correction_id 四列，
-- 且必须是 recorded → settled 或 recorded → corrected（M05 §3 状态机）。
-- 金额、用量、归属、模型、收据号等业务列一旦写入即不可改（INV-06「不得改原值」）。
CREATE OR REPLACE FUNCTION m05_usage_state_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['state', 'settled_at', 'corrected_at', 'correction_id'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'usage_records is append-only: DELETE not allowed (M05 INV-06)'
      USING ERRCODE = '42501';
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'usage_records: only state machine columns may change (M05 INV-06)'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.state = NEW.state THEN
    IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
      RAISE EXCEPTION 'usage_records: no-op state update with changed columns is not allowed'
        USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT ((OLD.state = 'recorded' AND NEW.state IN ('settled', 'corrected'))) THEN
    RAISE EXCEPTION 'usage_records: illegal transition % -> % (M05 §3)',
      OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS usage_records_state_guard ON usage_records;
CREATE TRIGGER usage_records_state_guard BEFORE UPDATE OR DELETE ON usage_records
  FOR EACH ROW EXECUTE FUNCTION m05_usage_state_guard();

DROP TRIGGER IF EXISTS usage_records_no_truncate ON usage_records;
CREATE TRIGGER usage_records_no_truncate BEFORE TRUNCATE ON usage_records
  FOR EACH STATEMENT EXECUTE FUNCTION m05_forbid_truncate();

-- 新行只能是 recorded：settled / corrected 必须经状态机迁移（不能一次写入终态绕过护栏）
CREATE OR REPLACE FUNCTION m05_usage_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.state <> 'recorded' THEN
    RAISE EXCEPTION 'usage_records: rows must start at state=recorded (M05 §3)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS usage_records_insert_guard ON usage_records;
CREATE TRIGGER usage_records_insert_guard BEFORE INSERT ON usage_records
  FOR EACH ROW EXECUTE FUNCTION m05_usage_insert_guard();

COMMENT ON TABLE usage_records IS
  'M05 唯一计费事实（M05 §5 / 迁移 501）：UNIQUE(request_id, attempt_no)；金额整数最小单位（USD 分）';
COMMENT ON COLUMN usage_records.usage_amount IS
  '上报原样字符串：参与收据签名（M05 §8.2），不复用 NUMERIC 回读值';
COMMENT ON COLUMN usage_records.amount_minor IS
  '整数最小单位（USD 分，INV-05）；0 是合法值（零价让路），负值在入口拒绝';

-- ────────────────────────────────────────────────────────── 结构断言（可重复执行也要同形）
DO $$
DECLARE
  missing TEXT;
BEGIN
  SELECT string_agg(col, ',') INTO missing
    FROM unnest(ARRAY['usage_id','request_id','attempt_no','account_id','node_id','model','access',
                      'tokens_in','tokens_out','usage_amount','usage_unit','amount_minor',
                      'usage_source','state','receipt_id','correction_id','recorded_at',
                      'settled_at','corrected_at','trace_id','created_at']) AS col
   WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns
                      WHERE table_schema = current_schema()
                        AND table_name = 'usage_records' AND column_name = col);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION '501: usage_records 缺列：%', missing;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes
                  WHERE schemaname = current_schema()
                    AND indexname = 'usage_records_request_attempt_uq') THEN
    RAISE EXCEPTION '501: 缺唯一索引 usage_records_request_attempt_uq（INV-04/INV-11）';
  END IF;
END
$$;

COMMIT;
