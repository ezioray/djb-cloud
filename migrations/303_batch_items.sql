-- 303 · M03 网关 · 慢任务明细（batch_items）
-- 规格：product/v4/modules/M03-gateway-protocol.md §3.1（batch 生命周期）/ §5（batch_items 归 M03）
--       §10.3 CR-1（已裁决 batch_items 归 M03）· spec `BatchCreateRequest.items[]`
--       02-events（本表不发事件；进度汇总走 batch_jobs）
--
-- 原则：
--   1) 一条 item = 一个 `custom_id` + 可选 `input`（正文**不落库**：只记元数据与结果引用；
--      慢任务结果本身走 `results_ref` 签名 URL，INV-M03-09）。
--   2) 幂等：同一批次内 `custom_id` 唯一；(batch_id, seq) 唯一（重投顺序稳定）。
--   3) 逐条终态：queued → running → succeeded | failed | canceled；终态只允许写结果列。
--   4) 金额整数最小单位（USD 分）；用量权威在 M05（本表只存引用 usage_id）。
--   5) 可重复执行 + 末尾结构断言。
BEGIN;

CREATE TABLE IF NOT EXISTS batch_items (
  item_id       UUID PRIMARY KEY,                      -- UUIDv7
  batch_id      UUID NOT NULL REFERENCES batch_jobs(batch_id) ON DELETE CASCADE,
  seq           INTEGER NOT NULL,                      -- 批次内序号（1 起）
  custom_id     TEXT NOT NULL,                         -- 调用方自定义 id（≤128）
  status        TEXT NOT NULL DEFAULT 'queued',
  request_id    TEXT,                                  -- 该条对应的 M03 请求号（排障）
  usage_id      TEXT,                                  -- M05 usage_records.usage_id（软引用）
  tokens_in     INTEGER,
  tokens_out    INTEGER,
  amount_minor  BIGINT,                                -- 该条实际成本（USD 分；以收据为准）
  error_code    INTEGER,
  result_ref    TEXT,                                  -- 结果分片引用（签名 URL 由 batch_jobs 下发）
  attempts      INTEGER NOT NULL DEFAULT 0,             -- 重试次数（检查点恢复用）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ
);

ALTER TABLE batch_items DROP CONSTRAINT IF EXISTS batch_items_status_ck;
ALTER TABLE batch_items ADD CONSTRAINT batch_items_status_ck
  CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')) NOT VALID;

ALTER TABLE batch_items DROP CONSTRAINT IF EXISTS batch_items_meta_ck;
ALTER TABLE batch_items ADD CONSTRAINT batch_items_meta_ck
  CHECK (seq >= 1
     AND char_length(custom_id) BETWEEN 1 AND 128
     AND (request_id IS NULL OR char_length(request_id) BETWEEN 1 AND 128)
     AND (usage_id IS NULL OR char_length(usage_id) BETWEEN 1 AND 64)
     AND (result_ref IS NULL OR char_length(result_ref) <= 2048)
     AND (tokens_in IS NULL OR tokens_in >= 0)
     AND (tokens_out IS NULL OR tokens_out >= 0)
     AND (amount_minor IS NULL OR amount_minor >= 0)
     AND (error_code IS NULL OR error_code BETWEEN 1000 AND 99999)
     AND attempts >= 0) NOT VALID;

CREATE UNIQUE INDEX IF NOT EXISTS batch_items_batch_seq_uq ON batch_items (batch_id, seq);
CREATE UNIQUE INDEX IF NOT EXISTS batch_items_batch_custom_uq
  ON batch_items (batch_id, custom_id);
CREATE INDEX IF NOT EXISTS batch_items_batch_status_idx ON batch_items (batch_id, status);
CREATE INDEX IF NOT EXISTS batch_items_usage_idx
  ON batch_items (usage_id) WHERE usage_id IS NOT NULL;

-- ────────────────────────────────────────────────────────── 逐条状态机
CREATE OR REPLACE FUNCTION m03_batch_item_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;                                        -- 随批次级联删除（保留期由 batch_jobs 管）
  END IF;
  IF OLD.status IN ('succeeded', 'failed', 'canceled') THEN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'batch_items: terminal status % cannot move to % (INV-M03-06)',
        OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
  ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT ((OLD.status = 'queued' AND NEW.status IN ('running', 'succeeded', 'failed', 'canceled'))
         OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed', 'canceled'))) THEN
      RAISE EXCEPTION 'batch_items: illegal transition % -> % (M03 §3.1)',
        OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
  END IF;
  IF NEW.status IN ('succeeded', 'failed', 'canceled') AND NEW.completed_at IS NULL THEN
    NEW.completed_at := now();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS batch_items_guard ON batch_items;
CREATE TRIGGER batch_items_guard BEFORE UPDATE OR DELETE ON batch_items
  FOR EACH ROW EXECUTE FUNCTION m03_batch_item_guard();

DROP TRIGGER IF EXISTS batch_items_no_truncate ON batch_items;
CREATE TRIGGER batch_items_no_truncate BEFORE TRUNCATE ON batch_items
  FOR EACH STATEMENT EXECUTE FUNCTION m03_forbid_truncate();

COMMENT ON TABLE batch_items IS
  'M03 慢任务明细（迁移 303）：逐条终态不可逆；正文不落库，结果走 results_ref 签名 URL';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'batch_items_batch_custom_uq') THEN
    RAISE EXCEPTION '303: 缺幂等索引 batch_items_batch_custom_uq';
  END IF;
END
$$;

COMMIT;
