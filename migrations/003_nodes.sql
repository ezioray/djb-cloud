-- 003 · 节点接入：注册、策略、收据上报、对账
BEGIN;

CREATE TABLE IF NOT EXISTS nodes (
  id                   TEXT PRIMARY KEY,          -- node_id
  platform             TEXT NOT NULL,             -- macos/windows/linux
  hardware_fingerprint TEXT NOT NULL,             -- 客户端本地算好的**哈希**，平台不回传原值
  client_version       TEXT NOT NULL,
  protocol_version     TEXT NOT NULL,
  state                TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('pending','active','frozen','retired')),
  key_prefix           TEXT NOT NULL,             -- 便于排障，不可用于鉴权
  key_hash             TEXT NOT NULL UNIQUE,      -- sha256(客户端密钥)
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at         TIMESTAMPTZ
);

-- 节点上报的收据（供方视角）。平台自己那份在 receipts 表；两边对账后才算闭环。
CREATE TABLE IF NOT EXISTS node_receipts (
  receipt_id   TEXT PRIMARY KEY,
  node_id      TEXT NOT NULL REFERENCES nodes(id),
  task_id      TEXT NOT NULL,
  access       TEXT NOT NULL,
  usage_amount NUMERIC(38,9) NOT NULL,
  usage_unit   TEXT NOT NULL,
  price_amount NUMERIC(38,9) NOT NULL,
  sig_provider TEXT NOT NULL,
  sig_consumer TEXT NOT NULL,
  raw          JSONB NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS node_receipts_task_idx ON node_receipts(task_id);

-- 平台侧收据补 task_id，用于与节点上报对齐
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS task_id TEXT;
CREATE INDEX IF NOT EXISTS receipts_task_idx ON receipts(task_id);

COMMIT;
