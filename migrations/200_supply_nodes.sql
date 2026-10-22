-- 200 · M02 node-supply · 节点主档增量列（nodes）
-- 规格：M02 §3 领域模型 / §5 数据所有权（nodes 关键字段）/ §6.1 注册与准入 / §8 配置
--       01-ownership §2（M02 拥有 nodes 等 5 张表）· 00-conventions §7.2（只允许加列 / 加表 / 加索引）
--
-- 重要：``nodes`` 的基线由 **存量 003_nodes.sql** 建立（M02 §5「迁移：只加不改；003_nodes.sql
-- 保留为历史」）。本迁移**不重建、不改名、不改类型**，只在既有表上追加列 / 约束 / 索引：
--
--   1) 生命周期状态沿用存量列 ``state``（003 的 CHECK 已恰好是 pending/active/frozen/retired，
--      与 M02 §5 枚举一致）——所以 ``state`` 仍是**唯一写者列**；本轮只加一个
--      ``lifecycle_state`` **生成列**（GENERATED ALWAYS AS (state) STORED）作为只读别名，
--      让按 §5 字段名写的查询 / 后台视图 / M14 读取都能直接用，且不会产生双写漂移。
--   2) ``lifecycle_state`` 是生成列：任何 UPDATE 写它都会被 PG 拒绝（单一事实来源由库层保证）。
--   3) 在线 / 离线是**派生视图**（M02 §3「一层权威 + 一层派生，不得混用」）：本迁移不建
--      online/stale/offline 状态列，派生逻辑在 app/supply/state.py:derive_online()。
BEGIN;

-- ---------------------------------------------------------------- 归属与档案
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS account_id     UUID;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS tenant_id      UUID;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS access_modes   TEXT[] NOT NULL DEFAULT '{}'::text[];
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capabilities   TEXT[] NOT NULL DEFAULT '{}'::text[];
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT '0';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS region         TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS labels         JSONB NOT NULL DEFAULT '{}'::jsonb;

-- CR-5（spec 1.2.0 已裁决，additive）：客户端运行态自述，**不落成枚举**（M02 §3 注）
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS runtime_state  TEXT;

-- ---------------------------------------------------------------- 绑定（CR-4：存 nodes 列 + node_events 历史）
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS bound_account_id UUID;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS bound_at         TIMESTAMPTZ;
-- 注意：``revoked_at`` = **绑定**撤销时刻（M02 §3 Binding / spec NodeBinding.revoked_at）；
-- 密钥撤销另用 key_revoked_at，二者不要混。
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS revoked_at       TIMESTAMPTZ;

-- ---------------------------------------------------------------- 客户端密钥（只存哈希，INV-10）
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS key_id              UUID;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS key_issued_at       TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS key_revoked_at      TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS prev_key_id         UUID;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS prev_key_hash       TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS prev_key_expires_at TIMESTAMPTZ;

-- ---------------------------------------------------------------- 生命周期 / 审核 / 清退
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS reviewed_at          TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS reviewed_by          TEXT;
-- INV-09 清退两段：降权（不再派新单）→ 摘除（retired）；retire_requested_at 记降权时刻
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS retire_requested_at  TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS retired_at           TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS updated_at           TIMESTAMPTZ NOT NULL DEFAULT now();

-- 只读别名：M02 §5 字段名 lifecycle_state（单事实来源 = state）
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS lifecycle_state TEXT
  GENERATED ALWAYS AS (state) STORED;

-- ---------------------------------------------------------------- 约束（NOT VALID：不改存量行）
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_access_modes_ck') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_access_modes_ck
      CHECK (access_modes <@ ARRAY['A1', 'A2', 'B']::text[]) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_binding_pair_ck') THEN
    -- INV-08：一个节点同时只有一条有效绑定；bound_account_id 与 bound_at 同生同灭
    ALTER TABLE nodes ADD CONSTRAINT nodes_binding_pair_ck
      CHECK ((bound_account_id IS NULL) = (bound_at IS NULL)
             AND (revoked_at IS NULL OR bound_at IS NULL OR revoked_at >= bound_at)) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_key_overlap_ck') THEN
    -- INV-10：轮换重叠 ≤24 h，重叠期内旧钥只验签
    ALTER TABLE nodes ADD CONSTRAINT nodes_key_overlap_ck
      CHECK (prev_key_expires_at IS NULL
             OR (prev_key_hash IS NOT NULL
                 AND key_issued_at IS NOT NULL
                 AND prev_key_expires_at > key_issued_at
                 AND prev_key_expires_at <= key_issued_at + interval '24 hours')) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_retired_chk') THEN
    -- 清退必须留摘除时刻（存量行可能不满足，故 NOT VALID）
    ALTER TABLE nodes ADD CONSTRAINT nodes_retired_chk
      CHECK (state <> 'retired' OR retired_at IS NOT NULL) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_policy_version_chk') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_policy_version_chk
      CHECK (char_length(policy_version) BETWEEN 1 AND 64) NOT VALID;
  END IF;
END
$$;

-- ---------------------------------------------------------------- 索引（M02 §5 索引与唯一）
-- INV-01：(platform, hardware_fingerprint) 唯一；同指纹重注册幂等返回同一 node_id
CREATE UNIQUE INDEX IF NOT EXISTS nodes_platform_fp_uq
  ON nodes (platform, hardware_fingerprint);
CREATE INDEX IF NOT EXISTS nodes_account_idx
  ON nodes (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS nodes_bound_account_idx
  ON nodes (bound_account_id) WHERE bound_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS nodes_state_seen_idx
  ON nodes (state, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS nodes_prev_key_idx
  ON nodes (prev_key_hash) WHERE prev_key_hash IS NOT NULL;

COMMIT;
