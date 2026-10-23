-- 1101 · M11 限额定义（risk_limits）+ 只读视图 v_risk_limits
-- 规格：M11-risk-abuse.md §3（risk_limit 生命周期：新增 / 调整 / 过期回收）· §4.3（限额由
--       M03 / M04 / M08 读 v_risk_limits 本地判定，本模块不进入转发路径；CR-2 方案 A）
--       §5 数据所有权（迁移 1101，保留 = 有效期内 + 1 年）
--
-- 说明：
--   1) 本表存的是**对单个主体的限额**（契约 RiskLimit.value / window_s），不是规则阈值；
--      规则阈值只存在于 M10 私有 risk-config（INV-01），本表没有任何命中条件 / 权重字段。
--   2) 同一 (subject_type, subject_id, limit_type) 原地调整：revision 单调 +1，保留 updated_at。
--   3) v_risk_limits 是**只读**视图：只暴露当前生效（未过期）的限额，供 M03 / M04 / M08
--      同步判定；不含任何规则命中信息，也不含名单。
--   4) 可重复执行：IF NOT EXISTS / CREATE OR REPLACE / 约束先 DROP 再 ADD。
BEGIN;

CREATE TABLE IF NOT EXISTS risk_limits (
  id            BIGSERIAL PRIMARY KEY,
  tenant_id     TEXT NOT NULL,                     -- 隔离域（管理面主体所属租户）
  subject_type  TEXT NOT NULL,                     -- account / node / key / address
  subject_id    TEXT NOT NULL,                     -- 主体标识（账户 id / 节点 id / key id / 地址）
  limit_type    TEXT NOT NULL,                     -- 限额类型（如 qps / daily_quota / payout_daily）
  value         BIGINT NOT NULL,                   -- 限额值（MINOR 或计数；语义由 limit_type 决定）
  window_s      INTEGER NOT NULL,                  -- 窗口秒数（0 = 无窗口 / 即时）
  expires_at    TIMESTAMPTZ,                       -- 过期时间（NULL = 长期有效，直到被调整）
  revision      INTEGER NOT NULL DEFAULT 1,        -- 调整代数（每次变更 +1；48005 用）
  set_by        TEXT NOT NULL,                     -- 设置人（管理面主体）
  idempotency_key TEXT,                            -- 设置幂等键（16..128）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT risk_limits_uq UNIQUE (tenant_id, subject_type, subject_id, limit_type),
  CONSTRAINT risk_limits_subject_type_ck CHECK
    (subject_type IN ('account', 'node', 'key', 'address')),
  CONSTRAINT risk_limits_range_ck CHECK (value >= 0 AND window_s >= 0),
  CONSTRAINT risk_limits_type_ck CHECK (char_length(limit_type) BETWEEN 1 AND 64),
  CONSTRAINT risk_limits_revision_ck CHECK (revision >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS risk_limits_idem_uq
  ON risk_limits (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS risk_limits_subject_idx
  ON risk_limits (tenant_id, subject_type, subject_id);
CREATE INDEX IF NOT EXISTS risk_limits_expiry_idx
  ON risk_limits (expires_at) WHERE expires_at IS NOT NULL;

COMMENT ON TABLE risk_limits IS
  'M11 限额：对 subject 的可执行限额（value/window_s）；规则阈值/权重/名单不入库（INV-01）';

-- 只读视图：当前生效限额（过期即回收，不需要后台任务）
CREATE OR REPLACE VIEW v_risk_limits AS
  SELECT tenant_id,
         subject_type,
         subject_id,
         limit_type,
         value,
         window_s,
         expires_at,
         revision,
         updated_at
    FROM risk_limits
   WHERE expires_at IS NULL OR expires_at > now();

COMMENT ON VIEW v_risk_limits IS
  'M11 只读视图：当前生效限额（M03 / M04 / M08 本地判定；不含阈值/名单，本模块不进转发路径）';

COMMIT;
