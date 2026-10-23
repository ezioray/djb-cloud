-- 405 · M04 scheduler-pricing · 配额 / 公平计数（quota_usage）
-- 规格：M04 §3 QuotaUsage / §5 数据所有权（保留 13 个月）· §6 流程 2 P5（更新 quota_usage）
--       INV-07（并发 = min(平台下发, 终端上报, 节点 max_qps)）· INV-08（单租户同模型并发 ≤25%）
--       §4.7.5 配额（日 / 周 / 月）· 00-conventions §3.5（比例用 bps / pct）
--
-- 设计要点
--   1) 计数行按 (tenant_id, model, window_kind, window_start) 唯一：M04 §3 的 `window` = 窗口
--      种类（day / week / month，列名用 window_kind——`window` 是 PG 保留字），
--      M04 §5 的 `window_start` = 窗口起点；两者合起来才是唯一键。
--   2) `concurrent` 是「当前并发单元数」，由 P5 在决策事务内 +1、由消费方 release 时 -1；
--      只允许非负（见 CHECK）。
--   3) `share_pct` 按 00-conventions §3.5 以 **bps** 存（0–10000 = 0%–100%），
--      避免浮点参与公平判定；展示层换算百分比。
--   4) 非只追加：计数必须可增可减；但 tenant/model/window 维度不可变（改维度 = 新行）。
BEGIN;

CREATE TABLE IF NOT EXISTS quota_usage (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          UUID NOT NULL,
  model              TEXT NOT NULL,
  window_kind        TEXT NOT NULL DEFAULT 'day',   -- M04 §3 的 `window`（window 是 PG 保留字）
  window_start       TIMESTAMPTZ NOT NULL,
  concurrent         INT NOT NULL DEFAULT 0,
  daily_spend_minor  BIGINT NOT NULL DEFAULT 0,
  share_pct_bps      INT NOT NULL DEFAULT 0,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT quota_usage_window_ck CHECK (window_kind IN ('day', 'week', 'month')),
  CONSTRAINT quota_usage_concurrent_ck CHECK (concurrent >= 0),
  CONSTRAINT quota_usage_spend_ck CHECK (daily_spend_minor >= 0),
  CONSTRAINT quota_usage_share_ck CHECK (share_pct_bps BETWEEN 0 AND 10000),
  CONSTRAINT quota_usage_model_len_ck CHECK (char_length(model) BETWEEN 1 AND 200),
  CONSTRAINT quota_usage_window_uq UNIQUE (tenant_id, model, window_kind, window_start)
);

-- M04 §5 索引：quota_usage(tenant_id, model, window_start) 唯一族
CREATE INDEX IF NOT EXISTS quota_usage_tenant_model_idx ON quota_usage (tenant_id, model, window_start);
CREATE INDEX IF NOT EXISTS quota_usage_updated_idx      ON quota_usage (updated_at);

-- 维度不可变：改 tenant/model/window/window_start 只能新建行（避免计数被「挪」到别人头上）
CREATE OR REPLACE FUNCTION m04_quota_usage_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'quota_usage 不允许 DELETE（计数只能归零，不能消失）';
  END IF;

  IF NEW.tenant_id <> OLD.tenant_id
     OR NEW.model <> OLD.model
     OR NEW.window_kind <> OLD.window_kind
     OR NEW.window_start <> OLD.window_start THEN
    RAISE EXCEPTION 'quota_usage 维度列不可变（改维度请新建行）';
  END IF;

  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS quota_usage_guard_trg ON quota_usage;
CREATE TRIGGER quota_usage_guard_trg
  BEFORE UPDATE OR DELETE ON quota_usage
  FOR EACH ROW EXECUTE FUNCTION m04_quota_usage_guard();

COMMENT ON TABLE quota_usage IS
  'M04 配额 / 公平计数：13 个月保留；concurrent 由 P5 +1、消费方释放 -1；share_pct 以 bps 存';
COMMENT ON COLUMN quota_usage.window_kind IS 'M04 §3 的 window：day / week / month（保留字改名）';
COMMENT ON COLUMN quota_usage.share_pct_bps IS '单租户同模型并发占比（bps，0–10000）；INV-08 上限 25% = 2500 bps';

COMMIT;
