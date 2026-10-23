-- 406 · M04 scheduler-pricing · 模型主数据（model_catalog）
-- 规格：M04 §5 数据所有权（**长期保留**；01-ownership §2 列为「共享只读对象」）·
--       M04 §6 P1 F1（model slug **归一后**比较）· 03-facts §4（费率 / gas 归 M08/M10）
--
-- 设计要点
--   1) 主键是**归一化**后的 model slug（小写 + 去首尾空白 + 折叠空白），
--      P1 的能力匹配用归一后比较（M04 §6 F1），原始写法另存 `display_name`。
--   2) `price_version` 指向生效的价格快照版本（M10 policy_version 同族），
--      本模块只读它进决策锚点，不写费率、不算费（计费归 M05/M06）。
--   3) 状态：active（可路由）/ deprecated（还能用但告警）/ retired（不参与候选集）。
BEGIN;

CREATE TABLE IF NOT EXISTS model_catalog (
  model          TEXT PRIMARY KEY,
  display_name   TEXT,
  vendor         TEXT NOT NULL,
  unit           TEXT NOT NULL,                                  -- token / gpu_second / gb_hour
  price_version  TEXT NOT NULL,
  state          TEXT NOT NULL DEFAULT 'active',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT model_catalog_slug_ck CHECK (model = lower(btrim(model)) AND char_length(model) BETWEEN 1 AND 200),
  CONSTRAINT model_catalog_vendor_len_ck CHECK (char_length(vendor) BETWEEN 1 AND 128),
  CONSTRAINT model_catalog_unit_len_ck CHECK (char_length(unit) BETWEEN 1 AND 64),
  CONSTRAINT model_catalog_price_version_ck CHECK (char_length(price_version) BETWEEN 1 AND 64),
  CONSTRAINT model_catalog_state_ck CHECK (state IN ('active', 'deprecated', 'retired')),
  CONSTRAINT model_catalog_display_len_ck
    CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 200)
);

CREATE INDEX IF NOT EXISTS model_catalog_state_idx  ON model_catalog (state);
CREATE INDEX IF NOT EXISTS model_catalog_vendor_idx ON model_catalog (vendor, state);

COMMENT ON TABLE  model_catalog IS 'M04 模型主数据（长期保留）：归一化 slug 为主键；价格版本只读进决策锚点';
COMMENT ON COLUMN model_catalog.price_version IS '生效价格快照版本（M10 同族）；M04 只读、不算费';

COMMIT;
