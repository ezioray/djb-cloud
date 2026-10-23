-- 905 · M09 对账 · 报表版本（report_renders）
-- 规格：M09-recon-reports.md §3.1（report_id · period · cutoff_at · data_hash · report_version ·
--       svg / pdf_object_key · status）/ §3.2（draft -> rendered -> signed_off -> archived；
--       incomplete 只能重跑）/ §3.3 INV-07（报表数字只来自当期 run / por 快照；
--       report_version = H(report_id, cutoff_at, data_hash, renderer_version)，同版本不可覆盖）/
--       §3.3 INV-08（SVG 校验不过不得进 rendered）
--       §5 数据所有权（report_renders，保留 5 年及以上）
--
-- 本轮（T1–T3）只建表与视图：REP-01/02 先出 JSON（不属于「渲染件」），SVG/PDF 与版本
-- 归档留 T4（REP-03/04/06 同批）。表在这里建好，T4 不再改 9xx 编号。
BEGIN;

CREATE TABLE IF NOT EXISTS report_renders (
  render_id        UUID PRIMARY KEY,                  -- UUIDv7
  report_id        TEXT NOT NULL,                     -- REP-01 … REP-06（REP-05 不在本模块）
  period           TEXT NOT NULL,                     -- YYYY-MM（spec ReportPeriod）或 YYYY-MM-DD（CR-1 若裁决）
  cutoff_at        TIMESTAMPTZ NOT NULL,              -- 取数截止（同版本口径固定）
  data_hash        TEXT NOT NULL,                     -- 报表主体 canonical JSON 的 sha256
  report_version   TEXT NOT NULL,                     -- H(report_id, cutoff_at, data_hash, renderer_version)
  renderer_version TEXT NOT NULL,
  svg_object_key   TEXT,                              -- 对象存储 key（不存正文）
  pdf_object_key   TEXT,                              -- 由同一 SVG 渲染，不二次取数（§6.3）
  status           TEXT NOT NULL DEFAULT 'draft',
  fail_reason      TEXT,                              -- incomplete / svg_invalid / storage_unavailable
  tenant_id        TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT report_renders_report_id_ck CHECK (
    report_id IN ('REP-01', 'REP-02', 'REP-03', 'REP-04', 'REP-06')),
  CONSTRAINT report_renders_period_ck CHECK (
    period ~ '^[0-9]{4}-(0[1-9]|1[0-2])(-(0[1-9]|[12][0-9]|3[01]))?$'),
  CONSTRAINT report_renders_status_ck CHECK (
    status IN ('draft', 'rendered', 'signed_off', 'archived')),
  CONSTRAINT report_renders_hash_ck CHECK (data_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT report_renders_version_ck CHECK (report_version ~ '^[0-9a-f]{64}$'),
  -- INV-08：没有对象 key 不得进 rendered
  CONSTRAINT report_renders_rendered_ck CHECK (
    status IN ('draft') OR svg_object_key IS NOT NULL)
);

-- INV-07：同 (report_id, period, report_version) 不可覆盖（历史版本只读）
CREATE UNIQUE INDEX IF NOT EXISTS report_renders_version_uq
  ON report_renders (report_id, period, report_version);
CREATE INDEX IF NOT EXISTS report_renders_lookup_idx
  ON report_renders (report_id, period, created_at DESC);
CREATE INDEX IF NOT EXISTS report_renders_tenant_idx
  ON report_renders (tenant_id, created_at DESC) WHERE tenant_id IS NOT NULL;

CREATE OR REPLACE FUNCTION m09_report_renders_guard() RETURNS trigger AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['draft->rendered', 'rendered->signed_off', 'signed_off->archived'];
  v_draft_mutable TEXT[] := ARRAY['status', 'svg_object_key', 'pdf_object_key', 'data_hash',
                                  'report_version', 'renderer_version', 'fail_reason', 'updated_at'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'report_renders is append-only: DELETE not allowed (M09 §3.1)'
      USING ERRCODE = '42501';
  END IF;

  -- 离开 draft 后：只有 status / updated_at 可变（历史只读，§3.1）
  IF OLD.status <> 'draft' THEN
    IF (to_jsonb(NEW) - ARRAY['status', 'updated_at'])
       IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'updated_at']) THEN
      RAISE EXCEPTION 'report_renders is read-only after rendering (M09 §3.1)'
        USING ERRCODE = '42501';
    END IF;
  ELSIF (to_jsonb(NEW) - v_draft_mutable) IS DISTINCT FROM (to_jsonb(OLD) - v_draft_mutable) THEN
    RAISE EXCEPTION 'report_renders: only % may change in draft (M09 §3.1)', v_draft_mutable
      USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'report_renders: illegal transition % -> % (M09 §3.2)',
      OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS report_renders_guard ON report_renders;
CREATE TRIGGER report_renders_guard BEFORE UPDATE OR DELETE ON report_renders
  FOR EACH ROW EXECUTE FUNCTION m09_report_renders_guard();
DROP TRIGGER IF EXISTS report_renders_no_truncate ON report_renders;
CREATE TRIGGER report_renders_no_truncate BEFORE TRUNCATE ON report_renders
  FOR EACH STATEMENT EXECUTE FUNCTION m09_forbid_truncate();

-- 只读视图：每 (report_id, period) 的最新版本 + 版本数（历史版本仍在表里）
CREATE OR REPLACE VIEW v_m09_report_versions AS
  SELECT report_id, period,
         count(*)                          AS version_count,
         max(created_at)                   AS latest_created_at,
         (array_agg(report_version ORDER BY created_at DESC))[1] AS latest_version,
         (array_agg(status ORDER BY created_at DESC))[1]         AS latest_status
    FROM report_renders
   GROUP BY report_id, period;

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['render_id','report_id','period','cutoff_at','data_hash','report_version',
                      'renderer_version','svg_object_key','pdf_object_key','status',
                      'fail_reason','tenant_id','created_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'report_renders'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'report_renders 结构与 905 不符，缺列：%', v_missing;
  END IF;
  IF to_regclass('report_renders_version_uq') IS NULL THEN
    RAISE EXCEPTION 'report_renders 缺 (report_id, period, report_version) 唯一索引（905 / INV-07）';
  END IF;
END;
$$;

COMMIT;
