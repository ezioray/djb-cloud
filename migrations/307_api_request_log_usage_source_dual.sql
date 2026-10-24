-- 307 · M03 网关 · api_request_log.usage_source 枚举扩展（estimated / actual → + dual）
-- 规格：product/v4/modules/M03-gateway-protocol.md §5（usage_source 枚举，INV-M03-07「只加不改」）
--       ops/audit/reports/PROBE-TOKEN-AUDIT-20261024T0017Z.md §2.2 / §5 C9（消费侧双计）
--       M05-metering-receipt.md §5 / 迁移 501：usage_records 已接受 dual，网关请求日志需同口径
--       00-conventions §7.2「只允许加列 / 加表 / 加索引」——本迁移只放宽枚举取值，不动数据
--
-- 为什么需要这一条：
--   301 的 api_request_log_usage_source_ck 只允许 estimated / actual。``NOT VALID`` 仅豁免
--   **历史行**，新插入仍然校验。C9a 的双计路径（开关 gateway.token.dual.enabled）要写
--   usage_source='dual'；不改这条 CHECK，每次双计请求的日志行都会因 23514 静默丢失
--   （_record 捕获异常只打 warning）→ 违反 INV-M03-02「请求留痕」。
--
-- 变更内容（纯放宽，可逆，无数据迁移）：
--   1) DROP 旧 CHECK，重加**同名列**的三值 CHECK（estimated / actual / dual），仍 NOT VALID：
--      不重写表、不 UPDATE 任何历史行、不碰账本 / 收据金额；
--   2) DO 块按 pg_constraint + pg_namespace(connamespace) 复核新定义确实生效（失败即 RAISE）。
--
-- 回滚：app/gateway/migrate.py 的 DOWN_SQL 里 307 段重建旧两值 CHECK（同样 NOT VALID）——
--       已存在的 dual 行不会被删除（不重写表），只把枚举判定恢复到 301 口径。
BEGIN;

ALTER TABLE api_request_log DROP CONSTRAINT IF EXISTS api_request_log_usage_source_ck;
ALTER TABLE api_request_log ADD CONSTRAINT api_request_log_usage_source_ck
  CHECK (usage_source IS NULL OR usage_source IN ('estimated', 'actual', 'dual')) NOT VALID;

COMMENT ON COLUMN api_request_log.usage_source IS
  '用量口径：estimated / actual / dual（dual = 上游 usage 与本地 tokenizer 双计，数值仍以上游为准）';

DO $$
DECLARE
  definition TEXT;
BEGIN
  SELECT pg_get_constraintdef(con.oid) INTO definition
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = con.connamespace
   WHERE n.nspname = current_schema()
     AND c.relname = 'api_request_log'
     AND con.conname = 'api_request_log_usage_source_ck';
  IF definition IS NULL THEN
    RAISE EXCEPTION '307: api_request_log 缺约束 api_request_log_usage_source_ck';
  END IF;
  IF position('dual' IN definition) = 0 THEN
    RAISE EXCEPTION '307: usage_source 枚举未包含 dual（%）', definition;
  END IF;
END
$$;

COMMIT;
