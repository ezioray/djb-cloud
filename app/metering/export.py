# SPDX-License-Identifier: AGPL-3.0-or-later
"""M05 §4.1 账单导出（spec 1.2.6 ``exportUserBilling``）：``GET /api/v1/user/billing/export``。

口径（spec 1.2.6 + M05 §4.1）：

* **只导本人范围**：``account_id`` 由鉴权主体给出并在 SQL 里强制，不做跨账户查询；
* **流式**：CSV 逐行 / JSON 数组逐元素，keyset 批读（``recorded_at, usage_id`` 升序），
  内存不随导出体量增长；不落导出正文（服务端只写一行审计日志，不含任何行内容）；
* **金额**：``amount_minor`` 整数最小单位 + ``currency``（S1 仅 USD，00-conventions §3），
  **不含** prompt / response 正文、凭据与 PII——``usage_records`` 表本来就没有正文字段（INV-10）；
* **时间窗**：``from`` / ``to`` 为 UTC（含端点）；窗口过大直接 400/40001（客户端拆分），
  不做静默截断；
* **下载凭据有效期**：响应头 ``X-DJB-Export-Expires-At`` = 申请时刻 + TTL（≤15 分钟）；
  文件名走 ``Content-Disposition: attachment; filename="billing-<period>.<csv|json>"``，
  由服务端构造，不含内部路径。
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Iterator, Mapping

from . import clock, errors, facts, models

log = logging.getLogger("djb.metering.export")

#: 响应头（spec 1.2.6：文件名 + 凭据 TTL）
EXPORT_EXPIRES_HEADER = "X-DJB-Export-Expires-At"
EXPORT_DISPOSITION_HEADER = "Content-Disposition"

#: 导出行的字段顺序（CSV 表头同序；JSON 每个元素同一键集；**新增字段只能追加**）
ROW_FIELDS: tuple[str, ...] = (
    "usage_id", "request_id", "attempt_no", "node_id", "model", "access",
    "tokens_in", "tokens_out", "amount_minor", "currency", "usage_source", "state",
    "receipt_id", "recorded_at",
)

#: 批读列（顺序与 ``_COLUMN_NAMES`` 一一对应）
_COLUMN_NAMES: tuple[str, ...] = (
    "usage_id", "request_id", "attempt_no", "node_id", "model", "access",
    "tokens_in", "tokens_out", "amount_minor", "usage_source", "state", "receipt_id",
    "recorded_at",
)

_ROW_SQL_BASE = """
    SELECT usage_id, request_id, attempt_no, node_id, model, access,
           tokens_in, tokens_out, amount_minor, usage_source, state, receipt_id, recorded_at
      FROM usage_records
     WHERE account_id = %(account_id)s
       AND recorded_at >= %(date_from)s
       AND recorded_at <= %(date_to)s
"""
_ROW_SQL_CURSOR = """
       AND (recorded_at, usage_id) > (%(cursor_ts)s, %(cursor_id)s)
"""
_ROW_SQL_TAIL = """
     ORDER BY recorded_at, usage_id
     LIMIT %(limit)s
"""


# --------------------------------------------------------------------------- 参数校验
def validate_format(raw: Any) -> str:
    """``format`` 枚举（默认 csv）；其它值 → 400/40001（不猜、不回落）。"""
    if raw is None:
        return facts.EXPORT_FORMATS[0]
    if not isinstance(raw, str) or raw.strip() not in facts.EXPORT_FORMATS:
        raise errors.InvalidArgument("format 只能是 csv / json", field="format",
                                     allowed=list(facts.EXPORT_FORMATS))
    return raw.strip()


def validate_window(date_from: Any, date_to: Any) -> tuple[datetime, datetime]:
    """解析并校验时间窗（UTC 含端点）；``to < from`` 或窗口过大 → 400/40001。"""
    start = models.parse_moment(date_from, field="from")
    end = models.parse_moment(date_to, field="to", end_of_day=True)
    if end < start:
        raise errors.InvalidArgument("to 不能早于 from", field="to")
    if end - start > timedelta(days=facts.EXPORT_MAX_WINDOW_DAYS):
        raise errors.InvalidArgument(
            f"时间窗过大（>{facts.EXPORT_MAX_WINDOW_DAYS} 天），请拆分后重新导出",
            field="from", reason="window_too_large")
    return start, end


def expires_at(moment: datetime | None = None) -> datetime:
    """下载凭据过期时间 = 申请时刻 + TTL（spec：≤15 分钟）。"""
    return clock.as_utc(moment or clock.utcnow()) + timedelta(seconds=facts.EXPORT_TTL_S)


def period_of(date_from: datetime, date_to: datetime) -> str:
    """文件名周期：同一 UTC 月 → ``YYYY-MM``；跨月 → ``YYYYMMDD-YYYYMMDD``。"""
    start = clock.as_utc(date_from)
    end = clock.as_utc(date_to)
    if (start.year, start.month) == (end.year, end.month):
        return f"{start.year:04d}-{start.month:02d}"
    return f"{start.strftime('%Y%m%d')}-{end.strftime('%Y%m%d')}"


def filename(*, date_from: datetime, date_to: datetime, fmt: str) -> str:
    """``billing-<period>.<fmt>``（只含数字 / 连字符 / 字母，不含内部路径）。"""
    return f"billing-{period_of(date_from, date_to)}.{fmt}"


# --------------------------------------------------------------------------- 行读取
def _row_dict(row: tuple) -> dict[str, Any]:
    values = dict(zip(_COLUMN_NAMES, row))
    for name in ("attempt_no", "tokens_in", "tokens_out", "amount_minor"):
        values[name] = int(values[name])
    values["usage_id"] = str(values["usage_id"])      # usage_records.usage_id 是 UUID 列
    for name in ("request_id", "node_id", "model", "access", "receipt_id",
                 "usage_source", "state"):
        if values[name] is not None:
            values[name] = str(values[name])
    values["currency"] = facts.CURRENCY
    values["recorded_at"] = models.iso(values["recorded_at"])
    return {name: values[name] for name in ROW_FIELDS}


def iter_rows(c: Any, *, account_id: Any, date_from: datetime, date_to: datetime,
              batch_size: int = facts.EXPORT_BATCH_SIZE) -> Iterator[dict[str, Any]]:
    """keyset 批读（稳定顺序），逐行产出 spec 账单口径的字典；**不 yield 数据库游标对象**。"""
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size < 1:
        raise errors.InvalidArgument("batch_size 必须是正整数", field="batch_size")
    cursor_ts: Any = None
    cursor_id: Any = None
    while True:
        sql = _ROW_SQL_BASE + (_ROW_SQL_CURSOR if cursor_ts is not None else "") + _ROW_SQL_TAIL
        params: dict[str, Any] = {"account_id": account_id, "date_from": date_from,
                                  "date_to": date_to, "limit": int(batch_size)}
        if cursor_ts is not None:
            params["cursor_ts"] = cursor_ts
            params["cursor_id"] = cursor_id
        with c.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        if not rows:
            return
        for row in rows:
            yield _row_dict(row)
        if len(rows) < batch_size:
            return
        cursor_id = rows[-1][0]
        cursor_ts = rows[-1][_COLUMN_NAMES.index("recorded_at")]


# --------------------------------------------------------------------------- 渲染
def csv_header() -> str:
    """CSV 表头（UTF-8 文本，含表头；字段顺序 = ``ROW_FIELDS``）。"""
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow(list(ROW_FIELDS))
    return buffer.getvalue()


def csv_line(values: Mapping[str, Any]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow(
        [values.get(name) for name in ROW_FIELDS])
    return buffer.getvalue()


def json_line(values: Mapping[str, Any]) -> str:
    return json.dumps(dict(values), ensure_ascii=False, separators=(",", ":"))


# --------------------------------------------------------------------------- 流
def stream(*, connection_factory: Any, account_id: Any, date_from: Any, date_to: Any,
           fmt: str, request_id: str = "") -> Iterator[bytes]:
    """返回流式字节迭代器（CSV 表头 + 逐行；JSON 数组）。错误信封由路由层先给。"""
    mode = validate_format(fmt)
    start, end = validate_window(date_from, date_to)
    return _generate(connection_factory=connection_factory, account_id=account_id,
                     date_from=start, date_to=end, fmt=mode, request_id=request_id)


def _generate(*, connection_factory: Any, account_id: Any, date_from: datetime,
              date_to: datetime, fmt: str, request_id: str) -> Iterator[bytes]:
    rows = 0
    with connection_factory() as c:
        try:
            if fmt == "csv":
                yield csv_header().encode("utf-8")
                for values in iter_rows(c, account_id=account_id, date_from=date_from,
                                        date_to=date_to):
                    yield csv_line(values).encode("utf-8")
                    rows += 1
            else:
                yield b"["
                first = True
                for values in iter_rows(c, account_id=account_id, date_from=date_from,
                                        date_to=date_to):
                    if not first:
                        yield b","
                    yield json_line(values).encode("utf-8")
                    first = False
                    rows += 1
                yield b"]\n"
        except Exception:                                   # pragma: no cover - 流已开始
            # 响应头已发出：不能改状态码，也不能把异常抛给已建立的连接；
            # 记录后停止输出，客户端按「提前 EOF」判定失败（服务端不落正文）。
            log.exception("metering.billing.export_failed",
                          extra={"request_id": request_id, "format": fmt})
            return
        finally:
            log.info("metering.billing.export",
                     extra={"request_id": request_id, "format": fmt, "rows": rows,
                            "from": models.iso(date_from), "to": models.iso(date_to)})


__all__ = ["ROW_FIELDS", "validate_format", "validate_window", "expires_at", "period_of",
           "filename", "iter_rows", "csv_header", "csv_line", "json_line", "stream"]
