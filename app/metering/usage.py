# SPDX-License-Identifier: Apache-2.0
"""用量查询：汇总（``GET /api/v1/user/usage/summary``）与明细（``.../records``，游标分页）。

口径（M05 §4.1 / spec ``UsageSummary`` / ``UsageRecordPage``）：

* **只读**、只看本账户（``account_id`` 由鉴权主体给出，路由层强制）；
* 汇总按 ``group_by=model|day``（spec 枚举），``day`` 是 **UTC 日**（00-conventions §4.2）；
* 明细默认 50、上限 200，游标是不透明串（base64url(``recorded_at|usage_id``)），
  **不得用 offset 翻页**（00-conventions §5）；排序键固定 ``recorded_at DESC, usage_id DESC``；
* 金额出口一律 ``Amount`` 形状（十进制字符串 + ``USD``），不在客户端做浮点运算；
* 不含 prompt / response 正文（INV-10）——表里本来就没有正文字段。
"""
from __future__ import annotations

import base64
import binascii
import uuid
from typing import Any

from . import amounts, clock, errors, facts, models


# ───────────────────────────────────────────────────────────────────── 汇总
_TOTAL_SQL = """
    SELECT count(*)                                   AS requests,
           COALESCE(sum(tokens_in), 0)                AS prompt_tokens,
           COALESCE(sum(tokens_out), 0)               AS completion_tokens,
           COALESCE(sum(amount_minor), 0)             AS billable_minor
      FROM usage_records
     WHERE account_id = %(account_id)s
       AND recorded_at >= %(date_from)s
       AND recorded_at <= %(date_to)s
"""

_GROUP_SQL = """
    SELECT {key}                                      AS group_key,
           count(*)                                   AS requests,
           COALESCE(sum(tokens_in), 0) + COALESCE(sum(tokens_out), 0) AS tokens,
           COALESCE(sum(amount_minor), 0)             AS billable_minor
      FROM usage_records
     WHERE account_id = %(account_id)s
       AND recorded_at >= %(date_from)s
       AND recorded_at <= %(date_to)s
     GROUP BY 1
     ORDER BY 1
"""


def summary(c: Any, *, account_id: str, date_from: Any, date_to: Any,
            group_by: str = "model") -> dict[str, Any]:
    """用量汇总（已含 ``period`` 回显；``group_by=day`` 用 UTC 日字符串作 key）。"""
    if group_by not in ("model", "day"):
        raise errors.InvalidArgument("group_by 只能是 model 或 day", field="group_by")
    moment_from = models.parse_moment(date_from, field="from")
    moment_to = models.parse_moment(date_to, field="to", end_of_day=True)
    if moment_to < moment_from:
        raise errors.InvalidArgument("to 不能早于 from", field="to")
    params = {"account_id": account_id, "date_from": moment_from, "date_to": moment_to}
    key_sql = "model" if group_by == "model" else \
        "to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')"

    with c.cursor() as cur:
        cur.execute(_TOTAL_SQL, params)
        requests, prompt_tokens, completion_tokens, billable = cur.fetchone()
        cur.execute(_GROUP_SQL.format(key=key_sql), params)
        rows = cur.fetchall()

    return {
        "period": {"from": models.iso(moment_from), "to": models.iso(moment_to)},
        "group_by": group_by,
        "totals": {
            "requests": int(requests or 0),
            "prompt_tokens": int(prompt_tokens or 0),
            "completion_tokens": int(completion_tokens or 0),
            "billable": {"amount": amounts.format_minor(int(billable or 0)),
                         "unit": facts.CURRENCY},
        },
        "groups": [
            {"key": str(key), "requests": int(count),
             "tokens": int(tokens or 0),
             "billable": {"amount": amounts.format_minor(int(group_minor or 0)),
                          "unit": facts.CURRENCY}}
            for key, count, tokens, group_minor in rows
        ],
    }


# ───────────────────────────────────────────────────────────────────── 明细（游标分页）
def encode_cursor(recorded_at: Any, usage_id: str) -> str:
    """游标 = base64url(``<UTC iso>|<usage_id>``)；不加密、不可猜（由服务端生成）。"""
    raw = f"{models.iso(clock.as_utc(recorded_at))}|{usage_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[Any, str]:
    """解析游标；非法 / 超长 / 结构不对 → 400/40001（不泄露内部字段名）。"""
    if not isinstance(cursor, str) or not cursor:
        raise errors.InvalidArgument("cursor 不能为空", field="cursor")
    if len(cursor) > facts.MAX_CURSOR_LEN:
        raise errors.InvalidArgument("cursor 超长", field="cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise errors.InvalidArgument("cursor 非法", field="cursor") from exc
    moment_text, _, usage_text = raw.partition("|")
    if not usage_text:
        raise errors.InvalidArgument("cursor 非法", field="cursor")
    try:
        moment = models.parse_moment(moment_text, field="cursor")
        usage_id = str(uuid.UUID(usage_text))
    except (errors.MeteringError, ValueError, AttributeError) as exc:
        raise errors.InvalidArgument("cursor 非法", field="cursor") from exc
    return moment, usage_id


_RECORD_COLUMNS = """
    usage_id, request_id, attempt_no, account_id, node_id, model, access,
    tokens_in, tokens_out, amount_minor, usage_source, state, receipt_id,
    correction_id, recorded_at
"""


def _row_to_usage(row: tuple) -> models.UsageRow:
    return models.UsageRow(
        usage_id=str(row[0]), request_id=row[1], attempt_no=int(row[2]), account_id=str(row[3]),
        node_id=row[4], model=row[5], access=row[6], tokens_in=int(row[7]),
        tokens_out=int(row[8]), amount_minor=int(row[9]), usage_source=row[10], state=row[11],
        receipt_id=row[12], correction_id=row[13], recorded_at=row[14])


def records_page(c: Any, *, account_id: str, limit: int | None = None, cursor: str | None = None,
                 model: str | None = None, state: str | None = None,
                 date_from: Any = None, date_to: Any = None) -> dict[str, Any]:
    """用量明细分页（默认 50、上限 200；``has_more`` + ``next_cursor``）。"""
    page_size = facts.DEFAULT_PAGE_SIZE if limit is None else int(limit)
    if page_size < 1 or page_size > facts.MAX_PAGE_SIZE:
        raise errors.InvalidArgument(
            f"limit 必须是 1..{facts.MAX_PAGE_SIZE}", field="limit")
    if state is not None and state not in facts.USAGE_STATES:
        raise errors.InvalidArgument("state 取值非法", field="state",
                                     allowed=list(facts.USAGE_STATES))

    where = ["account_id = %(account_id)s"]
    params: dict[str, Any] = {"account_id": account_id, "limit": page_size + 1}
    if model:
        where.append("model = %(model)s")
        params["model"] = model
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    if date_from is not None:
        where.append("recorded_at >= %(date_from)s")
        params["date_from"] = models.parse_moment(date_from, field="from")
    if date_to is not None:
        where.append("recorded_at <= %(date_to)s")
        params["date_to"] = models.parse_moment(date_to, field="to", end_of_day=True)
    if cursor:
        moment, usage_id = decode_cursor(cursor)
        where.append("(recorded_at, usage_id) < (%(cursor_ts)s, %(cursor_id)s)")
        params["cursor_ts"] = moment
        params["cursor_id"] = usage_id

    sql = (f"SELECT {_RECORD_COLUMNS} FROM usage_records "
           f"WHERE {' AND '.join(where)} "
           "ORDER BY recorded_at DESC, usage_id DESC LIMIT %(limit)s")
    with c.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    has_more = len(rows) > page_size
    page_rows = rows[:page_size]
    items = [_row_to_usage(row) for row in page_rows]
    next_cursor = encode_cursor(items[-1].recorded_at, items[-1].usage_id) if (has_more and items) \
        else None
    return {
        "data": [item.as_dict() for item in items],
        "page": {"cursor": cursor or "", "has_more": has_more, "next_cursor": next_cursor},
    }


__all__ = ["summary", "records_page", "encode_cursor", "decode_cursor"]
