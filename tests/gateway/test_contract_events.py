# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件契约漂移守卫（02-events §3 / 04-api-contracts §4 event-schema 门禁）。

来由：M03 T3/T4 合并时事件门禁红过一次——`batch.*` 六个 webhook 事件当时只在
`WIRING.md` 里定义、没有登记到 `contracts/02-events.md`。Lead 已补登（integration 2205500），
本文件把「代码里发的事件」与「契约里登记的事件」钉在一起，防止再犯：

* ``facts.EVENT_TYPES``（内部事件 request.completed / request.failed）必须在契约里登记，
  producer 必须是 M03；
* ``facts.WEBHOOK_EVENTS``（对外 webhook 六事件）必须在契约里登记，producer 必须是 M03；
* 契约登记的每个 payload 键，实现必须真的给出（允许的别名映射显式写在 ``ALIASES``）。
"""
from __future__ import annotations

import pathlib
import re

from app.gateway import facts, webhook

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts" / "02-events.md"

#: 契约键 → 实现里的取值路径（只允许「结构形态」差异，不允许缺数据）
ALIASES: dict[str, tuple[str, ...]] = {
    "cost_estimate": ("cost", "estimated"),
    "cost_actual": ("cost", "actual"),
}

_EVENT_TOKEN = re.compile(r"[a-z]+\.[a-z_.]+")


def _contract_rows() -> list[list[str]]:
    """把 02-events §3 的事件表切成行（`| 事件 | 生产者 | payload | 消费者 |`）。"""
    text = CONTRACT.read_text(encoding="utf-8")
    rows: list[list[str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("| ---") or line.startswith("| 事件"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        rows.append(cells)
    return rows


def _registered() -> dict[str, dict[str, str]]:
    """``{event: {producer, payload, consumers}}``（一行里可用 ``/`` 或 ``·`` 列多个事件）。"""
    out: dict[str, dict[str, str]] = {}
    for cells in _contract_rows():
        names = [name.strip() for name in re.split(r"\s*/\s*", cells[0])]
        for name in names:
            if not _EVENT_TOKEN.fullmatch(name.replace(" ", "")):
                continue
            out[name.replace(" ", "")] = {"producer": cells[1], "payload": cells[2],
                                          "consumers": cells[3]}
    return out


def _payload_keys(text: str) -> list[str]:
    """payload 列的键。

    支持契约里的缩写写法：``tokens_in/out`` → ``tokens_in`` + ``tokens_out``；
    ``cost_estimate/actual`` → ``cost_estimate`` + ``cost_actual``（后段是前段的**后缀**）。
    """
    keys: list[str] = []
    for chunk in text.split(","):
        parts = [part.strip().strip("`") for part in chunk.split("/")]
        parts = [part for part in parts if part and re.fullmatch(r"[a-z_]+", part)]
        if not parts:
            continue
        keys.append(parts[0])
        if len(parts) > 1 and "_" in parts[0]:
            prefix = parts[0][:parts[0].rfind("_") + 1]
            keys.extend(prefix + part for part in parts[1:])
    return keys


def _lookup(payload: dict, path: tuple[str, ...]):
    current = payload
    for step in path:
        if not isinstance(current, dict) or step not in current:
            return None
        current = current[step]
    return current


# ─────────────────────────────────────────────────────── 契约文件本身
def test_event_contract_exists():
    assert CONTRACT.exists(), "contracts/02-events.md 缺失（事件门禁的真相源）"


def test_internal_events_are_registered_with_m03_as_producer():
    registered = _registered()
    for event_type in facts.EVENT_TYPES:
        assert event_type in registered, f"{event_type} 未在 02-events §3 登记"
        assert registered[event_type]["producer"] == facts.EVENT_PRODUCER


def test_webhook_events_are_registered_with_m03_as_producer():
    registered = _registered()
    missing = [event for event in facts.WEBHOOK_EVENTS if event not in registered]
    assert missing == [], f"webhook 事件未登记（合并时事件门禁会红）：{missing}"
    for event_type in facts.WEBHOOK_EVENTS:
        assert registered[event_type]["producer"] == facts.EVENT_PRODUCER
        assert "webhook" in registered[event_type]["consumers"].lower()


def test_webhook_events_are_declared_as_external_delivery():
    """M03 §4.3：批次 webhook 属对客户的外部投递，不走内部事件总线。"""
    text = CONTRACT.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if "batch.queued" in line)
    assert "webhook" in row.lower()


# ─────────────────────────────────────────────────────── 实现 ↔ 契约
def test_internal_event_payload_covers_every_contract_key():
    """方向：**契约登记的键必须都发**；模块规格可在此基础上加字段（02-events §3 注）。

    例：``request.completed`` 的 ``usage_source`` 来自 M03 §4.2，属「只加不改」的增量字段。
    """
    registered = _registered()
    for event_type, keys in facts.EVENT_PAYLOAD_KEYS.items():
        documented = set(_payload_keys(registered[event_type]["payload"]))
        assert documented <= set(keys), (
            f"{event_type} payload 缺契约键：{sorted(documented - set(keys))}")


def test_webhook_payload_provides_every_contract_key():
    """契约登记的每个键，`webhook.build_payload` 都必须给出（含显式别名映射）。"""
    from datetime import datetime, timezone

    registered = _registered()
    batch_event = facts.WEBHOOK_EVENTS[0]
    documented = _payload_keys(registered[batch_event]["payload"])
    assert documented, "契约里没有解析到 webhook payload 键"

    from app.gateway import models

    batch = models.BatchView(batch_id="b-1", account_id="a-1", tenant_id="t-1", kind="chat",
                             model="m1", status="queued", total_items=2, eta_seconds=42,
                             cost_estimate_minor=500, cost_actual_minor=480,
                             created_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
    payload = webhook.build_payload(event_type=batch_event, batch=batch,
                                    occurred_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
    missing = []
    for key in documented:
        path = ALIASES.get(key, (key,))
        if _lookup(payload, path) is None:
            missing.append(key)
    assert missing == [], f"webhook payload 缺契约键：{missing}"


def test_webhook_payload_never_carries_bodies_or_secrets():
    from datetime import datetime, timezone

    from app.gateway import models

    batch = models.BatchView(batch_id="b-1", account_id="a-1", tenant_id=None, kind="chat",
                             model="m1", status="succeeded", total_items=1,
                             created_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
    payload = webhook.build_payload(event_type="batch.completed", batch=batch,
                                    occurred_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
    text = str(payload).lower()
    for forbidden in ("prompt", "content", "secret", "token_value", "api_key", "signature"):
        assert forbidden not in text
