# SPDX-License-Identifier: Apache-2.0
"""M02 上线前盘点（R5）：重复硬件指纹必须为 0。

背景（R5，Lead 已并入 T6 清单）：``nodes(platform, hardware_fingerprint)`` 的唯一索引
由 200 迁移建立；若**存量**数据里同一指纹出现在不同 ``node_id`` 上（003 时代没有唯一约束），
索引会建不起来，或者建起来后仍有历史脏数据。上线前必须盘点到 0 并人工归并。

用法（工作树 ``PYTHONPATH=$PWD``，只读，不写库）::

    python -m app.supply.audit --schema <schema>            # 人类可读报告
    python -m app.supply.audit --schema <schema> --json     # 机器可读

退出码：0 = 无重复；1 = 有重复（阻断上线）；2 = 参数 / 连接问题。
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Any

import psycopg

DUPLICATE_SQL = """
    SELECT platform, hardware_fingerprint, count(*) AS copies,
           array_agg(id ORDER BY created_at, id) AS node_ids
      FROM nodes
     GROUP BY platform, hardware_fingerprint
    HAVING count(*) > 1
     ORDER BY copies DESC, platform, hardware_fingerprint
"""

SUMMARY_SQL = """
    SELECT count(*) AS nodes,
           count(*) FILTER (WHERE state = 'pending') AS pending,
           count(*) FILTER (WHERE state = 'active') AS active,
           count(*) FILTER (WHERE state = 'frozen') AS frozen,
           count(*) FILTER (WHERE state = 'retired') AS retired,
           count(*) FILTER (WHERE state = 'retired' AND retired_at IS NULL) AS retired_without_ts
      FROM nodes
"""


def duplicate_fingerprints(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """返回重复指纹分组（**只报哈希与 node_id，不回传任何明文指纹**）。"""
    with conn.cursor() as cur:
        cur.execute(DUPLICATE_SQL)
        columns = [desc.name for desc in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]


def summary(conn: psycopg.Connection) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute(SUMMARY_SQL)
        columns = [desc.name for desc in cur.description]
        row = cur.fetchone()
    return {key: int(value or 0) for key, value in zip(columns, row or ())}


def report(conn: psycopg.Connection) -> dict[str, Any]:
    duplicates = duplicate_fingerprints(conn)
    counts = summary(conn)
    blockers = []
    if duplicates:
        blockers.append(f"重复硬件指纹 {len(duplicates)} 组（唯一索引前置条件，必须为 0）")
    if counts.get("retired_without_ts"):
        blockers.append(f"retired 但缺 retired_at 的节点 {counts['retired_without_ts']} 个")
    return {"duplicate_fingerprints": duplicates, "summary": counts, "blockers": blockers,
            "ready": not blockers}


def _connect(schema: str) -> psycopg.Connection:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        raise RuntimeError("缺 DJB_DSN")
    options = f"-c search_path={schema}" if schema else ""
    return psycopg.connect(dsn, autocommit=True, options=options or "-c search_path=public")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M02 上线前盘点（默认只读）")
    parser.add_argument("--schema", default="public", help="目标 schema（默认 public，只读）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)
    try:
        conn = _connect(args.schema)
    except Exception as exc:                                   # pragma: no cover - 环境问题
        print(f"连接失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    try:
        data = report(conn)
    finally:
        conn.close()
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    else:
        s = data["summary"]
        print(f"schema={args.schema} 节点={s['nodes']} pending={s['pending']} "
              f"active={s['active']} frozen={s['frozen']} retired={s['retired']}")
        if data["duplicate_fingerprints"]:
            print("重复硬件指纹（必须归并到 0）：")
            for item in data["duplicate_fingerprints"]:
                print(f"  {item['platform']} {item['hardware_fingerprint'][:16]}… "
                      f"×{item['copies']} → {', '.join(item['node_ids'])}")
        print("上线前置检查：" + ("通过" if data["ready"] else "；".join(data["blockers"])))
    return 0 if data["ready"] else 1


if __name__ == "__main__":                                     # pragma: no cover
    raise SystemExit(main())
