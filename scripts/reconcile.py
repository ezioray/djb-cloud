# SPDX-License-Identifier: Apache-2.0
"""双边对账：节点上报 vs 平台记账，差异必须为 0。"""
import json, sys

from app import db
from app.reconcile import run


def main():
    expect_zero = "--expect-zero" in sys.argv
    task_ids = [a.split("=", 1)[1] for a in sys.argv if a.startswith("--task-id=")] or None
    with db.conn() as c:
        r = run(c, task_ids=task_ids)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if expect_zero and r["diff"] != 0:
        print("❌ 对账差异非 0 —— 按 P0 处置", file=sys.stderr)
        sys.exit(1)
    print("✅ 对账差异 = 0" if r["diff"] == 0 else f"⚠️ 差异 {r['diff']}")


if __name__ == "__main__":
    main()
