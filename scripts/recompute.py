# SPDX-License-Identifier: AGPL-3.0-or-later
"""账本全量复算：差异必须为 0。"""
import json, sys

from app import db
from app.ledger import recompute


def main():
    expect_zero = "--expect-zero" in sys.argv
    with db.conn() as c:
        r = recompute(c)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if expect_zero and r["diff"] != 0:
        print("❌ 复算差异非 0 —— 按 P0 处置", file=sys.stderr)
        sys.exit(1)
    print("✅ 复算差异 = 0" if r["diff"] == 0 else f"⚠️ 差异 {r['diff']}")


if __name__ == "__main__":
    main()
