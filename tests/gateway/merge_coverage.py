# SPDX-License-Identifier: Apache-2.0
"""把多段覆盖率会话（每个 pytest 进程一份 JSON）合并成一份：**按行取并集**。

NAS 上单进程跑完整套 + settrace 会超时（护栏 --timeout 480），所以把用例拆成几段分别跑，
再用本脚本合并。合并口径必须是「行号并集」，不能把百分比相加——那是假数。
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any


def merge(paths: list[pathlib.Path]) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        for item in report["files"]:
            slot = files.setdefault(item["file"], {"executable": item["executable"],
                                                   "hit_lines": set()})
            slot["executable"] = max(slot["executable"], item["executable"])
            slot["hit_lines"] |= set(item["hit_lines"])
    merged = []
    total_exec = total_hit = 0
    for name, slot in sorted(files.items()):
        hits = len(slot["hit_lines"])
        total_exec += slot["executable"]
        total_hit += hits
        merged.append({"file": name, "executable": slot["executable"], "hit": hits,
                       "percent": round(100.0 * hits / slot["executable"], 2)
                       if slot["executable"] else 100.0})
    return {"files": merged, "total_executable": total_exec, "total_hit": total_hit,
            "percent": round(100.0 * total_hit / total_exec, 2) if total_exec else 100.0,
            "sessions": [str(path) for path in paths]}


if __name__ == "__main__":                               # pragma: no cover - CLI
    inputs = [pathlib.Path(item) for item in sys.argv[1:-1]]
    out = pathlib.Path(sys.argv[-1])
    result = merge(inputs)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"merged {len(inputs)} sessions -> {out} : {result['percent']}%")
