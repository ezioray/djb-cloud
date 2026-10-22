# SPDX-License-Identifier: Apache-2.0
"""极简行覆盖率（stdlib 实现，零依赖）。

为什么不用 coverage.py：M10 工作境只装了 pytest / psycopg / pyyaml，装新依赖要么污染共享
venv、要么联网；验收要求「覆盖率 ≥80%」需要可复现的数字，所以用 ``sys.settrace`` 自己数：

  · 只统计 ``app/config_center/*.py``（目标模块），不统计测试自身与第三方；
  · 可执行行 = ``dis.findlinestarts`` 递归收集的 code object 行号（不含空行/注释/文档字符串）；
  · 通过 ``M10_COVERAGE=1`` 启用，``M10_COVERAGE_OUT=<path>`` 落 JSON；平时跑测试零开销。

局限（写进证据文件 §风险）：这是**行覆盖率**，不是分支覆盖率；生成器/装饰器内部的行可能
被算作已执行。对本模块（大量纯函数 + SQL 字符串）足够反映「哪些逻辑没被测到」。
"""
from __future__ import annotations

import dis
import json
import os
import pathlib
import sys
from types import CodeType
from typing import Any

__all__ = ["LineCoverage", "maybe_start"]


def _executable_lines(code: CodeType) -> set[int]:
    lines: set[int] = set()
    for _, lineno in dis.findlinestarts(code):
        if lineno:
            lines.add(lineno)
    for const in code.co_consts:
        if isinstance(const, CodeType):
            lines |= _executable_lines(const)
    return lines


class LineCoverage:
    """记录目标目录下的行命中。"""

    def __init__(self, roots: list[pathlib.Path]) -> None:
        self.roots = [root.resolve() for root in roots]
        self.prefixes = tuple(str(root) + os.sep for root in self.roots)
        self.hits: dict[str, set[int]] = {}
        self._previous: Any = None

    def start(self) -> None:
        self._previous = sys.gettrace()
        sys.settrace(self._trace)

    def stop(self) -> None:
        sys.settrace(self._previous)

    def _trace(self, frame: Any, event: str, arg: Any) -> Any:
        filename = frame.f_code.co_filename
        if not filename.startswith(self.prefixes):
            return None
        if event == "line":
            self.hits.setdefault(filename, set()).add(frame.f_lineno)
        return self._trace

    def report(self) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        total_exec = total_hit = 0
        for root in self.roots:
            for path in sorted(root.glob("*.py")):
                source = path.read_text(encoding="utf-8")
                code = compile(source, str(path), "exec")
                executable = _executable_lines(code)
                executed = self.hits.get(str(path), set()) & executable
                exec_n, hit_n = len(executable), len(executed)
                total_exec += exec_n
                total_hit += hit_n
                files.append({
                    "file": str(path),
                    "executable": exec_n,
                    "hit": hit_n,
                    "percent": round(100.0 * hit_n / exec_n, 2) if exec_n else 100.0,
                    "missing": sorted(executable - executed)[:40],
                })
        percent = round(100.0 * total_hit / total_exec, 2) if total_exec else 100.0
        return {
            "files": files,
            "total_executable": total_exec,
            "total_hit": total_hit,
            "percent": percent,
        }


def maybe_start() -> LineCoverage | None:
    """``M10_COVERAGE=1`` 时启动；返回实例供 conftest 在 session 结束时落盘。"""
    if os.environ.get("M10_COVERAGE") != "1":
        return None
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    coverage = LineCoverage([repo_root / "app" / "config_center"])
    coverage.start()
    return coverage


def write_report(coverage: LineCoverage, path: str) -> dict[str, Any]:
    report = coverage.report()
    report["written_to"] = path
    pathlib.Path(path).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
