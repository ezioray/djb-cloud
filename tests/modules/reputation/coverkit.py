# SPDX-License-Identifier: Apache-2.0
"""极简行覆盖率（stdlib 实现，零依赖；与 tests/modules/notify/coverkit.py 同款）。

为什么不用 coverage.py：共享 venv 只装了 pytest / psycopg / fastapi / httpx / pyyaml，
装新依赖要么污染共享 venv、要么联网；验收要求「覆盖率 ≥80%」需要可复现的数字，所以用
``sys.settrace`` 自己数：

  · 只统计 ``app/reputation/*.py``（本模块），不统计测试自身与第三方；
  · 可执行行 = ``dis.findlinestarts`` 递归收集的 code object 行号（不含空行/注释/文档字符串）；
  · 通过 ``M07_COVERAGE=1`` 启用，``M07_COVERAGE_OUT=<path>`` 落 JSON；平时跑测试零开销。

局限（写进证据文件「风险」）：这是**行覆盖率**，不是分支覆盖率；生成器/装饰器内部的行
可能被算作已执行。对本模块（纯函数 + SQL 字符串 + 路由）足够反映「哪些逻辑没被测到」。
"""
from __future__ import annotations

import dis
import json
import os
import pathlib
import sys
import threading
from types import CodeType
from typing import Any

__all__ = ["LineCoverage", "maybe_start", "write_report"]


def _excluded_lines(source: str) -> set[int]:
    """``# pragma: no cover`` 标记的行及其缩进块（与 coverage.py 的语义对齐）。

    只用于**统计口径**：防御性 ``except Exception`` / CLI 入口不纳入分母，否则会把
    「不可能在测试里触发」的行算成未覆盖，虚低 80% 这个门禁。
    """
    lines = source.splitlines()
    excluded: set[int] = set()
    index = 0
    while index < len(lines):
        if "pragma: no cover" in lines[index]:
            base_indent = len(lines[index]) - len(lines[index].lstrip())
            excluded.add(index + 1)
            following = index + 1
            while following < len(lines):
                raw = lines[following]
                if not raw.strip():
                    following += 1
                    continue
                indent = len(raw) - len(raw.lstrip())
                if indent <= base_indent:
                    break
                excluded.add(following + 1)
                following += 1
            index = following
            continue
        index += 1
    return excluded


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
        # Starlette 的 TestClient 在 anyio portal 线程里跑 handler：只设 sys.settrace
        # 会漏掉全部路由行，所以线程级也要设。
        threading.settrace(self._trace)

    def stop(self) -> None:
        threading.settrace(None)
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
                executable = _executable_lines(code) - _excluded_lines(source)
                executed = self.hits.get(str(path), set()) & executable
                exec_n, hit_n = len(executable), len(executed)
                total_exec += exec_n
                total_hit += hit_n
                files.append({
                    "file": path.name,
                    "executable": exec_n,
                    "hit": hit_n,
                    "percent": round(100.0 * hit_n / exec_n, 2) if exec_n else 100.0,
                    "missing": sorted(executable - executed)[:60],
                    # 合并多段覆盖率会话用（tests/metering/merge_coverage.py 取并集）
                    "hit_lines": sorted(executed),
                })
        percent = round(100.0 * total_hit / total_exec, 2) if total_exec else 100.0
        return {"files": files, "total_executable": total_exec, "total_hit": total_hit,
                "percent": percent}


def maybe_start() -> LineCoverage | None:
    """``M07_COVERAGE=1`` 时启动；返回实例供 conftest 在 session 结束时落盘。"""
    if os.environ.get("M07_COVERAGE") != "1":
        return None
    repo_root = pathlib.Path(__file__).resolve().parents[3]
    coverage = LineCoverage([repo_root / "app" / "reputation"])
    coverage.start()
    return coverage


def write_report(coverage: LineCoverage, path: str) -> dict[str, Any]:
    report = coverage.report()
    report["written_to"] = path
    pathlib.Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
    return report
