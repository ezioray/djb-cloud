# SPDX-License-Identifier: Apache-2.0
"""M14 极简行覆盖率（stdlib 实现，零依赖；沿用 tests/risk、tests/recon 的做法）。

· 只统计 ``app/data_gov/*.py`` 与 ``app/admin/data_gov.py``（本模块代码）；
· 可执行行 = ``dis.findlinestarts`` 递归收集（不含空行 / 注释 / 文档字符串）；
· ``M14_COVERAGE=1`` 启用，``M14_COVERAGE_OUT=<path>`` 落 JSON；
· ``M14_COVERAGE_GATE=1`` 时低于 80% 直接让 pytest 退出码非 0（门禁）。

局限（写进证据）：这是**行覆盖率**，不是分支覆盖率。
"""
from __future__ import annotations

import dis
import json
import os
import pathlib
import sys
import threading
from types import CodeType
from typing import Any, Iterable

__all__ = ["LineCoverage", "maybe_start", "write_report", "THRESHOLD", "root_files"]

THRESHOLD = 80.0


def _executable_lines(code: CodeType) -> set[int]:
    lines: set[int] = set()
    for _, lineno in dis.findlinestarts(code):
        if lineno:
            lines.add(lineno)
    for const in code.co_consts:
        if isinstance(const, CodeType):
            lines |= _executable_lines(const)
    return lines


def root_files(repo_root: pathlib.Path) -> list[pathlib.Path]:
    files = sorted((repo_root / "app" / "data_gov").glob("*.py"))
    facade = repo_root / "app" / "admin" / "data_gov.py"
    if facade.exists():
        files.append(facade)
    return files


class LineCoverage:
    def __init__(self, files: Iterable[pathlib.Path]) -> None:
        self.files = [path.resolve() for path in files]
        self.prefixes = tuple(str(path) + os.sep for path in {path.parent for path in self.files})
        self.hits: dict[str, set[int]] = {}
        self._previous: Any = None
        self._previous_thread: Any = None

    def start(self) -> None:
        self._previous = sys.gettrace()
        self._previous_thread = threading.gettrace()
        sys.settrace(self._trace)
        threading.settrace(self._trace)

    def stop(self) -> None:
        sys.settrace(self._previous)
        threading.settrace(self._previous_thread)

    def _trace(self, frame: Any, event: str, arg: Any) -> Any:
        filename = frame.f_code.co_filename
        if not filename.startswith(self.prefixes):
            return None
        if event == "line":
            self.hits.setdefault(filename, set()).add(frame.f_lineno)
        return self._trace

    def report(self) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        total_exec = total_hit = 0
        for path in self.files:
            code = compile(path.read_text(encoding="utf-8"), str(path), "exec")
            executable = _executable_lines(code)
            executed = self.hits.get(str(path), set()) & executable
            exec_n, hit_n = len(executable), len(executed)
            total_exec += exec_n
            total_hit += hit_n
            entries.append({
                "file": str(path), "executable": exec_n, "hit": hit_n,
                "percent": round(100.0 * hit_n / exec_n, 2) if exec_n else 100.0,
                "missing": sorted(executable - executed)[:40],
            })
        percent = round(100.0 * total_hit / total_exec, 2) if total_exec else 100.0
        return {"files": entries, "total_executable": total_exec, "total_hit": total_hit,
                "percent": percent}


def maybe_start() -> LineCoverage | None:
    if os.environ.get("M14_COVERAGE") != "1":
        return None
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    coverage = LineCoverage(root_files(repo_root))
    coverage.start()
    return coverage


def write_report(coverage: LineCoverage, path: str) -> dict[str, Any]:
    report = coverage.report()
    report["written_to"] = path
    pathlib.Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
    return report
