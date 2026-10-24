#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate contracts/fixtures against the fixture schema and coverage rules."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts/fixtures"
SCHEMA = FIXTURES / "_schema.json"
MODULE_RE = re.compile(r"^M\d{2}$")
CASES = {"success", "error", "boundary"}


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL: {path.relative_to(ROOT)} is not valid JSON: {exc}")


def main() -> int:
    schema = load(SCHEMA)
    required = schema.get("required", [])
    errors: list[str] = []
    seen: dict[str, set[str]] = {}

    for module_dir in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        module = module_dir.name
        if not MODULE_RE.match(module):
            errors.append(f"{module}: directory name is not Mxx")
            continue
        seen[module] = set()
        for path in sorted(module_dir.glob("*.json")):
            doc = load(path)
            for key in required:
                if key not in doc:
                    errors.append(f"{path.relative_to(ROOT)}: missing {key}")
            if doc.get("module") != module:
                errors.append(f"{path.relative_to(ROOT)}: module mismatch")
            case = doc.get("case")
            if case not in CASES:
                errors.append(f"{path.relative_to(ROOT)}: bad case {case!r}")
            else:
                seen[module].add(case)
            if not isinstance(doc.get("input"), dict) or not isinstance(doc.get("expect"), dict):
                errors.append(f"{path.relative_to(ROOT)}: input/expect must be objects")
            if not str(doc.get("description", "")).strip():
                errors.append(f"{path.relative_to(ROOT)}: empty description")

    for module, cases in seen.items():
        missing = CASES - cases
        if missing:
            errors.append(f"{module}: missing fixture case(s) {sorted(missing)}")

    if errors:
        print("FAIL: fixtures check")
        for error in errors:
            print(" -", error)
        return 1

    total = sum(len(list((FIXTURES / m).glob("*.json"))) for m in seen)
    print(f"OK: {len(seen)} modules / {total} fixtures; each has success+error+boundary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
