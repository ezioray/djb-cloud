#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Gate: migration file names are unique and live in the module's number segment."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations"
NAME_RE = re.compile(r"^(\d{3,4})_[a-z0-9_]+\.sql$")

SEGMENTS = {
    "legacy": (1, 99),
    "M01": (100, 199),
    "M02": (200, 299),
    "M03": (300, 399),
    "M04": (400, 499),
    "M05": (500, 599),
    "M06": (600, 699),
    "M07": (700, 799),
    "M08": (800, 899),
    "M09": (900, 999),
    "M10": (1000, 1099),
    "M11": (1100, 1199),
    "M12": (1200, 1299),
    "M13": (1300, 1399),
    "M14": (1300, 1399),
    "M15": (1300, 1399),
    "M16": (1400, 1499),
}


def segment_of(number: int) -> str | None:
    for name, (low, high) in SEGMENTS.items():
        if low <= number <= high:
            return name
    return None


def main() -> int:
    files = sorted(MIGRATIONS.glob("*.sql"))
    if not files:
        print("FAIL: no migrations found", file=sys.stderr)
        return 1

    seen: dict[int, str] = {}
    errors: list[str] = []
    for path in files:
        match = NAME_RE.match(path.name)
        if not match:
            errors.append(f"{path.name}: expected NNN_name.sql")
            continue
        number = int(match.group(1))
        if number in seen:
            errors.append(f"{path.name}: duplicate number {number} (also {seen[number]})")
        seen[number] = path.name
        if segment_of(number) is None:
            errors.append(f"{path.name}: number {number} outside module segments 1-1499")

    if errors:
        print("FAIL: migration check")
        for error in errors:
            print(" -", error)
        return 1

    counts: dict[str, int] = {}
    for number in seen:
        seg = segment_of(number) or "?"
        counts[seg] = counts.get(seg, 0) + 1
    summary = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
    print(f"OK: {len(seen)} migrations; unique numbers; segments {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
