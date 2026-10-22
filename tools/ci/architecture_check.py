#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: no cross-module imports between app/<module>/ packages.

Legacy top-level modules (app/*.py) and app/admin, app/chain are transitional
and are not yet enforced; they are listed in the allowlist or treated as legacy.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "app"
IMPORT_RE = re.compile(r"^\s*(?:from\s+app\.([a-zA-Z0-9_]+)|import\s+app\.([a-zA-Z0-9_]+))")

MODULE_OF = {
    "identity": "M01",
    "supply": "M02",
    "gateway": "M03",
    "scheduling": "M04",
    "metering": "M05",
    "ledger": "M06",
    "reputation": "M07",
    "treasury": "M08",
    "recon": "M09",
    "config_center": "M10",
    "risk": "M11",
    "notify": "M12",
    "data_gov": "M14",
}

ALLOWLIST = Path(__file__).with_name("architecture_allowlist.txt")


def allowlisted() -> set[str]:
    if not ALLOWLIST.exists():
        return set()
    return {
        line.strip()
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def package_module(path: Path) -> str | None:
    rel = path.relative_to(APP)
    if len(rel.parts) < 2:
        return None
    top = rel.parts[0]
    return MODULE_OF.get(top)


def main() -> int:
    allowed = allowlisted()
    violations: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        own = package_module(path)
        if own is None:
            continue  # legacy top-level module or transitional package
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = IMPORT_RE.match(line)
            if not match:
                continue
            target = match.group(1) or match.group(2)
            target_module = MODULE_OF.get(target)
            if target_module is None or target_module == own:
                continue
            key = f"{path.relative_to(ROOT)}:{target}"
            if key in allowed:
                continue
            violations.append(f"{path.relative_to(ROOT)}:{lineno}: {own} imports {target} ({target_module})")

    if violations:
        print("FAIL: cross-module imports:")
        for item in violations:
            print(" -", item)
        print("Use the other module's public API or a contracts.* type; allowlist only with Lead approval.")
        return 1

    packages = sorted({p.name for p in APP.iterdir() if p.is_dir() and not p.name.startswith("__")})
    print(f"OK: no cross-module imports; package dirs: {', '.join(packages) or '(none yet)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
