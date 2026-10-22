#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: every emitted event name must be registered in 02-events.md §3.

Convention: modules emit events through a helper call or an explicit
``event_type=`` assignment, e.g.::

    emit_event("usage.recorded", payload)
    outbox.append(event_type="journal.posted", payload=...)

Only literals in those positions are treated as event names, so config keys
and permission strings are not misclassified.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVENTS_DOC = ROOT / "contracts/02-events.md"
APP = ROOT / "app"
ALLOWLIST = Path(__file__).with_name("event_allowlist.txt")

EVENT_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
EMIT_RE = re.compile(
    r"(?:emit_event|emit|publish_event|append_event|event_type)\s*(?:\(\s*|=\s*)['\"]([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)['\"]"
)


def registered_events() -> set[str]:
    text = EVENTS_DOC.read_text(encoding="utf-8")
    in_catalog = False
    events: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## 3 "):
            in_catalog = True
            continue
        if in_catalog and line.startswith("## "):
            break
        if not in_catalog or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0] in ("事件", "---"):
            continue
        for name in cells[0].split("/"):
            name = name.strip()
            if EVENT_RE.match(name):
                events.add(name)
    return events


def allowlisted() -> set[str]:
    if not ALLOWLIST.exists():
        return set()
    return {
        line.strip()
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def main() -> int:
    events = registered_events()
    if not events:
        print("FAIL: no events parsed from contracts/02-events.md §3", file=sys.stderr)
        return 1
    allowed = allowlisted()
    unknown: list[str] = []
    emitted = 0
    for path in sorted(APP.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for name in EMIT_RE.findall(line):
                emitted += 1
                if name not in events and name not in allowed:
                    unknown.append(f"{path.relative_to(ROOT)}:{lineno}: {name}")
    if unknown:
        print("FAIL: unregistered event emission(s):")
        for item in unknown:
            print(" -", item)
        print("Register in contracts/02-events.md §3, or add a temporary allowlist entry.")
        return 1
    print(f"OK: {len(events)} registered events; {emitted} emission site(s); none unregistered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
