#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate contracts/facts.yaml from the vendored contracts/03-facts.md.

03-facts.md is the human-readable source; facts.yaml is the machine-readable
projection consumed by module code and tests. CI regenerates the YAML and
compares it byte-for-byte with the committed file (see tools/ci/facts_check.py).

Usage:
    python3 tools/gen_facts.py            # write contracts/facts.yaml
    python3 tools/gen_facts.py --check    # fail if committed file is stale
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts/03-facts.md"
TARGET = ROOT / "contracts/facts.yaml"

SECTION_RE = re.compile(r"^##\s+(\d+)\s+(.+?)（Owner：([^）]+)）\s*$")
ROW_RE = re.compile(r"^\|(.+)\|\s*$")


def parse(source: Path) -> dict:
    lines = source.read_text(encoding="utf-8").splitlines()
    sections: list[dict] = []
    current: dict | None = None
    for line in lines:
        m = SECTION_RE.match(line.strip())
        if m:
            current = {
                "id": int(m.group(1)),
                "title": m.group(2).strip(),
                "owner": m.group(3).strip(),
                "facts": [],
            }
            sections.append(current)
            continue
        if current is None:
            continue
        row = ROW_RE.match(line.strip())
        if not row:
            if line.strip().startswith("## "):
                current = None
            continue
        cells = [c.strip() for c in row.group(1).split("|")]
        if not cells or cells[0] in ("常量", "---") or set(cells[0]) <= {"-"}:
            continue
        key = cells[0]
        value = cells[1] if len(cells) > 1 else ""
        note = cells[2] if len(cells) > 2 else ""
        if not key or not value:
            continue
        current["facts"].append({"key": key, "value": value, "note": note})

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    doc = {
        "version": 1,
        "generated_from": str(SOURCE.relative_to(ROOT)),
        "source_sha256": digest,
        "rule": "机器源；由 tools/gen_facts.py 从 03-facts.md 生成，禁止手改。",
        "sections": sections,
    }
    return doc


def render(doc: dict) -> str:
    header = (
        "# DJB S1 facts（机器源，禁止手改）\n"
        "# 生成：python3 tools/gen_facts.py；校验：python3 tools/gen_facts.py --check\n"
        "# 人工源：product/v4/modules/03-facts.md\n"
    )
    return header + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=120)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    doc = parse(SOURCE)
    out = render(doc)
    if args.check:
        if not TARGET.exists():
            print(f"FAIL: {TARGET.relative_to(ROOT)} missing; run tools/gen_facts.py", file=sys.stderr)
            return 1
        current = TARGET.read_text(encoding="utf-8")
        if current != out:
            print("FAIL: contracts/facts.yaml is stale vs 03-facts.md", file=sys.stderr)
            return 1
        print(f"OK: facts.yaml matches {doc['generated_from']} ({len(doc['sections'])} sections)")
        return 0

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(out, encoding="utf-8")
    total = sum(len(s["facts"]) for s in doc["sections"])
    print(f"wrote {TARGET.relative_to(ROOT)}: {len(doc['sections'])} sections / {total} facts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
