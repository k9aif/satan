#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""
repent.py — K9X Satan Easter Egg

Inspired by the original repent.pl shipped with SATAN (1995) by Dan Farmer
and Wietse Venema. Running it renames SATAN to SANTA throughout the UI
and switches the header to green — because SANTA is friendly.

The original SATAN included this script for system administrators who were
uncomfortable with the name. K9X Satan includes it for the same reason.

Usage:
    python repent.py          # SATAN → SANTA (repent)
    python repent.py --undo   # SANTA → SATAN (relapse)
"""

import sys
import os

_DIR = os.path.dirname(os.path.abspath(__file__))

TARGETS = [
    os.path.join(_DIR, "webui", "index.html"),
]
# app.py and run.sh used to be rewritten too, purely decorative (the visible
# effect only ever came from index.html). Rewriting a running app's own
# source caused two real bugs: locally, uvicorn --reload saw app.py change
# mid-request and killed the connection before the response finished;
# in production, the container runs as non-root and can't write to those
# root-owned files at all. Neither app.py nor run.sh needs to change for
# the SATAN -> SANTA effect to work.

REPENT = [
    ("K9X Satan",  "K9X Santa"),
    ("K9x Satan",  "K9x Santa"),
    ("k9x Satan",  "k9x Santa"),
    ("SATAN",      "SANTA"),
    ("Satan",      "Santa"),
    # Acronym expansion — S·A·T·A·N → S·A·N·T·A
    (
        "Security &nbsp;\xb7&nbsp; Analysis &nbsp;\xb7&nbsp; Tool &nbsp;for&nbsp; Agentic &nbsp;\xb7&nbsp; Networks",
        "Security &nbsp;\xb7&nbsp; Analysis &nbsp;\xb7&nbsp; Networks &nbsp;\xb7&nbsp; Testing &nbsp;\xb7&nbsp; Agentic",
    ),
]

RELAPSE = [(b, a) for a, b in REPENT]

# Body class toggle — switches header to green when repented
_BODY_SATAN = "<body>"
_BODY_SANTA = '<body class="santa-mode">'


def _is_repented() -> bool:
    html = os.path.join(_DIR, "webui", "index.html")
    if not os.path.exists(html):
        return False
    with open(html, encoding="utf-8") as f:
        return _BODY_SANTA in f.read()


def transform(path: str, pairs: list, dry_run: bool = False) -> int:
    with open(path, encoding="utf-8") as f:
        original = f.read()

    result = original
    for src, dst in pairs:
        result = result.replace(src, dst)

    changes = sum(original.count(src) for src, _ in pairs)

    if changes and not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(result)

    return changes


def toggle_body_class(undo: bool, dry_run: bool = False) -> bool:
    html = os.path.join(_DIR, "webui", "index.html")
    if not os.path.exists(html):
        return False

    with open(html, encoding="utf-8") as f:
        content = f.read()

    if undo:
        changed = _BODY_SANTA in content
        result  = content.replace(_BODY_SANTA, _BODY_SATAN)
    else:
        changed = _BODY_SATAN in content
        result  = content.replace(_BODY_SATAN, _BODY_SANTA)

    if changed and not dry_run:
        with open(html, "w", encoding="utf-8") as f:
            f.write(result)

    return changed


def run(undo: bool = False, dry_run: bool = False) -> dict:
    """Run repent (or undo). Returns dict suitable for JSON API response."""
    pairs  = RELAPSE if undo else REPENT
    detail = []
    total  = 0

    for path in TARGETS:
        if not os.path.exists(path):
            detail.append({"file": os.path.basename(path), "changes": 0, "skipped": True})
            continue
        n = transform(path, pairs, dry_run=dry_run)
        detail.append({"file": os.path.basename(path), "changes": n})
        total += n

    # Body class handles the green/red color switch
    toggle_body_class(undo, dry_run=dry_run)

    if undo:
        msg = "Relapsed. SATAN is back. No judgement."
    else:
        msg = "Repented. K9X Santa wishes you a safe and compliant holiday season. 🎅"

    return {"repented": not undo, "changes": total, "message": msg, "detail": detail}


def main():
    undo = "--undo" in sys.argv

    print()
    print(f"  K9X {'Santa' if not undo else 'Satan'} — repent.py")
    print(f"  {'SATAN → SANTA (repenting…)' if not undo else 'SANTA → SATAN (relapsing…)'}")
    print()

    result = run(undo=undo)

    for item in result["detail"]:
        label = "–" if item.get("skipped") else ("✓" if item["changes"] else "–")
        print(f"  {label}  {item['file']}  ({item['changes']} substitutions)")

    print()
    print(f"  {result['message']}")
    print()


if __name__ == "__main__":
    main()
