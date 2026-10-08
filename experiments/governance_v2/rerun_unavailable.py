# SPDX-License-Identifier: Apache-2.0
"""Deviation 6: a Guardian-unavailable block (fail-closed) is an infrastructure failure, not a
verdict. Move those records to results/<file>.unavailable.jsonl (archived, reported) and drop them
from the run file, so `run_eval.py` (resumable) re-runs exactly those documents on the same code.

  python rerun_unavailable.py      (then: run_eval.py --config F|G --run N for each file listed)
"""

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"

for f in sorted(RESULTS.glob("*_run[0-9].jsonl")):
    rows = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
    bad = [r for r in rows if "unavailable" in (r.get("check_message") or "").lower()]
    if not bad:
        continue
    with (RESULTS / (f.stem + ".unavailable.jsonl")).open("a") as a:
        for r in bad:
            a.write(json.dumps(r) + "\n")
    f.write_text("".join(json.dumps(r) + "\n" for r in rows if r not in bad))
    print(f.name, len(bad))
