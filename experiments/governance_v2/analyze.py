# SPDX-License-Identifier: Apache-2.0
"""Turn results/*.jsonl into the numbers PROTOCOL.md section 5 defines.

  python analyze.py            -> results/summary.json + results/SUMMARY.md
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 3), round(min(1.0, c + h), 3))


def rate(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 3) if n else None, "ci95": [lo, hi]}


def load():
    runs = defaultdict(list)          # (config, profile, run) -> records
    for f in sorted(RESULTS.glob("*.jsonl")):
        if "_run0" in f.name:
            continue                  # trial runs are not measurements
        if f.name.endswith(".unavailable.jsonl"):
            continue                  # deviation 6: availability events, neither detection nor false positive
        for line in f.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                profile = r.get("profile", "production") + (f"_{r['tag']}" if r.get("tag") else "")
                runs[(r["config"], profile, r["run"])].append(r)
    return runs


def summarize(recs):
    att = [r for r in recs if r["kind"] == "attack"]
    ben = [r for r in recs if r["kind"] == "benign"]
    blocked = lambda r: r["status"] == "blocked"
    out = {
        "documents": len(recs),
        "errors": sum(1 for r in recs if r["status"] == "error"),
        "detection": rate(sum(map(blocked, att)), len(att)),
        "detected_before_agents": rate(sum(1 for r in att if blocked(r) and not r["reached_agents"]), len(att)),
        "false_positive": rate(sum(map(blocked, ben)), len(ben)),
        "benign_flagged_not_blocked": rate(
            sum(1 for r in ben if not blocked(r) and (r["ingress_flags"] or r["egress_flags"])), len(ben)),
        "per_class": {}, "per_wording": {}, "blocking_check": {}, "false_positive_check": {},
        "mean_seconds": {"attack": round(sum(r["elapsed_s"] for r in att) / max(1, len(att)), 1),
                         "benign": round(sum(r["elapsed_s"] for r in ben) / max(1, len(ben)), 1)},
    }
    by = defaultdict(list)
    for r in att:
        by[("class", r["class"])].append(r)
        by[("wording", r["wording"])].append(r)
    for (kind, key), rs in sorted(by.items()):
        out["per_class" if kind == "class" else "per_wording"][key] = rate(sum(map(blocked, rs)), len(rs))
    out["blocking_check"] = dict(Counter(r["blocked_by"] for r in att if blocked(r)).most_common())
    out["false_positive_check"] = dict(Counter(r["blocked_by"] for r in ben if blocked(r)).most_common())
    out["false_positive_documents"] = sorted(r["document"] for r in ben if blocked(r))
    out["missed_attacks"] = sorted(r["document"] for r in att if not blocked(r))
    return out


def run_variation(runs, config, profile):
    reps = sorted(k for k in runs if k[0] == config and k[1] == profile)
    if len(reps) < 2:
        return None
    outcome = [{r["document"]: r["status"] == "blocked" for r in runs[k]} for k in reps]
    docs = set.intersection(*(set(o) for o in outcome))
    differ = sorted(d for d in docs if len({o[d] for o in outcome}) > 1)
    return {"runs": len(reps), "documents_compared": len(docs), "documents_differing": len(differ),
            "differing": differ}


def pct(x):
    return "—" if x["rate"] is None else f"{x['rate'] * 100:.1f}% [{x['ci95'][0] * 100:.1f}, {x['ci95'][1] * 100:.1f}] ({x['k']}/{x['n']})"


def main():
    runs = load()
    summary = {f"{c}_{p}_run{r}": summarize(recs) for (c, p, r), recs in sorted(runs.items())}
    summary["variation_F_production"] = run_variation(runs, "F", "production")
    # Strict profile (PII blocks at egress), derived from F run 1 (PROTOCOL deviation 4):
    # blocked in production, or flagged by PIIBoundaryCheck at egress.
    f1 = runs.get(("F", "production", 1))
    if f1:
        strict = [dict(r, status="blocked", blocked_by="PIIBoundaryCheck")
                  if r["status"] == "completed" and "PIIBoundaryCheck" in (r["egress_flags"] or []) else r
                  for r in f1]
        summary["F_strict_run1_derived"] = summarize(strict)
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=1))
    lines = ["# Governance evaluation v2: summary", "",
             "| Run | Detection | Stopped before agents | False positives | Benign flagged only |",
             "|---|---|---|---|---|"]
    for key, s in summary.items():
        if key.startswith("variation") or s is None:
            continue
        lines.append(f"| {key} | {pct(s['detection'])} | {pct(s['detected_before_agents'])} | "
                     f"{pct(s['false_positive'])} | {pct(s['benign_flagged_not_blocked'])} |")
    v = summary.get("variation_F_production")
    if v:
        lines += ["", f"F, production, {v['runs']} runs: {v['documents_differing']} of {v['documents_compared']} "
                      f"documents changed outcome between runs."]
    (RESULTS / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
