"""
K9x Satan — benign-corpus runner.

Fires every benign document in app.CORPUS (evil=False) through the same
pipeline satan_runner.py fires attacks at, N times each, and reports the
false-positive rate: how often a clean document gets blocked or flagged
by a check that exists to catch malicious ones.

Calls run_pipeline() directly rather than going over HTTP — no need to
stand up the FastAPI app or fake_search server for this, since none of
the benign documents exercise the search-poisoning path.

Usage:
  python -m k9x_satan.runner.benign_runner
  python -m k9x_satan.runner.benign_runner --runs 5
  python -m k9x_satan.runner.benign_runner --runs 5 --report json
"""

import argparse
import json
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9x_satan.app import CORPUS
from k9x_satan.target.pipeline import run_pipeline, load_config


def run_benign_suite(runs: int, config: dict) -> list:
    benign_keys = [k for k, v in CORPUS.items() if not v["evil"]]
    results = []
    for run_idx in range(1, runs + 1):
        for key in benign_keys:
            payload = {
                "event_type":     "document_received",
                "document_text":  CORPUS[key]["text"],
                "correlation_id": f"satan-benign-run{run_idx}-{key}",
            }
            result = run_pipeline(dict(payload), config=config)
            false_positive = result["status"] != "completed"
            results.append({
                "run":             run_idx,
                "corpus_key":      key,
                "label":           CORPUS[key]["label"],
                "status":          result["status"],
                "blocked_at":      result.get("blocked_at"),
                "blocked_by":      result.get("blocked_by"),
                "false_positive":  false_positive,
            })
            marker = "FALSE POSITIVE" if false_positive else "ok"
            print(f"[run {run_idx}] {key:24s} status={result['status']:10s} "
                  f"blocked_by={result.get('blocked_by') or '-':24s} {marker}")
    return results


def main():
    parser = argparse.ArgumentParser(description="K9x Satan — benign-corpus false-positive runner")
    parser.add_argument("--runs", type=int, default=5, help="Number of passes over the benign corpus (default: 5)")
    parser.add_argument("--report", default="text", choices=["text", "json"])
    args = parser.parse_args()

    config = load_config()
    results = run_benign_suite(args.runs, config)

    total = len(results)
    fps = sum(1 for r in results if r["false_positive"])

    if args.report == "json":
        print(json.dumps({"total_trials": total, "false_positives": fps, "results": results}, indent=2))
    else:
        print()
        print(f"Benign corpus: {len(set(r['corpus_key'] for r in results))} documents x {args.runs} runs "
              f"= {total} trials")
        print(f"False positives: {fps}/{total} ({100 * fps / total:.1f}%)")
        if fps:
            print("Details:")
            for r in results:
                if r["false_positive"]:
                    print(f"  - run {r['run']}: {r['corpus_key']} blocked_by={r['blocked_by']}")


if __name__ == "__main__":
    main()
