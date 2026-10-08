# SPDX-License-Identifier: Apache-2.0
"""Run the frozen corpus through the k9x_satan pipeline in one configuration
(PROTOCOL.md section 3) and record each document's outcome.

  python run_eval.py --config F|P|G --run 1 [--only SUBSTR] [--limit N]

F = pattern checks + Guardian (as shipped); P = pattern checks, Guardian off
(agent governance = Shield profile); G = Guardian only (pattern chains emptied).
Resumable: documents already in the output file are skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"          # --corpus corpus_heldout for the after-fix row (deviation 5)
RESULTS = HERE / "results"
ECOSYSTEM = Path(os.environ.get("K9X_ECOSYSTEM", HERE.parents[2]))   # the folder holding k9x_satan
sys.path.insert(0, str(ECOSYSTEM))

MODEL = "qwen3.8:27b"


def configure(cfg: dict, which: str) -> dict:
    """Deployment model throughout (think off); provider per configuration."""
    for m in cfg["inference"]["llm_factory"]["models"].values():
        m["model"] = MODEL
        m["think"] = False
    cfg["governance"]["provider"] = "shield" if which == "P" else "guardian"
    cfg["k9_env"] = "production"
    return cfg


def empty_pattern_chains():
    """Configuration G: the Router's ingress and the Orchestrator's egress
    chains run no checks (Guardian, at Router pre-governance and in the
    agents, is untouched)."""
    from k9_aif_abb.k9_security.vulnerability.vulnerability_chain import VulnerabilityChain
    from k9x_satan.target.orchestrator import DocumentOrchestrator
    from k9x_satan.target.router import DocumentRouter
    DocumentRouter._build_ingress_chain = lambda self: VulnerabilityChain()
    DocumentOrchestrator._build_egress_chain = lambda self: VulnerabilityChain()


def production_profile():
    """The deployed profile (DAS, framework examples): PIIBoundaryCheck flags
    personal data at egress instead of blocking it. k9x_satan's red-team
    pipeline blocks on it (block_on_match: True), which stops every claim that
    carries an address ZIP code (PROTOCOL deviation 1). Every other check and
    its setting is unchanged."""
    from k9_aif_abb.k9_security.vulnerability.checks.pii_boundary_check import PIIBoundaryCheck
    from k9x_satan.target.orchestrator import DocumentOrchestrator
    built = DocumentOrchestrator._build_egress_chain

    def egress(self):
        chain = built(self)
        for check in chain._checks:
            if isinstance(check, PIIBoundaryCheck):
                check._block = False
        return chain
    DocumentOrchestrator._build_egress_chain = egress


def flags(checks) -> list:
    out = []
    for c in checks or []:
        if isinstance(c, dict) and str(c.get("status", "")).upper() == "FLAG":   # router/orchestrator _serialize_chain
            out.append(c.get("name"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", choices=["F", "P", "G"], required=True)
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--profile", choices=["production", "strict"], default="production",
                    help="production = PII flag-only at egress (deployed); strict = k9x_satan as shipped")
    ap.add_argument("--corpus", default="corpus", help="corpus directory (default: the frozen corpus)")
    ap.add_argument("--tag", default="", help="suffix for the results file, e.g. heldout_fix")
    ap.add_argument("--only")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--subset", action="store_true",
                    help="every 4th document of each kind (52) -- run-to-run variation runs (deviation 4)")
    args = ap.parse_args()

    os.environ["K9_ENV"] = "production"
    if not os.environ.get("OLLAMA_BASE_URL"):
        sys.exit("set OLLAMA_BASE_URL to the Ollama server (e.g. http://localhost:11434)")
    os.environ["SATAN_LLM_MODEL"] = MODEL
    from k9x_satan.target.pipeline import load_config, run_pipeline
    if args.config == "G":
        empty_pattern_chains()
    elif args.profile == "production":
        production_profile()
    cfg = configure(load_config(), args.config)

    corpus = HERE / args.corpus
    manifest = json.loads((corpus / "manifest.json").read_text())
    docs = [("attack", n, m) for n, m in manifest["attacks"].items()] + \
           [("benign", n, m) for n, m in manifest["benign"].items()]
    if args.subset:
        docs = [d for i, d in enumerate([x for x in docs if x[0] == "attack"]) if i % 4 == 0] + \
               [d for i, d in enumerate([x for x in docs if x[0] == "benign"]) if i % 4 == 0]
    if args.only:
        docs = [d for d in docs if args.only in d[1]]
    if args.limit:
        docs = docs[: args.limit]

    RESULTS.mkdir(exist_ok=True)
    tag = ("" if args.profile == "production" else "_strict") + (f"_{args.tag}" if args.tag else "")
    out_path = RESULTS / f"{args.config}{tag}_run{args.run}{'_' + args.only if args.only else ''}.jsonl"
    done = set()
    if out_path.exists():
        done = {json.loads(l)["document"] for l in out_path.read_text().splitlines() if l.strip()}

    with out_path.open("a") as out:
        for kind, name, meta in docs:
            if name in done:
                continue
            text = (corpus / ("attacks" if kind == "attack" else "benign") / name).read_text()
            payload = {"event_type": "document_received", "document_text": text,
                       "correlation_id": f"v2-{args.config}-r{args.run}-{name}"}
            t0 = time.monotonic()
            try:
                res = run_pipeline(dict(payload), config=cfg)
                err = None
            except Exception as exc:                      # recorded, never dropped
                res, err = {"status": "error"}, f"{type(exc).__name__}: {str(exc)[:300]}"
            rec = {
                "document": name, "kind": kind, **meta,
                "config": args.config, "profile": args.profile, "run": args.run,
                **({"corpus": args.corpus, "tag": args.tag} if args.tag else {}),
                "status": res.get("status"), "blocked_at": res.get("blocked_at"),
                "blocked_by": res.get("blocked_by"), "check_message": (res.get("check_message") or "")[:300],
                "ingress_flags": flags(res.get("ingress_checks")), "egress_flags": flags(res.get("egress_checks")),
                "reached_agents": res.get("status") == "completed" or res.get("blocked_at") == "orchestrator",
                "error": err, "elapsed_s": round(time.monotonic() - t0, 1),
            }
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"{args.config} r{args.run} {kind:6} {name[:46]:46} {rec['status']:9} "
                  f"{(rec['blocked_by'] or ''):24} {rec['elapsed_s']}s", flush=True)


if __name__ == "__main__":
    main()
