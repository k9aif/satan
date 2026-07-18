"""
K9x Satan — main runner.

Usage:
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000 --attack prompt_injection_document
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000 --suite full --report json
"""

import argparse
import json
import os
import sys
from typing import List

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import AttackOutcome, AttackResult
from k9x_satan.runner.attack_registry import ATTACK_REGISTRY
from k9x_satan.report.satan_report import print_report, print_comparison_report, report_to_dict


def run_suite(target_url: str, attack_names: List[str], config: dict) -> List[AttackResult]:
    results = []
    for name in attack_names:
        cls = ATTACK_REGISTRY.get(name)
        if not cls:
            print(f"[WARN] Unknown attack: {name} — skipping")
            continue
        print(f"  → Running: {name}")
        attack = cls(config=config)
        result = attack.run(target_url)
        results.append(result)
    return results


def run_suite_compare(target_url: str, attack_names: List[str], config: dict):
    """
    Run each attack twice: once with governance_mode="noop" (K9X Shield's
    deterministic VulnerabilityChain checks only) and once with
    governance_mode="guardian" (Shield + IBM Guardian's semantic layer).

    Shows exactly what Guardian adds on top of the deterministic checks —
    Shield alone is the baseline; Guardian should only ever add coverage on
    the attacks Shield's pattern matching missed, never take coverage away.
    """
    rows = []
    for name in attack_names:
        cls = ATTACK_REGISTRY.get(name)
        if not cls:
            print(f"[WARN] Unknown attack: {name} — skipping")
            continue

        print(f"  → Running: {name}  (deterministic only)")
        deterministic = cls(config={**config, "governance_mode": "noop"}).run(target_url)

        print(f"  → Running: {name}  (deterministic + Guardian)")
        with_guardian = cls(config={**config, "governance_mode": "guardian"}).run(target_url)

        rows.append((name, deterministic, with_guardian))
    return rows


def main():
    parser = argparse.ArgumentParser(description="K9x Satan — adversarial test runner")
    parser.add_argument("--target", required=True,  help="Target K9-AIF pipeline URL")
    parser.add_argument("--attack", default=None,   help="Single attack name to run")
    parser.add_argument("--suite",  default="full", choices=["full", "ingress", "egress"],
                        help="Attack suite to run (default: full)")
    parser.add_argument("--report", default="text", choices=["text", "json"],
                        help="Output format (default: text)")
    parser.add_argument("--fake-search-url", default="http://localhost:9999",
                        help="URL of the fake search server")
    parser.add_argument("--compare-governance", action="store_true",
                        help="Run each attack twice — deterministic checks only vs. "
                             "deterministic + IBM Guardian — to show what Guardian adds")
    args = parser.parse_args()

    config = {"fake_search_url": args.fake_search_url}

    if args.attack:
        attack_names = [args.attack]
    elif args.suite == "ingress":
        # Router ingress chain: RequestFrequencyCheck, InputSizeCheck,
        # PromptInjectionCheck, FieldAnomalyCheck, MemoryPoisoningCheck,
        # ToolArgumentCheck, ToolAuthorizationCheck
        attack_names = ["prompt_injection_document", "search_poisoning", "payload_flood",
                         "memory_poisoning", "request_flood",
                         "tool_argument_poison", "shadow_tool"]
    elif args.suite == "egress":
        # Orchestrator egress chain: SemanticDriftCheck, ExecutionGuardCheck,
        # PIIBoundaryCheck, HardcodedCredentialCheck, SystemPromptLeakageCheck,
        # OutputSanitizationCheck
        attack_names = ["semantic_drift", "execution_bypass", "pii_exfiltration",
                         "hardcoded_credential",
                         "system_prompt_leakage", "output_sanitization"]
    else:
        attack_names = list(ATTACK_REGISTRY.keys())

    print(f"\nK9x Satan — Security Analysis Tool for Agentic Networks")
    print(f"Target  : {args.target}")
    print(f"Suite   : {args.suite}  ({len(attack_names)} attacks)")
    if args.compare_governance:
        print("Mode    : deterministic-only vs. deterministic + Guardian (comparison)")
    print(f"{'─' * 55}")

    if args.compare_governance:
        rows = run_suite_compare(args.target, attack_names, config)
        if args.report == "json":
            print(json.dumps(
                [{"attack": name,
                  "deterministic_only":       report_to_dict(det),
                  "deterministic_plus_guardian": report_to_dict(grd)}
                 for name, det, grd in rows],
                indent=2,
            ))
        else:
            print_comparison_report(rows)
        findings = [name for name, det, grd in rows
                    if det.outcome == AttackOutcome.PASSED and grd.outcome == AttackOutcome.PASSED]
        sys.exit(1 if findings else 0)

    results = run_suite(args.target, attack_names, config)

    if args.report == "json":
        print(json.dumps([report_to_dict(r) for r in results], indent=2))
    else:
        print_report(results)

    findings = [r for r in results if r.outcome == AttackOutcome.PASSED]
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
