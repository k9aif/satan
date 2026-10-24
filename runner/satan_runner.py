# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""
K9x Satan — main runner.

Usage:
  python -m k9x_satan.runner.satan_runner                       # the sample application on localhost:6660
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000 --attack prompt_injection_document
  python -m k9x_satan.runner.satan_runner --profile targets/my_app.yaml --suite full --report json

A target profile (docs/target-profiles.md) describes any running application:
where to send attacks, how to shape the request, how to read the answer.
--target <url> is the sample application's profile at that URL.
"""

import argparse
import json
import os
import sys
from typing import List, Union

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import AttackOutcome, AttackResult
from k9x_satan.attacks._target import TargetProfile, TargetProfileError
from k9x_satan.runner.attack_registry import ATTACK_REGISTRY
from k9x_satan.report.satan_report import print_report, print_comparison_report, report_to_dict


def _note_undelivered(target, result: AttackResult) -> None:
    """Say so when the target never received the fields this attack's control inspects."""
    if not isinstance(target, TargetProfile):
        return
    missing = target.undelivered(result.payload_sent or {})
    if missing:
        note = (f"Not sent to this target: {', '.join(missing)} (its profile does not map them), "
                f"so the control that inspects them was not tested; only the attack text was.")
        result.notes = f"{result.notes} {note}".strip() if result.notes else note


def run_suite(target: Union[str, TargetProfile], attack_names: List[str], config: dict) -> List[AttackResult]:
    results = []
    for name in attack_names:
        cls = ATTACK_REGISTRY.get(name)
        if not cls:
            print(f"[WARN] Unknown attack: {name} — skipping")
            continue
        print(f"  → Running: {name}")
        attack = cls(config=config)
        result = attack.run(target)
        _note_undelivered(target, result)
        results.append(result)
    return results


def run_suite_compare(target: Union[str, TargetProfile], attack_names: List[str], config: dict):
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
        deterministic = cls(config={**config, "governance_mode": "noop"}).run(target)

        print(f"  → Running: {name}  (deterministic + Guardian)")
        with_guardian = cls(config={**config, "governance_mode": "guardian"}).run(target)

        rows.append((name, deterministic, with_guardian))
    return rows


def main():
    parser = argparse.ArgumentParser(description="K9x Satan — adversarial test runner")
    parser.add_argument("--target", default=None,   help="URL of a running Satan sample application "
                                                         "(default: the sample at http://localhost:6660)")
    parser.add_argument("--profile", default=None,  help="Target profile YAML describing any running "
                                                         "application (see targets/, docs/target-profiles.md)")
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

    try:
        if args.profile:
            target = TargetProfile.load(args.profile, base_url=args.target)
        else:
            target = TargetProfile.sample(base_url=args.target)
        target.check()
    except (TargetProfileError, OSError) as exc:
        parser.error(str(exc))
    if args.compare_governance and not target.supports_governance_override:
        parser.error(f"--compare-governance needs a target that honours _governance_override "
                     f"(response.supports_governance_override: true); {target.name} does not")

    config = {"fake_search_url": args.fake_search_url}

    if args.attack:
        attack_names = [args.attack]
    elif args.suite == "ingress":
        # Router ingress chain: RequestFrequencyCheck, InputSizeCheck,
        # PromptInjectionCheck, FieldAnomalyCheck, MemoryPoisoningCheck,
        # ToolArgumentCheck, ToolAuthorizationCheck
        attack_names = ["prompt_injection_document", "search_poisoning", "payload_flood",
                         "memory_poisoning", "request_flood",
                         "tool_argument_poison", "shadow_tool",
                         "agent_impersonation", "paraphrased_override"]
    elif args.suite == "egress":
        # Orchestrator egress chain: SemanticDriftCheck, ExecutionGuardCheck,
        # PIIBoundaryCheck, HardcodedCredentialCheck, SystemPromptLeakageCheck,
        # OutputSanitizationCheck
        attack_names = ["semantic_drift", "execution_bypass", "pii_exfiltration",
                         "hardcoded_credential",
                         "system_prompt_leakage", "output_sanitization",
                         "phishing_link"]
    else:
        attack_names = list(ATTACK_REGISTRY.keys())

    print(f"\nK9x Satan — Security Analysis Tool for Agentic Networks")
    print(f"Target  : {target.name}  ({target.url})")
    print(f"Suite   : {args.suite}  ({len(attack_names)} attacks)")
    if args.compare_governance:
        print("Mode    : deterministic-only vs. deterministic + Guardian (comparison)")
    print(f"{'─' * 55}")

    if args.compare_governance:
        rows = run_suite_compare(target, attack_names, config)
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

    results = run_suite(target, attack_names, config)

    if args.report == "json":
        print(json.dumps([report_to_dict(r) for r in results], indent=2))
    else:
        print_report(results)

    findings = [r for r in results if r.outcome == AttackOutcome.PASSED]
    inconclusive = [r for r in results if r.outcome == AttackOutcome.FLAGGED]
    sys.exit(1 if findings else 2 if inconclusive else 0)


if __name__ == "__main__":
    main()
