"""
K9x Satan — main runner.

Usage:
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000 --attack prompt_injection_document
  python -m k9x_satan.runner.satan_runner --target http://localhost:8000 --suite full --report json
"""

import argparse
import json
import sys
from typing import List

from k9x_satan.attacks.base_attack import AttackOutcome, AttackResult
from k9x_satan.runner.attack_registry import ATTACK_REGISTRY
from k9x_satan.report.satan_report import print_report, report_to_dict


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
    args = parser.parse_args()

    config = {"fake_search_url": args.fake_search_url}

    if args.attack:
        attack_names = [args.attack]
    elif args.suite == "ingress":
        attack_names = ["prompt_injection_document", "payload_flood"]
    elif args.suite == "egress":
        attack_names = ["search_poisoning", "pii_exfiltration", "semantic_drift", "tool_argument_poison"]
    else:
        attack_names = list(ATTACK_REGISTRY.keys())

    print(f"\nK9x Satan — Security Analysis Tool for Agentic Networks")
    print(f"Target  : {args.target}")
    print(f"Suite   : {args.suite}  ({len(attack_names)} attacks)")
    print(f"{'─' * 55}")

    results = run_suite(args.target, attack_names, config)

    if args.report == "json":
        print(json.dumps([report_to_dict(r) for r in results], indent=2))
    else:
        print_report(results)

    findings = [r for r in results if r.outcome == AttackOutcome.PASSED]
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
