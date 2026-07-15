"""K9x Satan — report formatter (text + JSON)."""

from typing import List
from k9x_satan.attacks.base_attack import AttackResult, AttackOutcome, PenetrationDepth

OUTCOME_ICON = {
    AttackOutcome.BLOCKED: "✓",
    AttackOutcome.FLAGGED: "✓",
    AttackOutcome.PASSED:  "✗",
}

DEPTH_COLOR = {
    PenetrationDepth.ROUTER:       "router",
    PenetrationDepth.ORCHESTRATOR: "orchestrator",
    PenetrationDepth.SQUAD:        "SQUAD  ← FINDING",
    PenetrationDepth.AGENT:        "AGENT  ← FINDING",
    PenetrationDepth.UNKNOWN:      "unknown",
}

BANNER = r"""
 ____     _     _____     _     _   _
/ ___|   / \   |_   _|   / \   | \ | |
\___ \  / _ \    | |    / _ \  |  \| |
 ___) |/ ___ \   | |   / ___ \ | |\  |
|____//_/   \_\  |_|  /_/   \_\|_| \_|

  Security Analysis Tool for Agentic Networks
  K9-AIF Red Team Harness — k9x.ai
"""


def print_report(results: List[AttackResult]) -> None:
    print(BANNER)
    print(f"{'Attack':<35} {'Outcome':<10} {'Depth':<25} {'Icon'}")
    print("─" * 78)

    for r in results:
        depth_label = DEPTH_COLOR.get(r.penetration_depth, str(r.penetration_depth))
        icon        = OUTCOME_ICON.get(r.outcome, "?")
        print(f"{r.attack_name:<35} {r.outcome.value:<10} {depth_label:<25} {icon}")
        if r.finding:
            print(f"  FINDING: {r.finding}")

    print("─" * 78)
    blocked  = sum(1 for r in results if r.shield_held)
    findings = sum(1 for r in results if not r.shield_held)
    print(f"\n{blocked}/{len(results)} attacks contained  |  {findings} finding(s)")
    if findings == 0:
        print("Shield held on all attack surfaces.")
    else:
        print("ACTION REQUIRED: review findings above and harden K9X Shield.")
    print()


def report_to_dict(r: AttackResult) -> dict:
    return {
        "attack":            r.attack_name,
        "surface":           r.surface.value,
        "outcome":           r.outcome.value,
        "penetration_depth": r.penetration_depth.value,
        "shield_held":       r.shield_held,
        "finding":           r.finding,
        "notes":             r.notes,
    }
