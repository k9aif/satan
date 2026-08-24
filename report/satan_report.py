# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""K9x Satan — report formatter (text + JSON)."""

import os
import sys
from typing import List, Tuple

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import AttackResult, AttackOutcome, PenetrationDepth

OUTCOME_ICON = {
    AttackOutcome.BLOCKED: "✓",
    AttackOutcome.FLAGGED: "✓",
    AttackOutcome.PASSED:  "✗",
}

DEPTH_COLOR = {
    # AGENT depth no longer implies a finding — governance (Guardian/
    # ShieldGovernance) can contain an attack at the agent boundary, so depth
    # and outcome are independent. The Outcome column is the source of truth;
    # this is a location label only.
    PenetrationDepth.ROUTER:       "router",
    PenetrationDepth.ORCHESTRATOR: "orchestrator",
    PenetrationDepth.SQUAD:        "squad",
    PenetrationDepth.AGENT:        "agent",
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


def print_comparison_report(rows: List[Tuple[str, AttackResult, AttackResult]]) -> None:
    """
    Print deterministic-only vs. deterministic+Guardian side by side.

    "Guardian added" is true only when the deterministic-only run PASSED
    (Shield missed it) and adding Guardian turned that into BLOCKED/FLAGGED.
    A "REGRESSION" marker means Guardian made a previously-contained attack
    pass — that should never happen and is a bug in Guardian's wiring, not a
    finding about the attack.
    """
    print(BANNER)
    print("Deterministic checks (K9X Shield) vs. Deterministic + IBM Guardian\n")
    print(f"{'Attack':<28} {'Deterministic':<14} {'+ Guardian':<14} {'Guardian added?'}")
    print("─" * 78)

    guardian_added = 0
    regressions    = 0

    for name, det, grd in rows:
        det_ok = det.outcome != AttackOutcome.PASSED
        grd_ok = grd.outcome != AttackOutcome.PASSED

        if not det_ok and grd_ok:
            verdict = "YES — closed a gap"
            guardian_added += 1
        elif det_ok and not grd_ok:
            verdict = "⚠ REGRESSION"
            regressions += 1
        elif det_ok and grd_ok:
            verdict = "— already held"
        else:
            verdict = "✗ still a finding"

        print(f"{name:<28} {det.outcome.value:<14} {grd.outcome.value:<14} {verdict}")
        if det.finding:
            print(f"  deterministic-only finding: {det.finding}")
        if grd.finding:
            print(f"  +guardian finding:          {grd.finding}")

    print("─" * 78)
    print(f"\nGuardian closed {guardian_added}/{len(rows)} gap(s) that deterministic checks alone missed.")
    if regressions:
        print(f"⚠ {regressions} REGRESSION(S) — Guardian made a previously-contained attack pass. Investigate immediately.")
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
