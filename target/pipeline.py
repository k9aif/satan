"""
K9x Satan — Target Pipeline

A minimal but real K9-AIF implementation that Satan attacks.
Shield is wired at both gates:
  - Router   (ingress): PromptInjectionCheck + InputSizeCheck
  - Orchestrator (egress): SemanticDriftCheck + ExecutionGuardCheck

Agents are stub implementations (no LLM) — the test is about Shield, not inference.
"""

import logging
import sys
import os

# Bootstrap — use shared venv from k9-aif-framework
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.vulnerability_chain import VulnerabilityChain
from k9_aif_abb.k9_security.vulnerability.checks.prompt_injection_check import PromptInjectionCheck
from k9_aif_abb.k9_security.vulnerability.checks.input_size_check import InputSizeCheck
from k9_aif_abb.k9_security.vulnerability.checks.semantic_drift_check import SemanticDriftCheck
from k9_aif_abb.k9_security.vulnerability.checks.execution_guard_check import ExecutionGuardCheck
from k9_aif_abb.k9_squad.base_squad import BaseSquad
from k9_aif_abb.k9_core.agent.base_agent import BaseAgent

log = logging.getLogger("k9x_satan.target")


# ── Stub agents — no LLM needed, test is about Shield ──────────────────────

class DocumentExtractionAgent(BaseAgent):
    """Agent 1: extracts structured content from document text."""
    layer = "Satan.Target DocumentExtractionAgent"

    def execute(self, payload):
        text = payload.get("document_text", "")
        log.info("[DocumentExtractionAgent] processing %d chars", len(text))
        return {
            "agent":     "DocumentExtractionAgent",
            "extracted": text[:200],
            "char_count": len(text),
            "status":    "extracted",
        }


class AuditAgent(BaseAgent):
    """Agent 2: audits the extraction result."""
    layer = "Satan.Target AuditAgent"

    def execute(self, payload):
        extracted = payload.get("DocumentExtractionAgent", {})
        log.info("[AuditAgent] auditing extraction result")
        return {
            "agent":        "AuditAgent",
            "audit_status": "clean",
            "chars_reviewed": extracted.get("char_count", 0),
            "status":       "audited",
        }


# ── Shield chains ────────────────────────────────────────────────────────────

def _build_ingress_chain() -> VulnerabilityChain:
    """Router ingress gate — first line of defence."""
    return (
        VulnerabilityChain()
        .add(InputSizeCheck())
        .add(PromptInjectionCheck())
    )


def _build_egress_chain() -> VulnerabilityChain:
    """Orchestrator egress gate — second line of defence."""
    return (
        VulnerabilityChain()
        .add(SemanticDriftCheck())
        .add(ExecutionGuardCheck())
    )


# ── Pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(payload: dict) -> dict:
    """
    Full Router → Orchestrator → Squad → Agent pipeline.
    Returns a result dict that always includes:
      - status:            blocked | flagged | completed
      - blocked_at:        router | orchestrator | (absent if not blocked)
      - blocked_by:        check name that blocked
      - penetration_depth: router | orchestrator | squad | agent
      - squad_reached:     bool
      - agents_reached:    list of agent names that executed
    """
    ingress = _build_ingress_chain()
    egress  = _build_egress_chain()

    # ── ROUTER — ingress gate ────────────────────────────────────────────────
    log.info("[Router] running ingress Shield checks")
    ingress_result = ingress.run(payload)

    if ingress_result.blocked:
        log.warning("[Router] BLOCKED by %s", ingress_result.blocked_by)
        return {
            "status":            "blocked",
            "blocked_at":        "router",
            "blocked_by":        ingress_result.blocked_by,
            "penetration_depth": "router",
            "squad_reached":     False,
            "agents_reached":    [],
            "shield_held":       True,
        }

    flagged_by = [r.check_name for r in ingress_result.results if r.status.value == "flag"]
    if flagged_by:
        log.info("[Router] FLAGGED by %s — continuing with caution", flagged_by)

    # ── ORCHESTRATOR → SQUAD → AGENTS ────────────────────────────────────────
    log.info("[Orchestrator] passing to squad")

    squad = BaseSquad(
        squad_id="DocumentProcessingSquad",
        agents=[DocumentExtractionAgent(), AuditAgent()],
    )
    squad.flow = [
        {"agent": "DocumentExtractionAgent", "result_key": "DocumentExtractionAgent"},
        {"agent": "AuditAgent",              "result_key": "AuditAgent"},
    ]

    agents_reached = []
    try:
        squad_result = squad.execute(payload)
        agents_reached = ["DocumentExtractionAgent", "AuditAgent"]
    except Exception as exc:
        log.error("[Squad] failed: %s", exc)
        squad_result = {"status": "squad_error", "error": str(exc)}

    # ── ORCHESTRATOR — egress gate ───────────────────────────────────────────
    log.info("[Orchestrator] running egress Shield checks")
    egress_payload = {**payload, **squad_result}
    egress_result  = egress.run(egress_payload)

    if egress_result.blocked:
        log.warning("[Orchestrator] BLOCKED by %s", egress_result.blocked_by)
        return {
            "status":            "blocked",
            "blocked_at":        "orchestrator",
            "blocked_by":        egress_result.blocked_by,
            "penetration_depth": "orchestrator",
            "squad_reached":     True,
            "agents_reached":    agents_reached,
            "shield_held":       True,
        }

    log.info("[Orchestrator] pipeline complete — no threats detected")
    return {
        "status":            "completed",
        "penetration_depth": "agent",
        "squad_reached":     True,
        "agents_reached":    agents_reached,
        "squad_result":      squad_result,
        "shield_held":       False,
        "flagged_by":        flagged_by,
    }
