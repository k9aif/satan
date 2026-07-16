"""
K9x Satan — DocumentOrchestrator SBB

Extends BaseOrchestrator. Owns DocumentProcessingSquad and applies
the egress Shield (SemanticDriftCheck + ExecutionGuardCheck) after
squad execution.
"""

import logging
import os
import sys
from typing import Any, Dict

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_core.orchestration.base_orchestrator import BaseOrchestrator
from k9_aif_abb.k9_security.vulnerability.vulnerability_chain import VulnerabilityChain
from k9_aif_abb.k9_security.vulnerability.checks.semantic_drift_check import SemanticDriftCheck
from k9_aif_abb.k9_security.vulnerability.checks.execution_guard_check import ExecutionGuardCheck
from k9_aif_abb.k9_security.vulnerability.checks.pii_boundary_check import PIIBoundaryCheck
from k9_aif_abb.k9_security.vulnerability.checks.tool_argument_check import ToolArgumentCheck
from k9_aif_abb.k9_security.vulnerability.checks.hardcoded_credential_check import HardcodedCredentialCheck
from k9x_satan.target.squad import DocumentProcessingSquad
from k9x_satan.target.tool_authorization_check import ToolAuthorizationCheck
from k9x_satan.target.system_prompt_leakage_check import SystemPromptLeakageCheck
from k9x_satan.target.output_sanitization_check import OutputSanitizationCheck


def _find_governance_block(squad_output: Dict[str, Any]) -> str:
    """Return the first governance-block finding among agent results, or ''."""
    for value in squad_output.values():
        if isinstance(value, dict) and value.get("status") == "blocked_by_governance":
            return value.get("guardian_finding", "blocked by governance")
    return ""


def _serialize_chain(chain_result) -> list:
    return [
        {
            "name":     r.check_name,
            "status":   r.status.value,
            "message":  r.message,
            "severity": getattr(r, "severity", "info"),
        }
        for r in chain_result.results
    ]

log = logging.getLogger("k9x_satan.target")


class DocumentOrchestrator(BaseOrchestrator):
    """
    SBB: Orchestrates document processing with egress Shield gate.

    Flow:
      1. Execute DocumentProcessingSquad
      2. Run egress VulnerabilityChain on combined payload
      3. Return result — blocked or completed
    """

    layer = "Satan.Target DocumentOrchestrator SBB"

    def __init__(self, config: Dict[str, Any] = None, **kwargs):
        super().__init__(config=config or {}, **kwargs)
        self._squad = DocumentProcessingSquad(config=self.config)

    def _build_egress_chain(self) -> VulnerabilityChain:
        pii_config = {**self.config, "block_on_match": True}
        return (
            VulnerabilityChain()
            .add(SemanticDriftCheck(self.config))
            .add(ExecutionGuardCheck(self.config))
            .add(PIIBoundaryCheck(pii_config))
            .add(ToolArgumentCheck(self.config))
            .add(HardcodedCredentialCheck(self.config))
            .add(ToolAuthorizationCheck(self.config))
            .add(SystemPromptLeakageCheck(self.config))
            .add(OutputSanitizationCheck(self.config))
        )

    def execute_flow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        log.info("[DocumentOrchestrator] executing squad")
        agents_reached = []

        try:
            squad_results = self.execute_squads([self._squad], payload)
            agents_reached = ["DocumentExtractionAgent", "AuditAgent"]
            squad_output   = squad_results.get("DocumentProcessingSquad", {})
        except Exception as exc:
            log.error("[DocumentOrchestrator] squad failed: %s", exc)
            squad_output = {"status": "squad_error", "error": str(exc)}

        # An agent may have short-circuited itself via governance (Guardian/
        # ShieldGovernance pre_process BLOCK) before ever calling the LLM.
        # That's containment, not a pass-through — report it as blocked rather
        # than letting it fall through to the egress chain, which only sees
        # {"status": "blocked_by_governance", ...} stub dicts that trip
        # nothing and would otherwise get reported as "completed".
        governance_finding = _find_governance_block(squad_output)
        if governance_finding:
            log.warning("[DocumentOrchestrator] BLOCKED by governance — %s", governance_finding)
            return {
                "status":            "blocked",
                "blocked_at":        "agent",
                "blocked_by":        "GovernanceBlock",
                "check_message":     governance_finding,
                "penetration_depth": "agent",
                "squad_reached":     True,
                "agents_reached":    agents_reached,
                "shield_held":       True,
                "egress_checks":     [],
            }

        log.info("[DocumentOrchestrator] running egress Shield checks")
        egress_chain  = self._build_egress_chain()
        egress_result = egress_chain.run({**payload, **squad_output})

        egress_checks = _serialize_chain(egress_result)

        if egress_result.blocked:
            log.warning("[DocumentOrchestrator] BLOCKED by %s", egress_result.blocked_by)
            blocked_check = next((r for r in egress_result.results if r.blocked), None)
            return {
                "status":            "blocked",
                "blocked_at":        "orchestrator",
                "blocked_by":        egress_result.blocked_by,
                "check_message":     blocked_check.message if blocked_check else "",
                "check_excerpt":     (blocked_check.metadata or {}).get("excerpt", "") if blocked_check else "",
                "penetration_depth": "orchestrator",
                "squad_reached":     True,
                "agents_reached":    agents_reached,
                "shield_held":       True,
                "egress_checks":     egress_checks,
            }

        log.info("[DocumentOrchestrator] pipeline complete — no threats at egress")
        depth = "agent" if agents_reached else "orchestrator"
        return {
            "status":            "completed",
            "penetration_depth": depth,
            "squad_reached":     True,
            "agents_reached":    agents_reached,
            "squad_result":      squad_output,
            "shield_held":       False,
            "egress_checks":     egress_checks,
        }
