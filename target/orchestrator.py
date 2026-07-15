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
from k9x_satan.target.squad import DocumentProcessingSquad

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
        return (
            VulnerabilityChain()
            .add(SemanticDriftCheck())
            .add(ExecutionGuardCheck())
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

        log.info("[DocumentOrchestrator] running egress Shield checks")
        egress_chain  = self._build_egress_chain()
        egress_result = egress_chain.run({**payload, **squad_output})

        if egress_result.blocked:
            log.warning("[DocumentOrchestrator] BLOCKED by %s", egress_result.blocked_by)
            return {
                "status":            "blocked",
                "blocked_at":        "orchestrator",
                "blocked_by":        egress_result.blocked_by,
                "penetration_depth": "orchestrator",
                "squad_reached":     True,
                "agents_reached":    agents_reached,
                "shield_held":       True,
            }

        log.info("[DocumentOrchestrator] pipeline complete — no threats at egress")
        return {
            "status":            "completed",
            "penetration_depth": "agent",
            "squad_reached":     True,
            "agents_reached":    agents_reached,
            "squad_result":      squad_output,
            "shield_held":       False,
        }
