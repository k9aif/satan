"""
K9x Satan — DocumentRouter SBB

Extends BaseRouter. Applies the ingress Shield (InputSizeCheck +
PromptInjectionCheck) then delegates to the registered DocumentOrchestrator.
"""

import logging
import os
import sys
from typing import Any, Dict

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_core.router.base_router import BaseRouter
from k9_aif_abb.k9_security.vulnerability.vulnerability_chain import VulnerabilityChain
from k9_aif_abb.k9_security.vulnerability.checks.input_size_check import InputSizeCheck
from k9_aif_abb.k9_security.vulnerability.checks.prompt_injection_check import PromptInjectionCheck

log = logging.getLogger("k9x_satan.target")


class DocumentRouter(BaseRouter):
    """
    SBB: Single entry point for the Satan target pipeline.

    Ingress gate runs InputSizeCheck then PromptInjectionCheck.
    Blocked payloads never reach the Orchestrator.
    Clean payloads are forwarded to the registered 'document_processing' orchestrator.
    """

    layer = "Satan.Target DocumentRouter SBB"

    def _build_ingress_chain(self) -> VulnerabilityChain:
        return (
            VulnerabilityChain()
            .add(InputSizeCheck())
            .add(PromptInjectionCheck())
        )

    def route(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        log.info("[DocumentRouter] running ingress Shield checks")
        ingress        = self._build_ingress_chain()
        ingress_result = ingress.run(payload)

        if ingress_result.blocked:
            log.warning("[DocumentRouter] BLOCKED by %s", ingress_result.blocked_by)
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
            log.info("[DocumentRouter] FLAGGED by %s — forwarding with caution", flagged_by)

        orchestrator = self.registry.get("document_processing")
        if orchestrator is None:
            raise RuntimeError("[DocumentRouter] No orchestrator registered for 'document_processing'")

        log.info("[DocumentRouter] forwarding to DocumentOrchestrator")
        return orchestrator.execute_flow(payload)
