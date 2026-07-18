"""
K9x Satan — DocumentRouter

Extends BaseRouter. Applies the 7-check ingress Shield (RequestFrequencyCheck,
InputSizeCheck, PromptInjectionCheck, FieldAnomalyCheck, MemoryPoisoningCheck,
ToolArgumentCheck, ToolAuthorizationCheck) then delegates to the registered
DocumentOrchestrator. All seven are now framework OOB checks
(k9_aif_abb.k9_security.vulnerability.checks) except FieldAnomalyCheck, which
stays Satan-local — its pattern set is tuned to this project's own
insurance-claim test corpus and was deliberately not promoted into the
framework (see the K9-AIF security review's Gap Analysis, G8).
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
from k9_aif_abb.k9_security.vulnerability.checks.tool_argument_check import ToolArgumentCheck
from k9_aif_abb.k9_security.vulnerability.checks.memory_poisoning_check import MemoryPoisoningCheck
from k9_aif_abb.k9_security.vulnerability.checks.request_frequency_check import RequestFrequencyCheck
from k9_aif_abb.k9_security.vulnerability.checks.tool_authorization_check import ToolAuthorizationCheck
from k9x_satan.target.field_anomaly_check import FieldAnomalyCheck
from k9x_satan.target._check_config import security_check_config

log = logging.getLogger("k9x_satan.target")


class DocumentRouter(BaseRouter):
    """
    Single entry point for the Satan target pipeline.

    Ingress gate runs InputSizeCheck then PromptInjectionCheck.
    Blocked payloads never reach the Orchestrator.
    Clean payloads are forwarded to the registered 'document_processing' orchestrator.
    """

    layer = "Satan.Target DocumentRouter"

    def _build_ingress_chain(self) -> VulnerabilityChain:
        sec_cfg = security_check_config(self.config)
        return (
            VulnerabilityChain()
            .add(RequestFrequencyCheck(sec_cfg))
            .add(InputSizeCheck(self.config))
            .add(PromptInjectionCheck(self.config))
            .add(FieldAnomalyCheck(self.config))
            .add(MemoryPoisoningCheck(sec_cfg))
            # ToolArgumentCheck/ToolAuthorizationCheck inspect the tool_name /
            # tool_arguments / *_backend fields a caller supplies up front —
            # nothing about them depends on the Squad/Agent having run. Both
            # checks' own docstrings say "before execution" / "before a tool
            # call is dispatched" — that only means something if they gate
            # ingress. Wiring them at Orchestrator egress (pre-move) let a
            # poisoned tool call reach Squad/Agent before ever being caught.
            .add(ToolArgumentCheck(self.config))
            .add(ToolAuthorizationCheck(sec_cfg))
        )

    def route(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        log.info("[DocumentRouter] running ingress Shield checks")
        ingress        = self._build_ingress_chain()
        ingress_result = ingress.run(payload)

        ingress_checks = _serialize_chain(ingress_result)

        if ingress_result.blocked:
            log.warning("[DocumentRouter] BLOCKED by %s", ingress_result.blocked_by)
            blocked_check = next((r for r in ingress_result.results if r.blocked), None)
            return {
                "status":            "blocked",
                "blocked_at":        "router",
                "blocked_by":        ingress_result.blocked_by,
                "check_message":     blocked_check.message if blocked_check else "",
                "check_excerpt":     (blocked_check.metadata or {}).get("excerpt", "") if blocked_check else "",
                "penetration_depth": "router",
                "squad_reached":     False,
                "agents_reached":    [],
                "shield_held":       True,
                "ingress_checks":    ingress_checks,
                "egress_checks":     [],
            }

        flagged_by = [r.check_name for r in ingress_result.results if r.status.value == "flag"]
        if flagged_by:
            log.info("[DocumentRouter] FLAGGED by %s — forwarding with caution", flagged_by)

        orchestrator = self.registry.get("document_processing")
        if orchestrator is None:
            raise RuntimeError("[DocumentRouter] No orchestrator registered for 'document_processing'")

        log.info("[DocumentRouter] forwarding to DocumentOrchestrator")
        result = orchestrator.execute_flow(payload)
        result["ingress_checks"] = ingress_checks
        return result


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
