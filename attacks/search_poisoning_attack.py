# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""SearchPoisoningAttack — fetches a poisoned result from the fake search server
and feeds it into the target pipeline as tool-response content."""

import os
import sys
import requests

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import (
    BaseAttack, AttackResult, AttackOutcome, AttackSurface, PenetrationDepth
)
from k9x_satan.attacks._fire import fire, classify


class SearchPoisoningAttack(BaseAttack):
    """
    Fires a real HTTP request against the fake_search server (fake_search/server.py),
    retrieves its poisoned scenario snippet, and feeds that snippet into the target
    pipeline exactly as a poisoned tool response would land in a real deployment.

    Targets: Router ingress PromptInjectionCheck. The chain scans whatever text
    lands in document_text regardless of whether it came from a document upload
    or a tool response — this attack proves that path holds for tool-response
    content too, not just uploaded documents.
    """

    name    = "search_poisoning"
    surface = AttackSurface.SEARCH

    def craft_payload(self):
        fake_search_url = self.config.get("fake_search_url", "http://localhost:9999")
        scenario = self.config.get("search_scenario", "prompt_injection")

        try:
            requests.post(f"{fake_search_url}/corpus/{scenario}", timeout=10)
            resp = requests.post(
                f"{fake_search_url}/search",
                json={"query": "K9-AIF policy update July 2026"},
                timeout=10,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            poisoned_text = "\n\n".join(r.get("snippet", "") for r in results)
            fetch_error = None
        except Exception as exc:
            poisoned_text = ""
            fetch_error = str(exc)

        return {
            "event_type":     "document_received",
            "document_text":  poisoned_text,
            "filename":       "search_tool_response.txt",
            "claim_id":       "SATAN-SP-001",
            "correlation_id": "satan-sp-001",
            "_fetch_error":   fetch_error,
        }

    def run(self, target_url: str) -> AttackResult:
        payload = self.craft_payload()
        fetch_error = payload.pop("_fetch_error", None)

        if fetch_error or not payload["document_text"]:
            return AttackResult(
                attack_name       = self.name,
                surface           = self.surface,
                outcome           = AttackOutcome.FLAGGED,
                penetration_depth = PenetrationDepth.UNKNOWN,
                payload_sent      = payload,
                response_received = {"error": fetch_error or "fake_search returned no results"},
                notes             = "fake_search unreachable or empty — attack not fired, not a verified result",
            )

        response, error_result = fire(target_url, payload, self.name, self.surface, governance_mode=self.config.get("governance_mode"))
        if error_result:
            return error_result

        depth, outcome = classify(response)
        finding = None
        if outcome == AttackOutcome.PASSED:
            finding = "PromptInjectionCheck missed injected instructions in search tool response"

        return AttackResult(
            attack_name       = self.name,
            surface           = self.surface,
            outcome           = outcome,
            penetration_depth = depth,
            payload_sent      = payload,
            response_received = response,
            finding           = finding,
        )
