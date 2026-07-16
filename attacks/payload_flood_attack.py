"""PayloadFloodAttack — oversized payload to exhaust the LLM token budget."""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import (
    BaseAttack, AttackResult, AttackOutcome, AttackSurface,
)
from k9x_satan.attacks._fire import fire, classify


class PayloadFloodAttack(BaseAttack):
    """
    Sends an oversized document_text to trip the per-payload character limit.
    Targets: Router ingress InputSizeCheck.
    """

    name    = "payload_flood"
    surface = AttackSurface.PAYLOAD

    def craft_payload(self):
        size = int(self.config.get("flood_chars", 40_000))
        return {
            "event_type":     "document_received",
            "document_text":  "A" * size,
            "filename":       "flood.txt",
            "correlation_id": "satan-flood-001",
        }

    def run(self, target_url: str) -> AttackResult:
        payload = self.craft_payload()
        response, error_result = fire(target_url, payload, self.name, self.surface, governance_mode=self.config.get("governance_mode"))
        if error_result:
            return error_result

        depth, outcome = classify(response)
        finding = None
        if outcome == AttackOutcome.PASSED:
            finding = "InputSizeCheck missed an oversized payload"

        return AttackResult(
            attack_name       = self.name,
            surface           = self.surface,
            outcome           = outcome,
            penetration_depth = depth,
            payload_sent      = {**payload, "document_text": f"<{len(payload['document_text'])} chars omitted>"},
            response_received = response,
            finding           = finding,
        )
