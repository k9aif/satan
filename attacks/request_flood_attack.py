"""RequestFloodAttack — resource-exhaustion via high request volume within one session."""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import (
    BaseAttack, AttackResult, AttackOutcome, AttackSurface,
)
from k9x_satan.attacks._fire import fire, classify


class RequestFloodAttack(BaseAttack):
    """
    Fires many identical, individually-benign requests against the same
    session in rapid succession — each one alone passes every content check;
    only the request budget catches the pattern.
    Targets: Router ingress RequestFrequencyCheck.
    """

    name    = "request_flood"
    surface = AttackSurface.PAYLOAD

    def craft_payload(self):
        session_id = self.config.get("session_id", "satan-flood-rate-001")
        return {
            "event_type":     "document_received",
            "document_text":  "Routine status check.",
            "session_id":     session_id,
            "correlation_id": session_id,
        }

    def run(self, target_url: str) -> AttackResult:
        payload = self.craft_payload()
        request_count = int(self.config.get("flood_requests", 25))

        response = None
        for _ in range(request_count):
            response, error_result = fire(target_url, payload, self.name, self.surface, governance_mode=self.config.get("governance_mode"))
            if error_result:
                return error_result

        depth, outcome = classify(response)
        finding = None
        if outcome == AttackOutcome.PASSED:
            finding = "RequestFrequencyCheck missed a resource-exhaustion request flood"

        return AttackResult(
            attack_name       = self.name,
            surface           = self.surface,
            outcome           = outcome,
            penetration_depth = depth,
            payload_sent      = payload,
            response_received = response,
            finding           = finding,
            notes             = f"Fired {request_count} requests against session '{payload['session_id']}' within the rate window.",
        )
