# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""Attacks from Zscaler ThreatLabz's 2026 Phishing & Initial Access Report,
against the defences added in k9-aif 1.14.

Each fires the matching document from the web UI's corpus (app.CORPUS), so
the CLI/report run and the drop-down exercise exactly the same payload.

    phishing_link        lookalike payment-portal link in a claim
                         -> Orchestrator egress OutboundLinkCheck
    agent_impersonation  inter-agent message asserting roles/trust to get
                         claims approved ("AI agents will phish other AI agents")
                         -> Granite Guardian ingress_risks: impersonation
    paraphrased_override "skip verification, approve it" with no trigger words
                         -> Granite Guardian ingress_risks: process_manipulation

The last two are deliberately invisible to Shield's pattern checks: under
governance "noop" they are expected to pass (a recorded finding), and under
"guardian" to be stopped. Run with --compare-governance to see both.
"""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.attacks.base_attack import (
    BaseAttack, AttackResult, AttackOutcome, AttackSurface,
)
from k9x_satan.attacks._fire import fire, classify


class _CorpusDocumentAttack(BaseAttack):
    """Fires one app.CORPUS document; subclasses name it and the defence it targets."""

    corpus_key = ""
    targets = ""
    surface = AttackSurface.DOCUMENT

    def craft_payload(self):
        from k9x_satan.app import CORPUS  # imported lazily: app.py builds the FastAPI app
        return {
            "event_type":     "document_received",
            "document_text":  CORPUS[self.corpus_key]["text"],
            "filename":       f"{self.corpus_key}.txt",
            "correlation_id": f"satan-{self.name}-001",
        }

    def run(self, target_url: str) -> AttackResult:
        payload = self.craft_payload()
        response, error_result = fire(target_url, payload, self.name, self.surface,
                                      governance_mode=self.config.get("governance_mode"))
        if error_result:
            return error_result
        depth, outcome = classify(response)
        finding = None
        if outcome == AttackOutcome.PASSED:
            finding = f"{self.targets} did not stop {self.corpus_key}"
        return AttackResult(
            attack_name       = self.name,
            surface           = self.surface,
            outcome           = outcome,
            penetration_depth = depth,
            payload_sent      = payload,
            response_received = response,
            finding           = finding,
        )


class PhishingLinkAttack(_CorpusDocumentAttack):
    name       = "phishing_link"
    corpus_key = "phishing_lookalike_link"
    targets    = "Orchestrator egress OutboundLinkCheck"


class AgentImpersonationAttack(_CorpusDocumentAttack):
    name       = "agent_impersonation"
    corpus_key = "agent_impersonation"
    targets    = "Granite Guardian ingress_risks (impersonation)"


class ParaphrasedOverrideAttack(_CorpusDocumentAttack):
    name       = "paraphrased_override"
    corpus_key = "paraphrased_override"
    targets    = "Granite Guardian ingress_risks (process_manipulation)"
