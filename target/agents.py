"""
K9x Satan — Target Agent SBBs

Stub agents that extend BaseAgent. No LLM — the test is about Shield,
not inference. Real SBBs would call llm_invoke here.
"""

import logging
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_core.agent.base_agent import BaseAgent

log = logging.getLogger("k9x_satan.target")


class DocumentExtractionAgent(BaseAgent):
    """SBB: Extracts structured content from document text."""

    layer = "Satan.Target DocumentExtractionAgent SBB"

    def execute(self, payload: dict) -> dict:
        text = payload.get("document_text", "")
        log.info("[DocumentExtractionAgent] processing %d chars", len(text))
        return {
            "agent":      "DocumentExtractionAgent",
            "extracted":  text[:200],
            "char_count": len(text),
            "status":     "extracted",
        }


class AuditAgent(BaseAgent):
    """SBB: Audits the extraction result for completeness and integrity."""

    layer = "Satan.Target AuditAgent SBB"

    def execute(self, payload: dict) -> dict:
        extracted = payload.get("DocumentExtractionAgent", {})
        log.info("[AuditAgent] auditing extraction result")
        return {
            "agent":          "AuditAgent",
            "audit_status":   "clean",
            "chars_reviewed": extracted.get("char_count", 0),
            "status":         "audited",
        }
