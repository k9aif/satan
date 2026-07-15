"""
K9x Satan — DocumentProcessingSquad SBB

Extends BaseSquad. Owns DocumentExtractionAgent + AuditAgent
and defines the execution flow between them.
"""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_squad.base_squad import BaseSquad
from k9x_satan.target.agents import DocumentExtractionAgent, AuditAgent


class DocumentProcessingSquad(BaseSquad):
    """SBB: Coordinates document extraction and audit agents."""

    def __init__(self, config=None):
        super().__init__(
            squad_id="DocumentProcessingSquad",
            agents=[DocumentExtractionAgent(config=config or {}), AuditAgent(config=config or {})],
        )
        self.description = "Extract and audit a document payload."
        self.flow = [
            {"agent": "DocumentExtractionAgent", "result_key": "DocumentExtractionAgent"},
            {"agent": "AuditAgent",              "result_key": "AuditAgent"},
        ]
