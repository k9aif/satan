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


def _make_governance(config: dict):
    """Return the configured governance instance, or None for NoopGovernance default."""
    provider = config.get("governance", {}).get("provider", "noop")
    if provider == "guardian":
        from k9x_satan.target.guardian_governance import GuardianGovernance
        return GuardianGovernance(config=config)
    return None  # BaseAgent.require_governance → NoopGovernance (dev env)


class DocumentProcessingSquad(BaseSquad):
    """SBB: Coordinates document extraction and audit agents."""

    def __init__(self, config=None):
        cfg = config or {}
        gov = _make_governance(cfg)
        super().__init__(
            squad_id="DocumentProcessingSquad",
            agents=[
                DocumentExtractionAgent(config=cfg, governance=gov),
                AuditAgent(config=cfg, governance=gov),
            ],
        )
        self.description = "Extract and audit a document payload."
        self.flow = [
            {"agent": "DocumentExtractionAgent", "result_key": "DocumentExtractionAgent"},
            {"agent": "AuditAgent",              "result_key": "AuditAgent"},
        ]
