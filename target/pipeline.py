"""
K9x Satan — Target Pipeline Entry Point

Thin wiring layer: instantiates the SBB hierarchy and fires the payload
through it.  All real logic lives in the SBBs below.

Hierarchy:
  DocumentRouter (BaseRouter)
    └── DocumentOrchestrator (BaseOrchestrator)
          └── DocumentProcessingSquad (BaseSquad)
                ├── DocumentExtractionAgent (BaseAgent)
                └── AuditAgent (BaseAgent)
"""

import logging
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9x_satan.target.router import DocumentRouter
from k9x_satan.target.orchestrator import DocumentOrchestrator

log = logging.getLogger("k9x_satan.target")


def run_pipeline(payload: dict, config: dict = None) -> dict:
    """
    Wire the K9-AIF SBB hierarchy and run the payload through it.

    Returns a result dict always containing:
      status            blocked | completed
      blocked_at        router | orchestrator (if blocked)
      blocked_by        check name (if blocked)
      penetration_depth router | orchestrator | agent
      squad_reached     bool
      agents_reached    list[str]
      shield_held       bool
    """
    cfg          = config or {}
    orchestrator = DocumentOrchestrator(config=cfg)
    router       = DocumentRouter(config=cfg)
    router.register_orchestrator("document_processing", orchestrator)

    log.info("[Pipeline] firing payload through Satan target pipeline")
    return router.route(payload)
