"""
K9x Satan — Target Pipeline Entry Point

Thin wiring layer: loads config, instantiates the SBB hierarchy and fires
the payload through it.

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

import yaml

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9x_satan.target.router import DocumentRouter
from k9x_satan.target.orchestrator import DocumentOrchestrator

log = logging.getLogger("k9x_satan.target")

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")


def load_config() -> dict:
    try:
        with open(_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        # env var wins over config file for k9_env
        cfg["k9_env"] = os.environ.get("K9_ENV", cfg.get("k9_env", "development"))
        return cfg
    except FileNotFoundError:
        log.warning("[Pipeline] config.yaml not found — using defaults")
        return {"k9_env": os.environ.get("K9_ENV", "development")}


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
    cfg = config or load_config()

    orchestrator = DocumentOrchestrator(config=cfg)
    router       = DocumentRouter(config=cfg)
    router.register_orchestrator("document_processing", orchestrator)

    log.info("[Pipeline] firing payload through Satan target pipeline (k9_env=%s)", cfg.get("k9_env"))
    return router.route(payload)
