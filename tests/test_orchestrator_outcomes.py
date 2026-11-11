# SPDX-License-Identifier: Apache-2.0
"""A governance block raised inside an agent is reported as blocked at the agent; any other squad failure is an
error. Neither may be reported as completed (governance evaluation accounting, k9x_satan 1.0.4)."""
import os

import pytest

os.environ.setdefault("K9_ENV", "development")
from k9x_satan.target.orchestrator import DocumentOrchestrator  # noqa: E402


def _run_with_squad_raising(exc, monkeypatch):
    orch = DocumentOrchestrator(config={})
    monkeypatch.setattr(orch, "execute_squads", lambda *a, **k: (_ for _ in ()).throw(exc))
    return orch.execute_flow({"document_text": "Claim form. Description: hail damage."})


def test_agent_governance_block_is_blocked_not_completed(monkeypatch):
    out = _run_with_squad_raising(PermissionError("Granite Guardian blocked ingress: guardian score=yes"), monkeypatch)
    assert out["status"] == "blocked" and out["blocked_at"] == "agent" and out["blocked_by"] == "GovernanceBlock"
    assert "guardian score=yes" in out["check_message"]


def test_other_squad_failure_is_an_error(monkeypatch):
    out = _run_with_squad_raising(RuntimeError("model unreachable"), monkeypatch)
    assert out["status"] == "error" and "RuntimeError" in out["error"]
