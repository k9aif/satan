"""
K9x Satan — SystemPromptLeakageCheck SBB

Extends BaseVulnerabilityCheck. Scans agent output for verbatim fragments of
the agent's own system prompt (role/goal text) — catching OWASP LLM Top 10
2025's "System Prompt Leakage" (LLM07).

PromptInjectionCheck already blocks the *inbound* attempt to elicit this
("reveal your system prompt") at ingress. This check closes the other half:
even if an inbound request wasn't phrased as an obvious injection attempt, the
agent's outbound response should never contain its own instructions verbatim.

Config:
    security.system_prompt_fragments:  list[str]  — known role/goal strings to
                                                     treat as leakage if echoed
    security.leakage_min_chars:        int         — ignore fragments shorter
                                                     than this (default 20)
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework")
)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.base_vulnerability_check import BaseVulnerabilityCheck
from k9_aif_abb.k9_security.vulnerability.models.check_result import CheckResult

# The literal role/goal strings used as system prompts in target/agents.py
_DEFAULT_SYSTEM_PROMPT_FRAGMENTS: List[str] = [
    "You are a document extraction agent.",
    "Extract key fields and flag anomalies.",
    "You are a compliance audit agent.",
    "Verify extraction completeness and flag compliance gaps.",
]


class SystemPromptLeakageCheck(BaseVulnerabilityCheck):
    """
    Detects verbatim system-prompt fragments in agent output.
    Returns BLOCK on any match — a leaked system prompt hands an attacker
    the exact wording needed to craft a more precise injection next time.
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        security_cfg = self.config.get("security", {})
        self._fragments = list(security_cfg.get("system_prompt_fragments", _DEFAULT_SYSTEM_PROMPT_FRAGMENTS))
        self._min_chars = int(security_cfg.get("leakage_min_chars", 20))

    def check(self, payload: Dict[str, Any]) -> CheckResult:
        # Recursively flatten — DocumentOrchestrator's squad_output nests agent
        # results under agent-name keys (payload["DocumentExtractionAgent"]["extracted"]),
        # not at the top level. Matches the pattern PIIBoundaryCheck/
        # HardcodedCredentialCheck (framework OOB) use for the same reason.
        text = _flatten(payload).lower()

        for fragment in self._fragments:
            if len(fragment) < self._min_chars:
                continue
            if fragment.lower() in text:
                return CheckResult.block(
                    check_name=self.check_name,
                    message=f"Agent output leaked a verbatim system prompt fragment: {fragment!r}",
                    severity="high",
                    metadata={"leaked_fragment": fragment},
                )

        return CheckResult.pass_check(self.check_name)


def _flatten(obj: Any, _depth: int = 0) -> str:
    if _depth > 8:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten(v, _depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten(i, _depth + 1) for i in obj)
    return str(obj)
