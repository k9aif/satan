"""
K9x Satan — OutputSanitizationCheck SBB

Extends BaseVulnerabilityCheck. Scans agent output for markup/script injection
patterns that are safe in a text/JSON payload but dangerous the moment that
output is rendered by a downstream consumer (a web UI, an email client, a
templating engine) — OWASP LLM Top 10 2025's "Improper Output Handling" (LLM05).

ToolArgumentCheck (framework OOB) already guards SQL/command/path/SSRF payloads
aimed at a tool call. This check guards the other common LLM05 sink: HTML/JS/
template markup that an attacker gets the LLM to echo into its response,
expecting some downstream renderer to execute it.

Config:
    security.block_on_output_markup: bool  — True (default) = BLOCK; False = FLAG
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Tuple

_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework")
)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.base_vulnerability_check import BaseVulnerabilityCheck
from k9_aif_abb.k9_security.vulnerability.models.check_result import CheckResult

_OUTPUT_MARKUP_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"<script[\s>]", re.I),                       "inline <script> tag"),
    (re.compile(r"javascript:", re.I),                        "javascript: URI"),
    (re.compile(r"\bon(error|load|click|mouseover)\s*=", re.I), "inline event handler"),
    (re.compile(r"<iframe[\s>]", re.I),                       "<iframe> injection"),
    (re.compile(r"data:text/html", re.I),                     "data:text/html URI"),
    (re.compile(r"\{\{.*\}\}"),                                "template injection ({{ }})"),
    (re.compile(r"\$\{.*\}"),                                  "template injection (${ })"),
]


class OutputSanitizationCheck(BaseVulnerabilityCheck):
    """
    Detects markup/script/template injection patterns in agent output before
    it exits the pipeline. Returns BLOCK by default (configurable to FLAG).
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        security_cfg = self.config.get("security", {})
        self._block = security_cfg.get("block_on_output_markup", True)

    def check(self, payload: Dict[str, Any]) -> CheckResult:
        # Recursively flatten — DocumentOrchestrator's squad_output nests agent
        # results under agent-name keys (payload["DocumentExtractionAgent"]["extracted"]),
        # not at the top level. Matches the pattern PIIBoundaryCheck/
        # HardcodedCredentialCheck (framework OOB) use for the same reason.
        text = _flatten(payload)

        for pattern, label in _OUTPUT_MARKUP_PATTERNS:
            m = pattern.search(text)
            if m:
                msg = f"Dangerous output markup detected: {label}"
                meta = {"label": label, "excerpt": m.group()[:60]}
                if self._block:
                    return CheckResult.block(
                        check_name=self.check_name, message=msg, severity="high", metadata=meta,
                    )
                return CheckResult.flag(
                    check_name=self.check_name, message=msg, severity="medium", metadata=meta,
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
