"""
K9x Satan — ToolAuthorizationCheck SBB

Extends BaseVulnerabilityCheck. Validates that any tool the agent is about to
call — or any external backend a tool call resolves to — is on the solution's
approved allowlist.

This is distinct from ToolArgumentCheck (framework OOB): ToolArgumentCheck
inspects the *arguments* of a tool call assuming the tool itself is legitimate
(SQL injection, command injection, path traversal, SSRF payloads). This check
inspects the tool's *identity* — catching Zscaler ThreatLabz's "Shadow AI &
Tool Abuse" vector, where an unapproved tool or a poisoned/attacker-controlled
backend URL is invoked instead of (or masquerading as) a sanctioned one.

Config:
    security.approved_tools:    list[str]  — allowed tool_name values
    security.approved_backends: list[str]  — allowed host substrings for any
                                              *_backend / *_url / *_endpoint field
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework")
)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.base_vulnerability_check import BaseVulnerabilityCheck
from k9_aif_abb.k9_security.vulnerability.models.check_result import CheckResult

_DEFAULT_APPROVED_TOOLS: List[str] = ["fake_search"]
_DEFAULT_APPROVED_BACKENDS: List[str] = ["localhost", "127.0.0.1"]

_BACKEND_FIELD_SUFFIXES = ("_backend", "_url", "_endpoint")


class ToolAuthorizationCheck(BaseVulnerabilityCheck):
    """
    Detects unapproved tools or tool backends before a tool call is dispatched.
    Returns BLOCK on any tool_name or backend URL not on the allowlist.
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        security_cfg = self.config.get("security", {})
        self._approved_tools    = set(security_cfg.get("approved_tools", _DEFAULT_APPROVED_TOOLS))
        self._approved_backends = list(security_cfg.get("approved_backends", _DEFAULT_APPROVED_BACKENDS))

    def check(self, payload: Dict[str, Any]) -> CheckResult:
        tool_name = payload.get("tool_name")
        if tool_name and tool_name not in self._approved_tools:
            return CheckResult.block(
                check_name=self.check_name,
                message=f"Unapproved tool invocation: '{tool_name}' is not on the approved tool allowlist",
                severity="critical",
                metadata={"tool_name": tool_name, "approved_tools": sorted(self._approved_tools)},
            )

        for key, value in payload.items():
            if not key.endswith(_BACKEND_FIELD_SUFFIXES) or not isinstance(value, str):
                continue
            host = _extract_host(value)
            if not any(_host_matches(host, approved) for approved in self._approved_backends):
                return CheckResult.block(
                    check_name=self.check_name,
                    message=f"Unapproved tool backend: '{value}' resolves to a host outside the allowlist",
                    severity="critical",
                    metadata={"field": key, "backend": value, "host": host, "approved_backends": self._approved_backends},
                )

        return CheckResult.pass_check(self.check_name)


def _extract_host(value: str) -> str:
    """
    Extract and normalize the hostname from a URL or bare host[:port] string.

    Lowercased, port stripped. Prepending "//" when no scheme is present lets
    urlparse treat the leading segment as netloc (so "localhost:9999" and
    "http://localhost:9999" both yield hostname "localhost") — plain
    urlparse("localhost:9999") would otherwise parse it as a relative path,
    not a host.
    """
    candidate = value if "://" in value else f"//{value}"
    hostname = urlparse(candidate).hostname
    return (hostname or value).lower()


def _host_matches(host: str, approved: str) -> bool:
    """
    Exact match or suffix match on a dot boundary — NOT substring containment.

    "localhost" must match host "localhost" or "api.localhost", never
    "evil-localhost.attacker.com" (substring containment previously let that
    through — a live SSRF/egress allowlist bypass).
    """
    host = host.lower()
    approved = approved.lower()
    return host == approved or host.endswith("." + approved)
