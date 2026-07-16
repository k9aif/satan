"""
K9x Satan — RequestFrequencyCheck SBB

Extends BaseVulnerabilityCheck. Uses the framework's CacheFactory to enforce a
per-session request budget within a rolling time window — OWASP LLM Top 10
2025's "Unbounded Consumption" (LLM10).

InputSizeCheck (framework OOB) bounds the size of a single payload. It says
nothing about how many payloads a session sends per minute. A resource-
exhaustion attack that stays under the per-payload size limit but fires a high
volume of requests against the same session is invisible to InputSizeCheck —
this check is the complementary control.

Config:
    security.max_requests_per_window:   int  — request budget (default 20)
    security.rate_limit_window_seconds: int  — rolling window length (default 60)
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict

_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework")
)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.base_vulnerability_check import BaseVulnerabilityCheck
from k9_aif_abb.k9_security.vulnerability.models.check_result import CheckResult
from k9x_satan.target._shared_cache import get_shared_cache


class RequestFrequencyCheck(BaseVulnerabilityCheck):
    """
    Enforces a per-session request budget within a rolling time window.
    Returns BLOCK once the session exceeds the configured request count.
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._cache = get_shared_cache(self.config)
        security_cfg = self.config.get("security", {})
        self._max_requests   = int(security_cfg.get("max_requests_per_window", 20))
        self._window_seconds = int(security_cfg.get("rate_limit_window_seconds", 60))

    def check(self, payload: Dict[str, Any]) -> CheckResult:
        session_id = payload.get("session_id") or payload.get("correlation_id") or "default"
        key = f"satan:rate:{session_id}"
        now = time.time()

        state = self._cache.get(key) or {"count": 0, "window_start": now}
        if now - state["window_start"] > self._window_seconds:
            state = {"count": 0, "window_start": now}

        state["count"] += 1
        self._cache.set(key, state, ttl=self._window_seconds * 2)

        if state["count"] > self._max_requests:
            return CheckResult.block(
                check_name=self.check_name,
                message=(
                    f"Session '{session_id}' exceeded {self._max_requests} requests "
                    f"in {self._window_seconds}s — possible resource-exhaustion attack"
                ),
                severity="high",
                metadata={"session_id": session_id, "count": state["count"], "limit": self._max_requests},
            )

        return CheckResult.pass_check(self.check_name)
