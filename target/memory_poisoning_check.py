"""
K9x Satan — MemoryPoisoningCheck SBB

Extends BaseVulnerabilityCheck. Uses the framework's CacheFactory to fingerprint
the trust-sensitive facts of a session (claim amount, policy number, approval
status, fraud/confidence scores) and catches two distinct threat patterns:

  1. Fabricated memory  — the payload references a prior approval/agreement
     ("as previously approved", "per our prior conversation") for a session
     that has no corresponding cache record. There is no "prior" to reference.
  2. Contradicted memory — the payload's current facts conflict with facts
     already recorded for this session, framed with authority language that
     tries to make the override look legitimate ("the claim amount was
     corrected to $500,000", "this supersedes the earlier approval").

This is the runtime-checkable analog of Zscaler ThreatLabz's "Memory Poisoning"
vector — persistent memory/session state contaminated across turns. It has no
counterpart among the framework's OOB checks, which all evaluate a single
payload in isolation; this check is what makes cross-session state tampering
detectable at all.

Session key priority: session_id > correlation_id > "default". A stateless
attack that never reuses a session/correlation id can never trigger the
contradiction path — only the fabricated-memory path (claiming a past that
was never recorded).
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework")
)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.base_vulnerability_check import BaseVulnerabilityCheck
from k9_aif_abb.k9_security.vulnerability.models.check_result import CheckResult
from k9x_satan.target._shared_cache import get_shared_cache

# ── Facts worth fingerprinting across turns of the same session ──────────────

_TRACKED_FACT_KEYS = {
    "claim_amount", "policy_number", "approval_status",
    "fraud_score", "confidence", "authorization_code",
}

# ── Phrases that assert a prior session state exists ──────────────────────────

_MEMORY_CLAIM_PATTERNS: List[re.Pattern] = [
    re.compile(r"as\s+(previously|already)\s+(established|agreed|approved|confirmed)", re.I),
    re.compile(r"(per|recall)\s+(our\s+)?(prior|previous|earlier)\s+(conversation|session|discussion|approval)", re.I),
    re.compile(r"you\s+(already|previously)\s+(agreed|approved|confirmed|said)", re.I),
    re.compile(r"(this\s+)?(corrects?|supersedes|updates?)\s+the\s+(earlier|previous|prior)\s+(value|amount|approval|record)", re.I),
    re.compile(r"in\s+our\s+last\s+(session|conversation|turn)", re.I),
    re.compile(r"memory\s+(says|shows|indicates)", re.I),
]


class MemoryPoisoningCheck(BaseVulnerabilityCheck):
    """
    Detects fabricated or contradicted session memory using a CacheFactory-backed
    fact fingerprint. BLOCKs when the payload claims a prior state that isn't in
    the cache, or contradicts facts already recorded for the session.
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._cache = get_shared_cache(self.config)
        self._ttl = int(self.config.get("security", {}).get("memory_ttl", 3600))

    def check(self, payload: Dict[str, Any]) -> CheckResult:
        session_id = payload.get("session_id") or payload.get("correlation_id") or "default"
        cache_key  = f"satan:memory:{session_id}"

        text = " ".join([
            str(payload.get("document_text", "")),
            str(payload.get("extracted", "")),
            str(payload.get("audit_notes", "")),
        ])

        claims_prior_state = any(p.search(text) for p in _MEMORY_CLAIM_PATTERNS)
        prior_facts: Optional[Dict[str, str]] = self._cache.get(cache_key)
        current_facts = _extract_facts(payload)

        if claims_prior_state and prior_facts is None:
            return CheckResult.block(
                check_name=self.check_name,
                message=(
                    "Payload references a prior session state "
                    f"(session={session_id}) with no corresponding cache record "
                    "— fabricated memory claim"
                ),
                severity="critical",
                metadata={"session_id": session_id, "threat": "fabricated_memory"},
            )

        if prior_facts:
            conflicts = {
                k: (prior_facts[k], current_facts[k])
                for k in current_facts
                if k in prior_facts and prior_facts[k] != current_facts[k]
            }
            if conflicts and claims_prior_state:
                return CheckResult.block(
                    check_name=self.check_name,
                    message=(
                        f"Payload contradicts previously recorded session facts "
                        f"(session={session_id}): {conflicts}"
                    ),
                    severity="critical",
                    metadata={"session_id": session_id, "threat": "contradicted_memory", "conflicts": conflicts},
                )

        # Merge and persist facts for future turns in this session.
        merged = {**(prior_facts or {}), **current_facts}
        if merged:
            self._cache.set(cache_key, merged, ttl=self._ttl)

        return CheckResult.pass_check(self.check_name)


def _extract_facts(payload: Dict[str, Any]) -> Dict[str, str]:
    """Pull the tracked fact keys out of extracted_fields (populated by DoclingExtractor)."""
    fields: Dict[str, str] = payload.get("extracted_fields", {}) or {}
    return {k: v for k, v in fields.items() if k in _TRACKED_FACT_KEYS and isinstance(v, str)}
