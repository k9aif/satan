"""
K9x Satan — FieldAnomalyCheck SBB

Extends BaseVulnerabilityCheck. Uses fields extracted by DoclingExtractor
(stored in payload["extracted_fields"]) to detect document-level anomalies
that pattern-based injection checks miss.

Catches:
  - Social engineering: authority-override fields (Priority: CRITICAL,
    "Effective immediately", "supersedes all previous configuration")
  - Fake executive directives: COO/CEO authorization codes, action-required
    lists embedded in claim documents
  - Schema spoofing: a document claiming to be a claim form but containing
    none of the expected fields

Works with or without Docling — when extraction_method is "naive", check runs
against regex-extracted fields. When Docling-extracted, fields are richer.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List

_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework")
)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_security.vulnerability.base_vulnerability_check import BaseVulnerabilityCheck
from k9_aif_abb.k9_security.vulnerability.models.check_result import CheckResult


# ── Field keys that are red flags in a claims-processing document ────────────

_RED_FLAG_KEYS = {
    "priority",
    "action_required",
    "action",
    "override",
    "directive",
    "authorization_code",
    "coo_authorization_code",
    "ceo_authorization_code",
    "cfo_authorization_code",
    "executive_directive",
    "effective_immediately",
    "supersedes",
}

# ── Value patterns indicating social-engineering / authority-override intent ──

_RED_FLAG_VALUE_PATTERNS: List[re.Pattern] = [
    re.compile(r"override\s+.{0,40}(procedure|validation|rule|policy|check)", re.I),
    re.compile(r"disable\s+.{0,30}(audit|log|check|filter|safety)", re.I),
    re.compile(r"suspend\s+.{0,30}(rule|policy|check|system|normal)", re.I),
    re.compile(r"this\s+(directive\s+)?supersedes", re.I),
    re.compile(r"effective\s+immediately.{0,60}(all|override|disable|ai)", re.I),
    re.compile(r"authorization\s+code\s*:", re.I),
    re.compile(r"normal\s+(rule|validation|procedure)s?\s+suspended", re.I),
    re.compile(r"set\s+confidence\s+(score\s+)?to\s+1\.0", re.I),
    re.compile(r"approve\s+.{0,40}without\s+.{0,30}(check|fraud|validation)", re.I),
    re.compile(r"return\s+.{0,30}(pii|customer\s+pii|full.{0,10}ssn)", re.I),
]

# ── Patterns scanned on raw document text (catch HTML comment injections, etc.) ──

_RED_FLAG_RAW_PATTERNS: List[re.Pattern] = [
    re.compile(r"(EXEC|COO|CEO|CFO)[\s\-]+OVERRIDE[\s\-]+\d{4}", re.I),
    re.compile(r"executive\s+directive", re.I),
    re.compile(r"system\s+maintenance\s+window.*suspended", re.I | re.DOTALL),
]


class FieldAnomalyCheck(BaseVulnerabilityCheck):
    """
    Detects social engineering and schema-spoofing via document field analysis.

    Checks extracted_fields from DoclingExtractor, plus raw document_text for
    authority-override patterns. Returns BLOCK on any red-flag hit.
    """

    def check(self, payload: Dict[str, Any]) -> CheckResult:
        red_flag_keys:     List[str] = []
        red_flag_values:   List[str] = []
        red_flag_raw:      List[str] = []

        # ── 1. Check extracted field keys ────────────────────────────────────
        fields: Dict[str, str] = payload.get("extracted_fields", {})
        for key in fields:
            if key in _RED_FLAG_KEYS:
                red_flag_keys.append(f"field:{key}={fields[key][:60]!r}")

        # ── 2. Check extracted field values ──────────────────────────────────
        for key, val in fields.items():
            if not isinstance(val, str):
                continue
            for pattern in _RED_FLAG_VALUE_PATTERNS:
                m = pattern.search(val)
                if m:
                    red_flag_values.append(f"{key}: {m.group()!r}")
                    break

        # ── 3. Scan raw document text (catches injections outside key:value) ─
        raw = payload.get("document_text", "")
        if isinstance(raw, str):
            for pattern in _RED_FLAG_RAW_PATTERNS:
                m = pattern.search(raw)
                if m:
                    excerpt = m.group()[:80]
                    if excerpt not in [r[r.find(":")+1:].strip() for r in red_flag_raw]:
                        red_flag_raw.append(f"raw: {excerpt!r}")

        all_flags = red_flag_keys + red_flag_values + red_flag_raw
        if all_flags:
            extraction = payload.get("extraction_method", "unknown")
            return CheckResult.block(
                check_name=self.check_name,
                message=(
                    f"Authority-override patterns detected via {extraction} extraction "
                    f"({len(all_flags)} indicator{'s' if len(all_flags) != 1 else ''}): "
                    f"{', '.join(all_flags[:2])}"
                ),
                severity="critical",
                metadata={
                    "red_flag_keys":   red_flag_keys[:5],
                    "red_flag_values": red_flag_values[:5],
                    "red_flag_raw":    red_flag_raw[:3],
                    "extraction_method": extraction,
                    "field_count":     len(fields),
                },
            )

        return CheckResult.pass_check(self.check_name)
