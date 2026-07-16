"""
K9x Satan — DoclingExtractor SBB

Pre-Shield document field extractor. Runs before the VulnerabilityChain so that
FieldAnomalyCheck can evaluate structured field data.

Two extraction modes:
  naive   — lightweight regex key:value extraction (zero dependencies, always available)
  docling — Docling OCR/parse (optional; requires docling installed and enabled in config)

Architecture note: in production K9-AIF deployments, document extraction runs as a
dedicated Squad that consumes from a Kafka topic (non-blocking). In Satan (synchronous
test harness) it runs inline as a pre-Shield enrichment step — acceptable for red-team
testing where throughput is irrelevant.

Config:
    docling.enabled:    bool   — False (default); set True if docling is installed
    docling.endpoint:   str    — optional REST endpoint for remote Docling server
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Tuple

log = logging.getLogger("k9x_satan.target.extractor")


def _compose_docling_url() -> str:
    """Build Docling URL from env vars, handling split host/port format.

    Accepts either:
      DOCLING_URL=http://host:5001          (full URL — used as-is)
      DOCLING_URL=192.168.1.98 + DOCLING_PORT=5001  (host + port — composed)
    """
    raw = os.environ.get("DOCLING_URL", "")
    if raw.startswith("http"):
        return raw
    port = os.environ.get("DOCLING_PORT", "5001")
    if raw:
        return f"http://{raw}:{port}"
    return f"http://localhost:{port}"


class DoclingExtractor:
    """
    SBB: Pre-Shield document field extractor.

    Enriches the payload with extracted_fields, extraction_method, and
    docling_used before it enters the VulnerabilityChain.
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        cfg            = config or {}
        docling_cfg    = cfg.get("docling", {})
        self._enabled  = bool(docling_cfg.get("enabled", False))
        self._url     = docling_cfg.get("url") or _compose_docling_url()
        self._timeout = int(docling_cfg.get("timeout", 180))

    # ── public API ────────────────────────────────────────────────────────────

    def enrich(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Return a new payload dict enriched with field extraction results."""
        text = payload.get("document_text", "")
        fields: Dict[str, str] = {}
        docling_used  = False
        fallback_reason: str = ""

        if self._enabled:
            try:
                fields, docling_used = self._extract_via_docling(text)
                log.info("[DoclingExtractor] docling extraction: %d fields", len(fields))
            except Exception as exc:
                fallback_reason = str(exc)
                log.warning("[DoclingExtractor] docling failed (%s) — falling back to naive", exc)
                fields = self._naive_extract(text)
        else:
            fields = self._naive_extract(text)

        return {
            **payload,
            "extracted_fields":    fields,
            "extraction_method":   "docling" if docling_used else "naive",
            "docling_used":        docling_used,
            "extracted_count":     len(fields),
            "extraction_fallback": bool(fallback_reason),
            "extraction_error":    fallback_reason,
        }

    # ── extraction modes ──────────────────────────────────────────────────────

    def _naive_extract(self, text: str) -> Dict[str, str]:
        """Lightweight regex extraction of KEY: VALUE pairs from plain text."""
        fields: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^([A-Za-z][A-Za-z0-9 _\-]{1,50}):\s*(.{1,200})$", line)
            if m:
                key = _normalize_key(m.group(1))
                val = m.group(2).strip()
                if key and val:
                    fields[key] = val
        return fields

    def _extract_via_docling(self, text: str) -> Tuple[Dict[str, str], bool]:
        """
        Attempt Docling extraction. Returns (fields, True) on success.

        Priority: local docling library → remote endpoint → raises on both fail.
        """
        # Try local library first
        try:
            return self._docling_library(text), True
        except ImportError:
            pass

        # Try remote server if URL configured
        if self._url:
            return self._docling_endpoint(text), True

        raise RuntimeError("docling not installed and no endpoint configured")

    def _docling_library(self, text: str) -> Dict[str, str]:
        """Use installed docling package for structured extraction."""
        import tempfile, pathlib
        from docling.document_converter import DocumentConverter  # type: ignore

        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w",
                                         encoding="utf-8", delete=False) as f:
            f.write(text)
            tmp = f.name

        try:
            converter = DocumentConverter()
            result    = converter.convert(tmp)
            md_text   = result.document.export_to_markdown()
            # Extract key:value pairs from the structured output
            return self._naive_extract(md_text)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _docling_endpoint(self, text: str) -> Dict[str, str]:
        """Call a remote Docling server.

        Tries docling-serve's standard multipart file upload first
        (POST /v1/convert/file), then falls back to a JSON text endpoint
        (POST /v1/parse) for custom wrappers.
        """
        import io, requests  # type: ignore
        base = self._url.rstrip("/")

        # --- attempt 1: docling-serve standard multipart upload ---
        # Field name is "files" (plural) — matches DoclingParser ABB in k9-aif-framework.
        upload_url = f"{base}/v1/convert/file"
        try:
            file_bytes = io.BytesIO(text.encode("utf-8"))
            resp = requests.post(
                upload_url,
                files={"files": ("document.txt", file_bytes, "text/plain")},
                timeout=self._timeout,
            )
            if resp.status_code not in (404, 405, 422):
                resp.raise_for_status()
                return self._parse_docling_response(resp.json())
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(f"Cannot connect to {base}: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(f"Timeout reaching {base}") from exc

        # --- attempt 2: custom JSON text wrapper (POST /v1/parse) ---
        parse_url = f"{base}/v1/parse"
        resp2 = requests.post(
            parse_url,
            json={"text": text},
            timeout=self._timeout,
        )
        resp2.raise_for_status()
        return self._parse_docling_response(resp2.json())

    def _parse_docling_response(self, data: Any) -> Dict[str, str]:
        """Extract key:value fields from any docling-serve response shape."""
        if isinstance(data, dict):
            # docling-serve v2: {"document": {"md_content": "..."}}
            doc = data.get("document", {})
            if isinstance(doc, dict):
                for key in ("md_content", "text", "content"):
                    if key in doc:
                        return self._naive_extract(str(doc[key]))
            # custom wrapper: {"fields": {...}}
            if "fields" in data:
                return {_normalize_key(k): str(v) for k, v in data["fields"].items()}
            # custom wrapper: {"text": "..."}
            if "text" in data:
                return self._naive_extract(str(data["text"]))
        return self._naive_extract(str(data))


def _normalize_key(raw: str) -> str:
    """'COO Authorization Code' → 'coo_authorization_code'"""
    return re.sub(r"[^a-z0-9]+", "_", raw.strip().lower()).strip("_")
