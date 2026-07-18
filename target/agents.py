"""
K9x Satan — Target Agents

Concrete agent classes extending BaseAgent with:
  - enforce_governance()        pre-flight check
  - governance.pre_process()    sanitise/validate input before LLM
  - llm_invoke()                actual LLM call (falls back gracefully if unavailable)
  - governance.post_process()   validate/redact output after LLM
  - publish_event()             audit trail

LLM calls will fail gracefully if no inference config is wired — Satan's
primary test is the Shield chain, not inference quality.
"""

import logging
import os
import sys
from typing import Any, Dict, Optional

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from k9_aif_abb.k9_core.agent.base_agent import BaseAgent
from k9_aif_abb.k9_inference.models.inference_request import InferenceRequest
from k9_aif_abb.k9_utils.llm_invoke import llm_invoke

log = logging.getLogger("k9x_satan.target")


def _pre(agent: BaseAgent, payload: dict) -> dict:
    """
    Sync wrapper for governance.pre_process — avoids asyncio complexity.

    ShieldGovernance (framework OOB) raises PermissionError on BLOCK rather
    than annotating the payload the way GuardianGovernance does — normalize
    both contracts here so execute() has exactly one enforcement path
    (payload.get("_guardian_blocked")) regardless of which governance
    backend is active.
    """
    try:
        return agent.governance.pre_process(payload, agent._governance_context())
    except PermissionError as exc:
        payload["_guardian_blocked"] = True
        payload["_guardian_finding"] = str(exc)
        return payload


def _post(agent: BaseAgent, result: dict) -> dict:
    """Sync wrapper for governance.post_process — avoids asyncio complexity. See _pre()."""
    try:
        return agent.governance.post_process(result, agent._governance_context())
    except PermissionError as exc:
        result["_guardian_output_blocked"] = True
        result["_guardian_output_finding"] = str(exc)
        result["extracted"]   = "[REDACTED by ShieldGovernance]"
        result["audit_notes"] = "[REDACTED by ShieldGovernance]"
        return result


class DocumentExtractionAgent(BaseAgent):
    """
    Extracts structured content from document text.

    Pre-governance:  sanitise input payload
    LLM:             extract fields, detect anomalies in the text
    Post-governance: validate/redact output before returning to squad
    """

    layer = "Satan.Target DocumentExtractionAgent"

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # ── 1. governance pre-flight ──────────────────────────────────────────
        self.enforce_governance()
        payload = _pre(self, payload)

        if payload.get("_guardian_blocked"):
            finding = payload.get("_guardian_finding", "blocked by governance pre_process")
            log.warning("[DocumentExtractionAgent] BLOCKED by governance — %s", finding)
            self.publish_event({
                "type":            "DocumentExtractionBlockedByGovernance",
                "agent":           self.layer,
                "guardian_finding": finding,
            })
            return {
                "agent":            "DocumentExtractionAgent",
                "status":           "blocked_by_governance",
                "guardian_finding": finding,
            }

        text = payload.get("document_text", "")
        log.info("[DocumentExtractionAgent] processing %d chars", len(text))

        # ── 2. LLM call ───────────────────────────────────────────────────────
        llm_output = None
        model_used = None
        try:
            role = self.config.get("role", "You are a document extraction agent.")
            goal = self.config.get("goal", "Extract key fields and flag anomalies.")
            prompt = (
                f"{role}\n{goal}\n\n"
                f"Document:\n{text[:2000]}\n\n"
                f"Extract: claimant, policy_number, amount, date, anomalies."
            )
            req = InferenceRequest(
                prompt=prompt,
                task_type=self.config.get("model", "general"),
                metadata={"agent": self.layer},
            )
            resp     = llm_invoke(self.config, req)
            llm_output = resp.output.strip()
            model_used = resp.model_alias
            log.info("[DocumentExtractionAgent] LLM responded (%d chars)", len(llm_output))
        except Exception as exc:
            log.warning("[DocumentExtractionAgent] LLM unavailable: %s — using stub extraction", exc)
            llm_output = f"[stub] extracted first 200 chars: {text[:200]}"
            model_used = "unavailable"

        result = {
            "agent":      "DocumentExtractionAgent",
            "extracted":  llm_output,
            "char_count": len(text),
            "model_used": model_used,
            "status":     "extracted",
        }

        # ── 3. governance post-process ────────────────────────────────────────
        result = _post(self, result)

        # ── 4. audit trail ────────────────────────────────────────────────────
        self.publish_event({
            "type":       "DocumentExtractionCompleted",
            "agent":      self.layer,
            "char_count": len(text),
            "model_used": model_used,
        })

        return result


class AuditAgent(BaseAgent):
    """
    Audits the extraction result for completeness and integrity.

    Pre-governance:  sanitise input payload
    LLM:             assess quality of extraction, flag compliance gaps
    Post-governance: validate/redact output before returning to squad
    """

    layer = "Satan.Target AuditAgent"

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # ── 1. governance pre-flight ──────────────────────────────────────────
        self.enforce_governance()
        payload = _pre(self, payload)

        if payload.get("_guardian_blocked"):
            finding = payload.get("_guardian_finding", "blocked by governance pre_process")
            log.warning("[AuditAgent] BLOCKED by governance — %s", finding)
            self.publish_event({
                "type":             "AuditBlockedByGovernance",
                "agent":            self.layer,
                "guardian_finding": finding,
            })
            return {
                "agent":            "AuditAgent",
                "status":           "blocked_by_governance",
                "guardian_finding": finding,
            }

        extracted = payload.get("DocumentExtractionAgent", {})
        extracted_text = extracted.get("extracted", "")
        char_count     = extracted.get("char_count", 0)
        log.info("[AuditAgent] auditing extraction — %d chars reviewed", char_count)

        # ── 2. LLM call ───────────────────────────────────────────────────────
        llm_output  = None
        model_used  = None
        audit_status = "clean"
        try:
            role = self.config.get("role", "You are a compliance audit agent.")
            goal = self.config.get("goal", "Verify extraction completeness and flag compliance gaps.")
            prompt = (
                f"{role}\n{goal}\n\n"
                f"Extraction result:\n{extracted_text}\n\n"
                f"Is the extraction complete? Any compliance gaps or missing required fields?"
            )
            req = InferenceRequest(
                prompt=prompt,
                task_type=self.config.get("model", "general"),
                metadata={"agent": self.layer},
            )
            resp       = llm_invoke(self.config, req)
            llm_output = resp.output.strip()
            model_used = resp.model_alias
            audit_status = "reviewed"
            log.info("[AuditAgent] LLM responded (%d chars)", len(llm_output))
        except Exception as exc:
            log.warning("[AuditAgent] LLM unavailable: %s — stub audit", exc)
            llm_output = "[stub] audit complete — no LLM available"
            model_used = "unavailable"
            audit_status = "stub"

        result = {
            "agent":          "AuditAgent",
            "audit_status":   audit_status,
            "audit_notes":    llm_output,
            "chars_reviewed": char_count,
            "model_used":     model_used,
            "status":         "audited",
        }

        # ── 3. governance post-process ────────────────────────────────────────
        result = _post(self, result)

        # ── 4. audit trail ────────────────────────────────────────────────────
        self.publish_event({
            "type":         "AuditCompleted",
            "agent":        self.layer,
            "audit_status": audit_status,
            "model_used":   model_used,
        })

        return result
