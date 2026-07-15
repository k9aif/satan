"""BaseAttack — ABB contract for all K9x Satan attack implementations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class AttackSurface(str, Enum):
    DOCUMENT   = "document"    # inbound document / form content
    SEARCH     = "search"      # web search tool response
    CONFIG     = "config"      # SBB config override attempt
    PAYLOAD    = "payload"     # raw inbound payload
    TOOL       = "tool"        # tool call arguments


class PenetrationDepth(str, Enum):
    """How far the attack penetrated before being stopped."""
    ROUTER        = "router"        # stopped at ingress gate — Shield held
    ORCHESTRATOR  = "orchestrator"  # stopped at egress gate — Shield held
    SQUAD         = "squad"         # reached squad layer   — FINDING
    AGENT         = "agent"         # reached agent layer   — FINDING
    UNKNOWN       = "unknown"


class AttackOutcome(str, Enum):
    BLOCKED  = "BLOCKED"   # stopped at router or orchestrator — Shield held
    FLAGGED  = "FLAGGED"   # soft-blocked, flagged for review — Shield held
    PASSED   = "PASSED"    # not stopped — vulnerability found


@dataclass
class AttackResult:
    attack_name:       str
    surface:           AttackSurface
    outcome:           AttackOutcome
    penetration_depth: PenetrationDepth
    payload_sent:      Dict[str, Any]
    response_received: Optional[Dict[str, Any]] = None
    finding:           Optional[str] = None
    notes:             str = ""

    @property
    def shield_held(self) -> bool:
        return self.outcome in (AttackOutcome.BLOCKED, AttackOutcome.FLAGGED)


class BaseAttack(ABC):
    """
    ABB contract for all Satan attack implementations.

    Each subclass targets one attack surface and one K9X Shield check.
    The run() method sends the crafted payload through the real pipeline
    and returns an AttackResult with penetration depth and outcome.
    """

    name:    str = "BaseAttack"
    surface: AttackSurface = AttackSurface.PAYLOAD

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    @abstractmethod
    def craft_payload(self) -> Dict[str, Any]:
        """Build the malicious payload to send."""
        raise NotImplementedError

    @abstractmethod
    def run(self, target_url: str) -> AttackResult:
        """Send the attack and return the result."""
        raise NotImplementedError

    def _classify_depth(self, response: Dict[str, Any]) -> PenetrationDepth:
        """
        Infer penetration depth from the pipeline response.
        Shield-blocked responses contain a 'blocked_at' key.
        """
        blocked_at = response.get("blocked_at", "")
        if "router" in blocked_at:
            return PenetrationDepth.ROUTER
        if "orchestrator" in blocked_at:
            return PenetrationDepth.ORCHESTRATOR
        if "squad" in blocked_at or response.get("squad_id"):
            return PenetrationDepth.SQUAD
        if "agent" in blocked_at or response.get("agent"):
            return PenetrationDepth.AGENT
        return PenetrationDepth.UNKNOWN

    def _classify_outcome(self, response: Dict[str, Any], depth: PenetrationDepth) -> AttackOutcome:
        status = response.get("status", "")
        if status in ("blocked", "rejected"):
            return AttackOutcome.BLOCKED
        if status == "flagged":
            return AttackOutcome.FLAGGED
        if depth in (PenetrationDepth.SQUAD, PenetrationDepth.AGENT):
            return AttackOutcome.PASSED
        return AttackOutcome.BLOCKED
