"""Registry of all Satan attack classes."""

from k9x_satan.attacks.prompt_injection_attack import PromptInjectionAttack
from k9x_satan.attacks.search_poisoning_attack import SearchPoisoningAttack

ATTACK_REGISTRY = {
    "prompt_injection_document": PromptInjectionAttack,
    "search_poisoning":          SearchPoisoningAttack,
    # add new attacks here as they are implemented:
    # "payload_flood":           PayloadFloodAttack,
    # "pii_exfiltration":        PIIExfiltrationAttack,
    # "semantic_drift":          SemanticDriftAttack,
    # "tool_argument_poison":    ToolArgumentAttack,
    # "policy_override":         PolicyOverrideAttack,
}
