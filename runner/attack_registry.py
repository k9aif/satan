# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""Registry of all Satan attack classes."""

from k9x_satan.attacks.prompt_injection_attack import PromptInjectionAttack
from k9x_satan.attacks.search_poisoning_attack import SearchPoisoningAttack
from k9x_satan.attacks.payload_flood_attack import PayloadFloodAttack
from k9x_satan.attacks.pii_exfiltration_attack import PIIExfiltrationAttack
from k9x_satan.attacks.semantic_drift_attack import SemanticDriftAttack
from k9x_satan.attacks.tool_argument_attack import ToolArgumentAttack
from k9x_satan.attacks.execution_bypass_attack import ExecutionBypassAttack
from k9x_satan.attacks.hardcoded_credential_attack import HardcodedCredentialAttack
from k9x_satan.attacks.memory_poisoning_attack import MemoryPoisoningAttack
from k9x_satan.attacks.shadow_tool_attack import ShadowToolAttack
from k9x_satan.attacks.system_prompt_leakage_attack import SystemPromptLeakageAttack
from k9x_satan.attacks.output_sanitization_attack import OutputSanitizationAttack
from k9x_satan.attacks.request_flood_attack import RequestFloodAttack

ATTACK_REGISTRY = {
    "prompt_injection_document": PromptInjectionAttack,
    "search_poisoning":          SearchPoisoningAttack,
    "payload_flood":             PayloadFloodAttack,
    "pii_exfiltration":          PIIExfiltrationAttack,
    "semantic_drift":            SemanticDriftAttack,
    "tool_argument_poison":      ToolArgumentAttack,
    "execution_bypass":          ExecutionBypassAttack,
    "hardcoded_credential":      HardcodedCredentialAttack,
    "memory_poisoning":          MemoryPoisoningAttack,
    "shadow_tool":               ShadowToolAttack,
    "system_prompt_leakage":     SystemPromptLeakageAttack,
    "output_sanitization":       OutputSanitizationAttack,
    "request_flood":             RequestFloodAttack,
}
