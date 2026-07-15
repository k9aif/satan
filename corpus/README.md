# Attack Corpus

Malicious document and payload samples used by Satan attack implementations.

| File | Attack Class | Injection Method |
|---|---|---|
| `malicious_claim_form.txt` | `PromptInjectionAttack` | Override instructions in form body |
| `poisoned_policy_doc.txt` | `PromptInjectionAttack` | Hidden directive in HTML comment |
| `drift_narrative.txt` | `SemanticDriftAttack` | Gradual role reframing via repeated framing |
| `oversized_payload.txt` | `PayloadFloodAttack` | 1MB+ text to exhaust token budget |
| `pii_extraction_prompt.txt` | `PIIExfiltrationAttack` | Compliance-framed PII request |

All samples are synthetic. No real customer data.
