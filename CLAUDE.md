# CLAUDE.md — K9x Satan

This file guides Claude Code (or any coding assistant) working in `k9x_satan/`. It is self-contained — read it before touching this codebase, even without prior conversation context.

## What this project proves

**K9x Satan exists to demonstrate that zero trust and vulnerability defense are properties of the K9-AIF framework itself — not something each application has to build.**

The framework under test lives at `/Users/ravinatarajan/ai/k9-aif-framework/k9_aif_abb/` (imported here as `k9_aif_abb`). Its `k9_security/` package ships three ABB (Architecture Building Block) contracts:

| ABB | Path | Role |
|---|---|---|
| `BaseVulnerabilityCheck` | `k9_security/vulnerability/base_vulnerability_check.py` | One class of threat, one handler — GoF Chain of Responsibility link |
| `VulnerabilityChain` | `k9_security/vulnerability/vulnerability_chain.py` | Runs checks in order; stops on first BLOCK, continues past FLAG |
| `BaseAttack` | `k9_security/attacks/base_attack.py` | Symmetric offense-side contract — one attack SBB per threat class |
| `BaseZeroTrustGuard` / `DefaultZeroTrustGuard` | `k9_security/zero_trust/guards.py` | Verify → Control → Enforce guard, opt-in on `BaseOrchestrator` |

`BaseRouter` and `BaseOrchestrator` (`k9_aif_abb/k9_core/router/`, `k9_aif_abb/k9_core/orchestration/`) each expose an abstract chain-builder hook (`_build_ingress_chain()` / `_build_egress_chain()`) that any solution built on the framework must fill in. **Satan's job is to fire real attacks at a real pipeline built from these ABBs and prove that a poisoned payload cannot reach the Squad/Agent layer undetected.**

If an attack reaches the Squad/Agent layer, that is a **finding** — a gap in the framework, not a partial pass. Findings drive new `BaseVulnerabilityCheck` subclasses upstream in the framework; this is the hardening loop (see README.md and the Architecture tab).

## Containment contract

```
Attack → Router (ingress gate)       → BLOCKED  ✓
              ↓ if not blocked
         Orchestrator (egress gate)  → BLOCKED  ✓
              ↓ if not blocked
         Squad / Agent               → FINDING  ✗  (Shield failed)
```

A block at any phase terminates execution — downstream phases never run. Both gates are `VulnerabilityChain` instances assembled from framework `BaseVulnerabilityCheck` subclasses plus Satan-local subclasses. 13 checks total (7 framework OOB, 6 Satan-local) — see the "Complete Check Inventory" table in README.md and the Architecture tab for the full component × threat-class mapping.

## Repo structure

```
k9x_satan/
├── target/            ← the pipeline under test (SBBs extending K9-AIF ABBs)
│   ├── router.py           DocumentRouter(BaseRouter)          — ingress Shield (5 checks)
│   ├── orchestrator.py     DocumentOrchestrator(BaseOrchestrator) — egress Shield (8 checks)
│   ├── squad.py            DocumentProcessingSquad(BaseSquad) + governance selection (noop|guardian|shield)
│   ├── agents.py           DocumentExtractionAgent, AuditAgent (BaseAgent) — enforce _guardian_blocked
│   ├── field_anomaly_check.py, memory_poisoning_check.py, tool_authorization_check.py,
│   │   system_prompt_leakage_check.py, output_sanitization_check.py, request_frequency_check.py
│   │                       Satan-local BaseVulnerabilityCheck SBBs (6 total)
│   ├── extractor.py        DoclingExtractor — pre-Shield field extraction (naive regex | Docling OCR)
│   ├── guardian_governance.py  GuardianGovernance(BaseGovernance) — IBM Granite Guardian, fail-closed by default
│   └── pipeline.py         wiring: load config → extractor.enrich() → router.route()
├── attacks/            ← BaseAttack subclasses (the red team) — 13 implemented, one per check
│   └── _fire.py             shared POST-to-/api/attack/fire helper (FLAGGED on connection error, never fake BLOCKED)
├── corpus/             ← malicious document / payload samples
├── fake_search/        ← lightweight server returning poisoned search results (port 9999)
├── runner/             ← attack_registry.py + satan_runner.py — CLI harness (--compare-governance mode)
├── report/             ← BLOCKED / FLAGGED / PASSED report formatting + governance comparison report
├── config/config.yaml  ← Satan-local config (governance provider, security.shield, docling mode, LLM setup)
├── diagrams/           ← shield_class.puml (PlantUML) + generate.sh → shield_class.png
├── webui/index.html    ← FastAPI-served single-page dashboard (Setup / Penetration Monitor / Results / Architecture / About tabs)
├── app.py              ← FastAPI app — serves webui, /static (diagrams), /api/fire (UI), /api/attack/fire (automation)
├── repent.py           ← the REPENT easter egg (see README.md)
└── run.sh              ← starts fake_search server + uvicorn on :6660, shared venv with k9-aif-framework
```

## The actual pipeline under test

```
DoclingExtractor.enrich()              PRE-SHIELD — populates extracted_fields (naive regex or Docling OCR)
  ↓
DocumentRouter.route()                  extends BaseRouter
  ingress chain: RequestFrequencyCheck → InputSizeCheck → PromptInjectionCheck →
                 FieldAnomalyCheck → MemoryPoisoningCheck
  BLOCK → return immediately, Orchestrator never runs
  ↓ (clean or flagged)
DocumentOrchestrator.execute_flow()     extends BaseOrchestrator
  → DocumentProcessingSquad.execute()   extends BaseSquad
      → DocumentExtractionAgent.execute()  extends BaseAgent — Guardian/Shield pre/post hooks wrap this
      → AuditAgent.execute()               extends BaseAgent — Guardian/Shield pre/post hooks wrap this
  → egress chain: SemanticDriftCheck → ExecutionGuardCheck → PIIBoundaryCheck →
                  ToolArgumentCheck → HardcodedCredentialCheck → ToolAuthorizationCheck →
                  SystemPromptLeakageCheck → OutputSanitizationCheck
  BLOCK → return, response never exits
  ↓ (clean)
OUTPUT — status "completed"; if the payload was malicious, this is a FINDING (both gates missed it)
```

`InputSizeCheck`, `PromptInjectionCheck`, `SemanticDriftCheck`, `PIIBoundaryCheck`, `ToolArgumentCheck`, `ExecutionGuardCheck`, `HardcodedCredentialCheck` are all framework OOB checks (`k9_aif_abb/k9_security/vulnerability/checks/`). `FieldAnomalyCheck`, `MemoryPoisoningCheck`, `ToolAuthorizationCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, `RequestFrequencyCheck` are Satan-local — each extends the same `BaseVulnerabilityCheck` contract, proving a solution can add its own handlers without modifying the framework.

**Defense in depth, three governance options** (`squad.py._make_governance()`, selected via `governance.provider` in config.yaml or Setup → Governance in the webui):
- `noop` (default) — passthrough, dev only
- `guardian` — `GuardianGovernance` (Satan-local): semantic screening via `granite4.1-guardian:8b`, wraps every agent's pre/post hooks. Catches paraphrase/encoding evasion the pattern layer structurally cannot. Guardian unavailability (timeout/HTTP error/unreachable) is never silently "SAFE" — `governance.on_guardian_unavailable` (`fail_closed` default | `fail_open` | `inconclusive`) is an explicit policy decision.
- `shield` — `ShieldGovernance` (**framework OOB**, `k9_aif_abb.k9_security.vulnerability.shield_governance`): the same `VulnerabilityChain`/`BaseVulnerabilityCheck` contracts, wired at the agent pre/post hook instead of Router/Orchestrator. Raises `PermissionError` on BLOCK — `agents.py`'s `_pre()`/`_post()` catch it and normalize to the same `_guardian_blocked` flag `GuardianGovernance` uses, so `execute()` has one enforcement path regardless of which governance backend is active.

Compare what Guardian adds on top of the deterministic checks: `python -m k9x_satan.runner.satan_runner --target <url> --suite full --compare-governance` fires every attack twice (`governance_mode: noop` vs `guardian` via `_governance_override` in the payload, honored per-request by `POST /api/attack/fire` without mutating global server state) and reports which findings Guardian closed.

## ABB vs SBB — who owns what

**Framework ABBs/OOB (do not modify from this repo):**
`BaseRouter`, `BaseOrchestrator`, `BaseSquad`, `BaseAgent`, `BaseGovernance`, `BaseVulnerabilityCheck`, `VulnerabilityChain`, `BaseAttack`, `BaseZeroTrustGuard` (abstract contracts); `InputSizeCheck`, `PromptInjectionCheck`, `SemanticDriftCheck`, `PIIBoundaryCheck`, `ToolArgumentCheck`, `ExecutionGuardCheck`, `HardcodedCredentialCheck`, `ShieldGovernance` (concrete OOB) — all in `k9-aif-framework/k9_aif_abb/`.

**Satan SBBs (this repo):** `DocumentRouter`, `DocumentOrchestrator`, `DocumentProcessingSquad`, `DocumentExtractionAgent`, `AuditAgent`, `GuardianGovernance`, `NoopGovernance`, `FieldAnomalyCheck`, `MemoryPoisoningCheck`, `ToolAuthorizationCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, `RequestFrequencyCheck`, `DoclingExtractor`, plus every class under `attacks/`.

If a new threat vector needs coverage, the new handler is a framework `BaseVulnerabilityCheck` subclass (or a Satan-local one, per the 6 examples above) — never a rewrite of `VulnerabilityChain` or the Router/Orchestrator. Everything added to this project so far — 6 new checks, 11 new attacks, the `ShieldGovernance` wiring — required **zero new framework classes**; it's all SBB extension of existing ABBs.

## sys.path bootstrap pattern

Every `target/*.py` file inserts the framework root before importing `k9_aif_abb`:

```python
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
```

This assumes the fixed layout `ai/k9x-ecosystem/k9x_satan/` sitting alongside `ai/k9-aif-framework/`. Preserve this pattern in any new SBB file that imports from `k9_aif_abb`.

## Adding a new attack

1. Create `attacks/my_attack.py` extending `BaseAttack` — implement `craft_payload()` and `run()`.
2. Add a malicious payload to `corpus/` if it's document-based.
3. Register it in `runner/attack_registry.py` (`ATTACK_REGISTRY` dict).
4. If the target Shield doesn't have a check for this threat class yet, that first run should PASS — add the missing `BaseVulnerabilityCheck` to the framework (or `FieldAnomalyCheck`-style local check), then re-run until BLOCKED.

## Running it

```bash
./run.sh                                                                    # dashboard on :6660, fake_search on :9999
python -m k9x_satan.runner.satan_runner --target http://localhost:6660 --suite full
python -m k9x_satan.runner.satan_runner --target http://localhost:6660 --suite full --compare-governance
```

Shares the `k9-aif-framework/.venv` virtualenv — `run.sh` will error out if that venv doesn't exist yet. Attacks POST JSON to `/api/attack/fire` (distinct from the webui's multipart `/api/fire`) — both call the same `run_pipeline()`.

## Architecture tab & diagrams

`webui/index.html` → Architecture tab is the primary documentation surface for *why* the framework holds — it walks the Zscaler ThreatLabz four-vector mapping, the Phase 0–3 check execution sequence, and the ABB/SBB class hierarchy image.

`diagrams/shield_class.puml` is the PlantUML source for that class diagram. Regenerate with:

```bash
./diagrams/generate.sh
```

**Gotcha:** PlantUML uses the text after `@startuml` as the default output filename. Keep it as a single bare word (`@startuml shield_class`) — a title with spaces or `/` (e.g. `@startuml K9X Shield — ABB / SBB Class Hierarchy`) makes PlantUML create a nested directory instead of `shield_class.png`, and the `<img src="/static/shield_class.png">` in `index.html` will silently fall back to its placeholder.

## Working in this repo — conventions to preserve

- Every new Shield check is a `BaseVulnerabilityCheck` subclass added to the ingress or egress `VulnerabilityChain` in `target/router.py` / `target/orchestrator.py` — never inline conditionals in the Router/Orchestrator.
- Every new attack is a `BaseAttack` subclass registered in `runner/attack_registry.py`, fired via `attacks/_fire.py`'s `fire()` helper — never a one-off script, never a raw `requests.post()` that could let a connection error get misreported as BLOCKED.
- Keep the Router/Orchestrator/Squad/Agent decoupling from the main framework CLAUDE.md: Router only knows Orchestrators, Orchestrator only knows Squads, Squad only knows Agents.
- `NoopGovernance` is the dev-mode default (passthrough). `GuardianGovernance` and `ShieldGovernance` are opt-in via Setup tab / `config.yaml` `governance.provider: guardian|shield`. Guardian requires `ollama pull granite4.1-guardian:8b`.
- Any governance backend that can BLOCK must set `payload["_guardian_blocked"] = True` (or raise `PermissionError`, normalized to that flag by `agents.py`'s `_pre()`) — `execute()` checks this flag and short-circuits before the LLM call. A governance hook that only annotates the payload without either mechanism is decorative, not enforced — this was a real bug here (see git history) and is easy to reintroduce in a new agent.
- Guardian/Shield unavailability is a policy decision (`fail_closed` | `fail_open` | `inconclusive`), never silently mapped to "SAFE"/pass.
- No hardcoded IPs — `DoclingExtractor` and `GuardianGovernance` both resolve endpoints from env vars (`DOCLING_URL`/`DOCLING_PORT`, `OLLAMA_BASE_URL`) with localhost defaults.
- See `/Users/ravinatarajan/ai/k9-aif-framework/CLAUDE.md` for the full K9-AIF architecture (ABB/SBB discipline, factories, governance enforcement rules) — this file only covers what's specific to Satan.
