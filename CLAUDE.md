# CLAUDE.md — K9x Satan

This file guides Claude Code (or any coding assistant) working in `k9x_satan/`. It is self-contained — read it before touching this codebase, even without prior conversation context.

## What this project proves

**K9x Satan exists to demonstrate that zero trust and vulnerability defense are properties of the K9-AIF framework itself — not something each application has to build.**

The framework under test lives at `/Users/ravinatarajan/ai/k9-aif-framework/k9_aif_abb/` (imported here as `k9_aif_abb`). Its `k9_security/` package ships three ABB (Architecture Building Block) contracts:

| ABB | Path | Role |
|---|---|---|
| `BaseVulnerabilityCheck` | `k9_security/vulnerability/base_vulnerability_check.py` | One class of threat, one handler — GoF Chain of Responsibility link |
| `VulnerabilityChain` | `k9_security/vulnerability/vulnerability_chain.py` | Runs checks in order; stops on first BLOCK, continues past FLAG |
| `BaseAttack` | `k9_security/attacks/base_attack.py` | Symmetric offense-side contract — one attack class per threat class |
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

A block at any phase terminates execution — downstream phases never run. Both gates are `VulnerabilityChain` instances assembled from framework `BaseVulnerabilityCheck` subclasses plus one Satan-local subclass. 14 checks total (13 framework OOB, 1 Satan-local) — see the "Complete Check Inventory" table in README.md and the Architecture tab for the full component × threat-class mapping. Five of the thirteen framework OOB checks (`ToolAuthorizationCheck`, `MemoryPoisoningCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, `RequestFrequencyCheck`) were originally proven here as Satan-local checks and were later promoted into the framework itself once verified — see "Harvesting into the framework" below. A sixth, `PIIRequestCheck`, was added directly to the framework (not harvested from a Satan-local check) after a live attack — a "compliance audit" document soliciting full SSN/DOB/account-number disclosure with no literal PII in the payload itself — reached the agent layer uncaught; see `PIIRequestCheck`'s own docstring for the detail on why it belongs at ingress, not egress. Only `FieldAnomalyCheck` remains Satan-local.

Router ingress also runs an optional semantic governance check (Guardian, if `governance.provider: guardian`) — only if the pattern chain above didn't already block, so no LLM call is spent on a payload a regex already caught. This mirrors the same cheap-layer-first, semantic-layer-second ordering Guardian already uses at the agent layer.

## Repo structure

```
k9x_satan/
├── target/            ← the pipeline under test (components extending K9-AIF ABBs)
│   ├── router.py           DocumentRouter(BaseRouter)          — ingress Shield (8 checks) + optional Guardian
│   ├── orchestrator.py     DocumentOrchestrator(BaseOrchestrator) — egress Shield (8 checks; 2 duplicated from ingress)
│   ├── squad.py            DocumentProcessingSquad(BaseSquad) + governance selection (noop|guardian|shield)
│   ├── agents.py           DocumentExtractionAgent, AuditAgent (BaseAgent) — enforce _guardian_blocked
│   ├── field_anomaly_check.py  Satan-local BaseVulnerabilityCheck (1 total — the
│   │                       other 5 that used to live here were promoted into the
│   │                       framework; see "Harvesting into the framework" below)
│   ├── _check_config.py    flattens config.yaml's security:/cache: blocks into the
│   │                       scoped config shape framework OOB checks expect
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
                 FieldAnomalyCheck → MemoryPoisoningCheck →
                 ToolArgumentCheck → ToolAuthorizationCheck → PIIRequestCheck
  BLOCK → return immediately, Orchestrator never runs
  ↓ (clean or flagged)
  optional: Guardian pre_process() — only if the pattern chain above passed
  BLOCK → return immediately, Orchestrator never runs
  ↓ (clean)
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

`ToolArgumentCheck`/`ToolAuthorizationCheck` are deliberately wired at **both** gates, not one or the other. Ingress catches attacker-supplied `tool_name`/`tool_arguments`/`*_backend` fields present in the original payload — before Squad/Agent ever runs, closing the "detected too late" gap that existed when these checks lived at egress only (pre-2026-07 layout). But a real agent can generate a *fresh* tool call mid-execution from LLM output — data that doesn't exist yet at ingress, only visible to egress via `{**payload, **squad_output}`. Same defense-in-depth principle as Guardian (additive over pattern checks, never a replacement) — see `k9-aif-framework/CLAUDE.md`'s Provider Adapter Pattern section for the parallel. In Satan's own harness specifically neither agent (`DocumentExtractionAgent`/`AuditAgent`) generates tool calls, so today the egress copy never fires in practice — it exists for the case a real deployment's agent would hit.

`InputSizeCheck`, `PromptInjectionCheck`, `ToolArgumentCheck`, `SemanticDriftCheck`, `PIIBoundaryCheck`, `ExecutionGuardCheck`, `HardcodedCredentialCheck`, `ToolAuthorizationCheck`, `MemoryPoisoningCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, `RequestFrequencyCheck` are all framework OOB checks (`k9_aif_abb/k9_security/vulnerability/checks/`). Only `FieldAnomalyCheck` is Satan-local — it extends the same `BaseVulnerabilityCheck` contract, proving a solution can add its own handlers without modifying the framework, exactly the way the other five did before they were promoted (see "Harvesting into the framework" below).

**Defense in depth, three governance options** (`squad.py._make_governance()`, selected via `governance.provider` in config.yaml or Setup → Governance in the webui):
- `noop` (default) — passthrough, dev only
- `guardian` — `GuardianGovernance` (Satan-local): semantic screening via `granite4.1-guardian:8b`, wraps every agent's pre/post hooks. Catches paraphrase/encoding evasion the pattern layer structurally cannot. Guardian unavailability (timeout/HTTP error/unreachable) is never silently "SAFE" — `governance.on_guardian_unavailable` (`fail_closed` default | `fail_open` | `inconclusive`) is an explicit policy decision.
- `shield` — `ShieldGovernance` (**framework OOB**, `k9_aif_abb.k9_security.vulnerability.shield_governance`): the same `VulnerabilityChain`/`BaseVulnerabilityCheck` contracts, wired at the agent pre/post hook instead of Router/Orchestrator. Raises `PermissionError` on BLOCK — `agents.py`'s `_pre()`/`_post()` catch it and normalize to the same `_guardian_blocked` flag `GuardianGovernance` uses, so `execute()` has one enforcement path regardless of which governance backend is active.

Compare what Guardian adds on top of the deterministic checks: `python -m k9x_satan.runner.satan_runner --target <url> --suite full --compare-governance` fires every attack twice (`governance_mode: noop` vs `guardian` via `_governance_override` in the payload, honored per-request by `POST /api/attack/fire` without mutating global server state) and reports which findings Guardian closed.

## ABB vs Satan-local — who owns what

**Framework ABBs/OOB (do not modify from this repo):**
`BaseRouter`, `BaseOrchestrator`, `BaseSquad`, `BaseAgent`, `BaseGovernance`, `BaseVulnerabilityCheck`, `VulnerabilityChain`, `BaseAttack`, `BaseZeroTrustGuard` (abstract contracts); `InputSizeCheck`, `PromptInjectionCheck`, `SemanticDriftCheck`, `PIIBoundaryCheck`, `ToolArgumentCheck`, `ExecutionGuardCheck`, `HardcodedCredentialCheck`, `ToolAuthorizationCheck`, `MemoryPoisoningCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, `RequestFrequencyCheck`, `ShieldGovernance` (concrete OOB) — all in `k9-aif-framework/k9_aif_abb/`.

**Satan-local classes (this repo):** `DocumentRouter`, `DocumentOrchestrator`, `DocumentProcessingSquad`, `DocumentExtractionAgent`, `AuditAgent`, `GuardianGovernance`, `NoopGovernance`, `FieldAnomalyCheck`, `DoclingExtractor`, plus every class under `attacks/`.

If a new threat vector needs coverage, the new handler is a framework `BaseVulnerabilityCheck` subclass (or a Satan-local one, like `FieldAnomalyCheck`) — never a rewrite of `VulnerabilityChain` or the Router/Orchestrator. The 6 checks originally added to this project required zero new framework classes at the time; 5 of them (`ToolAuthorizationCheck`, `MemoryPoisoningCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, `RequestFrequencyCheck`) were later harvested into the framework itself once proven here — see "Harvesting into the framework" below. `FieldAnomalyCheck` remains Satan-local; its pattern set is tuned to this project's own insurance-claim test corpus and would misrepresent a worked example as a general framework capability if promoted as-is.

## Harvesting into the framework

Satan is an adversarial test tool built using the framework's ABB classes to attack and validate the framework itself — never described as an SBB in a governed-application sense, and never a place framework-internal logic lives. But a check proven correct here, against a real pipeline under real attack, is exactly the kind of validated capability the framework's own Enterprise Continuum philosophy says should be promoted (a proven pattern generalized and elevated to an OOB ABB-level capability) rather than reinvented per solution. That's what happened to `ToolAuthorizationCheck`, `MemoryPoisoningCheck`, `SystemPromptLeakageCheck`, `OutputSanitizationCheck`, and `RequestFrequencyCheck`: each was built here first, proven via this project's attack suite, then ported into `k9-aif-framework/k9_aif_abb/k9_security/vulnerability/checks/` (generalizing away Satan-specific defaults and flattening config access to match the framework's own convention — see the framework's `k9_security/docs/04-gap-analysis.md`, Gap G8, for the exact changes made during promotion).

The harvesting direction is strictly one-way: proven-here → generalized-into-framework, never framework-internals → Satan-specific behavior. `target/router.py` and `target/orchestrator.py` now import all five from `k9_aif_abb.k9_security.vulnerability.checks` instead of `k9x_satan.target`; `target/_check_config.py` adapts Satan's own `config.yaml` shape (`security:`/`cache:` blocks) into the flat, check-scoped config the framework versions expect.

## sys.path bootstrap pattern

Every `target/*.py` file inserts the framework root before importing `k9_aif_abb`:

```python
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
```

This assumes the fixed layout `ai/k9x-ecosystem/k9x_satan/` sitting alongside `ai/k9-aif-framework/`. Preserve this pattern in any new Satan-local file that imports from `k9_aif_abb`.

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

`webui/index.html` → Architecture tab is the primary documentation surface for *why* the framework holds — it walks the Zscaler ThreatLabz four-vector mapping, the Phase 0–3 check execution sequence, and the ABB/Satan-local class hierarchy image.

`diagrams/shield_class.puml` is the PlantUML source for that class diagram. Regenerate with:

```bash
./diagrams/generate.sh
```

**Gotcha:** PlantUML uses the text after `@startuml` as the default output filename. Keep it as a single bare word (`@startuml shield_class`) — a title with spaces or `/` (e.g. `@startuml K9X Shield Class Hierarchy`) makes PlantUML create a nested directory instead of `shield_class.png`, and the `<img src="/static/shield_class.png">` in `index.html` will silently fall back to its placeholder.

## Working in this repo — conventions to preserve

- Every new Shield check is a `BaseVulnerabilityCheck` subclass added to the ingress or egress `VulnerabilityChain` in `target/router.py` / `target/orchestrator.py` — never inline conditionals in the Router/Orchestrator.
- Every new attack is a `BaseAttack` subclass registered in `runner/attack_registry.py`, fired via `attacks/_fire.py`'s `fire()` helper — never a one-off script, never a raw `requests.post()` that could let a connection error get misreported as BLOCKED.
- Keep the Router/Orchestrator/Squad/Agent decoupling from the main framework CLAUDE.md: Router only knows Orchestrators, Orchestrator only knows Squads, Squad only knows Agents.
- `NoopGovernance` is the dev-mode default (passthrough). `GuardianGovernance` and `ShieldGovernance` are opt-in via Setup tab / `config.yaml` `governance.provider: guardian|shield`. Guardian requires `ollama pull granite4.1-guardian:8b`.
- Any governance backend that can BLOCK must set `payload["_guardian_blocked"] = True` (or raise `PermissionError`, normalized to that flag by `agents.py`'s `_pre()`) — `execute()` checks this flag and short-circuits before the LLM call. A governance hook that only annotates the payload without either mechanism is decorative, not enforced — this was a real bug here (see git history) and is easy to reintroduce in a new agent.
- Guardian/Shield unavailability is a policy decision (`fail_closed` | `fail_open` | `inconclusive`), never silently mapped to "SAFE"/pass.
- No hardcoded IPs — `DoclingExtractor` and `GuardianGovernance` both resolve endpoints from env vars (`DOCLING_URL`/`DOCLING_PORT`, `OLLAMA_BASE_URL`) with localhost defaults.
- See `/Users/ravinatarajan/ai/k9-aif-framework/CLAUDE.md` for the full K9-AIF architecture (ABB/SBB discipline, factories, governance enforcement rules) — this file only covers what's specific to Satan.
