
# K9X SHIELD — SBB CATALOG

# Unit of implementation = SBB. Stages are attachment points, not owners.

# Each SBB implements once, registers at N attachment points.

# 

# ATTACHMENT POINTS:

# RTR  = Router (ingress)

# ORC  = Orchestrator (plan admission)

# SQD  = Squad (collaboration admission)

# AGT_PRE  = Agent pre-execution

# TOOL = Tool invocation

# EXT  = External service call (LLM/MCP/API)

# AGT_POST = Agent post-execution

# MEM  = Memory read/write

# AUD  = Audit/governance emission — NOT a decision point. Nothing can BLOCK
#        here; by the time a Verdict is being emitted for audit, the
#        allow/deny decision has already happened elsewhere. Checks may not
#        list AUD as an attachment point (see FAMILY 6 restructure below).
#        AUD is retained in this list only because Verdict emission is a
#        real event in the pipeline — just not a check attachment.

# 

# RECONCILIATION ROUND 2 — CHANGES FROM ROUND 1:
#
# - attachment -> attachment_default (see below). Round 1 treated the
#   attachment column as fixed ABB law; it is not. BaseRouter/BaseOrchestrator
#   expose _build_ingress_chain()/_build_egress_chain() as abstract — the SBB
#   decides actual wiring. This column now states the RECOMMENDED default.
#   INV-4 is a validation rule evaluated against what an SBB actually wires
#   at build time, not a fixed binding. A row whose implementation wires
#   somewhere else is a documented deviation, not a violation — provided the
#   deviation is declared with a rationale (`deviations:` field on the row).
#   Undocumented deviation = build failure.
#
# - cost -> cost_profile where the cost is backend-conditional (see COST
#   legend). A plain scalar COST value means the cost is fixed regardless of
#   configured backend.
#
# - MATURITY is split into two independent axes: DETERMINISM and COVERAGE
#   (see legend below). The single MATURITY column conflated "does this
#   check produce a reliable verdict" with "does what it checks for cover
#   the threat class" — a check can be fully deterministic and testable
#   while only covering a fraction of the threat surface (e.g. a blocklist).
#   Enforcement is gated on DETERMINISM only (Rule 2, restated below).
#   COVERAGE does not gate enforcement — a partial-coverage deterministic
#   check is exactly what you want blocking.

# 

# ATTACHMENT_DEFAULT: the recommended wiring point(s) for an SBB implementing
#                      this row, evaluated as a documented-deviation check at
#                      build time — not a fixed binding enforced at runtime.

# ENFORCEMENT: BLOCK (fail-closed) | WARN (fail-open, emit) | LOG (record only)

# COST: STATIC (design-time, k9aif inspect — reserved for schema/config-shape
#         validation: does the declared schema/contract at this point parse
#         and type-check, not "does this specific runtime payload conform")
#       CHEAP (<1ms, no I/O)
#       IO (network/disk)
#       MODEL (LLM call)
#       — see cost_profile note above for backend-conditional rows.

# DETERMINISM: DETERMINISTIC (reliable, testable verdict for the inputs it
#                examines) | HEURISTIC (tunable, FP/FN tradeoff) | RESEARCH
#                (no reliable oracle)

# COVERAGE: COMPLETE (the check's input space covers the full threat class)
#             | PARTIAL (covers a subset — e.g. a blocklist; misses novel
#               phrasing/encoding by construction)
#             | UNBOUNDED (threat class itself has no fixed boundary to cover)

# 

# TEST RULE (restated against DETERMINISM, not the old MATURITY):

# DETERMINISTIC -> must have positive + negative + boundary tests. Zero
#                  tolerance for FN within the check's declared COVERAGE
#                  (a PARTIAL-coverage check is not required to catch what
#                  is outside its declared coverage — that gap is what a
#                  HEURISTIC/RESEARCH layer like Guardian exists to close).

# HEURISTIC      -> must have labeled corpus + measured precision/recall.
#                  Assert on thresholds, not booleans.

# RESEARCH       -> must NOT be BLOCK (Rule 2). Test that it emits signal,
#                  not that it is correct.

# =============================================================

# FAMILY 1: INPUT PROTECTION

# =============================================================

IP-01  InputSizeCheck              RTR                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
IP-02  InputSchemaValidationCheck  RTR, TOOL              BLOCK  STATIC  DETERMINISTIC/COMPLETE
IP-03  EncodingNormalizationCheck  RTR                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
IP-04  UnicodeCanonicalizationCheck RTR                   BLOCK  CHEAP   DETERMINISTIC/COMPLETE
IP-05  FileTypeValidationCheck     RTR                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
IP-06  MIMEValidationCheck         RTR                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
IP-07  DocumentStructureCheck      RTR                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
IP-08  MalwareSignatureCheck       RTR                    BLOCK  IO      DETERMINISTIC/PARTIAL
IP-09  VirusScanCheck              RTR                    BLOCK  IO      DETERMINISTIC/PARTIAL
IP-10  HardcodedCredentialCheck    RTR, AGT_PRE           BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       deviations: k9x_satan wires this at ORC (egress), not RTR/AGT_PRE.
       Rationale: Satan's target screens the squad's combined output for
       leaked credentials before it exits the pipeline, not the inbound
       document. Both are legitimate attachment points for this check;
       Satan's choice covers the egress leak surface specifically.
IP-11  PromptInjectionCheck        RTR, AGT_PRE           WARN   CHEAP   HEURISTIC/PARTIAL
       # Round-1 finding 2a: COST column previously read "PARTIAL" — not a
       # valid cost tier (duplicated from the adjacent maturity column by
       # error). Corrected to CHEAP (regex, no I/O, no model call).
       # Round-1 finding (unchanged): the framework OOB implementation
       # enforces BLOCK unconditionally with no WARN path — this row's
       # ENFORCEMENT=WARN does not match shipped code. Flagged, not
       # corrected here — enforcement posture is a product decision, not a
       # catalog typo; corrected only if reconciled against actual intent.
IP-12  IndirectPromptInjectionCheck RTR, EXT, MEM         WARN   CHEAP   HEURISTIC/PARTIAL
IP-13  ContextBoundaryCheck        RTR, ORC               BLOCK  CHEAP   DETERMINISTIC/COMPLETE
IP-14  SensitiveDataClassificationCheck RTR               WARN   CHEAP   HEURISTIC/PARTIAL

# =============================================================

# FAMILY 2: EXECUTION GOVERNANCE

# =============================================================

EG-01  SessionAuthenticationCheck  RTR                    BLOCK  IO      DETERMINISTIC/COMPLETE
EG-02  SessionIntegrityCheck       RTR, ORC               BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-03  TenantIsolationCheck        RTR, MEM               BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-04  RequestFrequencyCheck       RTR                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/PARTIAL
       deviations: k9x_satan's implementation matches this default (RTR,
       BLOCK) exactly. cost_profile applies as declared — this check reads
       CacheFactory-backed state; in_memory (Satan's default) is CHEAP,
       a redis-backed cache.provider makes every call a network round-trip
       (IO). COVERAGE is PARTIAL, not COMPLETE: a fixed request-count budget
       catches sustained floods, not a low-and-slow attack paced under the
       window threshold — same category of gap as any rate limiter.
EG-05  RateLimitCheck              RTR, TOOL, EXT         BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/PARTIAL
       # cost_profile applied on 2e audit — same backend-conditional shape
       # as EG-04 (counter/budget state plausibly cache-backed).
EG-06  AuthorityBoundaryCheck      ORC, SQD, AGT_PRE      BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-07  PrivilegeEscalationCheck    ORC, SQD               BLOCK  CHEAP   DETERMINISTIC/PARTIAL
EG-08  ExecutionGuardCheck         ORC                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       # Round-1 dispute upheld (Step 4): this is a literal-string blocklist
       # for destructive commands — exact match is fully deterministic and
       # testable (DETERMINISTIC), but the blocklist does not enumerate the
       # threat class (whitespace variation, quoting, encoding all evade it)
       # (PARTIAL coverage). Under the corrected Rule 2, DETERMINISTIC may
       # carry BLOCK regardless of coverage — this is exactly the intended
       # shape: a partial-coverage deterministic check IS what you want
       # blocking. No change to enforcement.
EG-09  PlanningLoopLimitCheck      ORC                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-10  InfiniteLoopCheck           ORC                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
EG-11  BudgetConsumptionCheck      ORC, TOOL, EXT         BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
EG-12  TimeWindowCheck             ORC, TOOL              BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-13  HumanApprovalCheck          ORC, SQD               BLOCK  IO      DETERMINISTIC/COMPLETE
EG-14  GovernancePolicyCheck       ORC                    BLOCK  STATIC  DETERMINISTIC/COMPLETE
EG-15  PolicyComplianceCheck       RTR, ORC, AGT_POST     BLOCK  CHEAP   DETERMINISTIC/PARTIAL
EG-16  RoleAssignmentCheck         SQD                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
       # 2b re-audit finding: this row was STATIC in round 1. "Role
       # assignment" at SQD (a runtime collaboration-admission point) is a
       # decision about a SPECIFIC squad execution's agent-to-role binding —
       # it inspects runtime values (which agent, which role, this
       # invocation), not a schema shape. Not a fit for STATIC per the
       # narrowed definition (schema/config-shape validation only).
       # Corrected to CHEAP. This is the second STATIC-on-runtime-value
       # finding beyond TX-03 (see below) — EG-17/23/26 were also audited
       # and are discussed at those rows.
EG-17  DelegationPolicyCheck       SQD                    BLOCK  STATIC  DETERMINISTIC/COMPLETE
       # 2b audit note: matches the "*_PolicyCheck" naming carve-out (kept
       # STATIC per reconciliation instruction), but the same tension as
       # EG-16 applies on inspection — "is THIS delegation, in THIS squad
       # invocation, permitted" reads as a runtime-value decision, not a
       # schema-shape one. Left as STATIC per explicit carve-out; flagged
       # as disputed rather than silently accepted. If DelegationPolicyCheck
       # actually validates that a squad's static delegation *configuration*
       # (YAML) is well-formed at build time — separate from evaluating any
       # specific runtime delegation event — the STATIC label is correct and
       # this note can be dropped. Needs the same human call as EG-23/EG-26.
EG-18  TaskScopeValidationCheck    SQD, AGT_PRE           BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-19  AgentIsolationCheck         SQD                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-20  CrossAgentTrustCheck        SQD                    BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-21  DuplicateExecutionCheck     SQD, TOOL              BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
EG-22  ConsensusValidationCheck    SQD                    WARN   CHEAP   HEURISTIC/PARTIAL
EG-23  EscalationPolicyCheck       SQD, ORC               BLOCK  STATIC  DETERMINISTIC/COMPLETE
       # Same disputed-STATIC note as EG-17 — kept per carve-out, flagged.
EG-24  AgentAuthorizationCheck     AGT_PRE                BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-25  IdentityValidationCheck     AGT_PRE                BLOCK  CHEAP   DETERMINISTIC/COMPLETE
EG-26  ModelPolicyCheck            AGT_PRE, EXT           BLOCK  STATIC  DETERMINISTIC/COMPLETE
       # Same disputed-STATIC note as EG-17 — kept per carve-out, flagged.
EG-27  GoalIntegrityCheck          ORC                    WARN   MODEL   RESEARCH/UNBOUNDED
EG-28  GoalConsistencyCheck        AGT_PRE                WARN   MODEL   RESEARCH/UNBOUNDED
EG-29  ForbiddenPatternCheck (proposed rename — see Step 3 report; ID reserved, not yet assigned)
       Formerly asserted as "SemanticDriftCheck" ORC, AGT_POST / LOG / MODEL
       / RESEARCH. Round-1 finding, upheld and escalated in Step 3: the
       shipped k9x_satan implementation is a zero-LLM-call regex matcher
       (goal-override phrase list + repeated-substring loop-trap detector),
       enforced as BLOCK by default. RESEARCH-tier may never BLOCK (Rule 2)
       — this is a live violation under the old label, not a hypothetical.
       Per Step 3 instruction: EG-29 is NOT retagged to make this disappear.
       EG-29 (SemanticDriftCheck, true semantic/model-based goal-drift
       detection) remains in the catalog as RESEARCH, now formally
       NO_IMPLEMENTATION — nothing in this codebase does that. The regex
       matcher that currently ships under that name needs its own honest
       ID once a name is agreed (see Step 3 report below) — not assigned
       here, pending that decision.

# =============================================================

# FAMILY 3: DATA PROTECTION

# =============================================================

DP-01  PIIBoundaryCheck            RTR, AGT_POST, MEM     BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       deviations: k9x_satan wires this at ORC (egress) only — no RTR, no
       MEM. Rationale: Satan screens the squad's combined output for PII
       crossing the egress boundary; it does not screen inbound documents
       or memory reads for PII. Also note: the framework OOB DEFAULT
       (block_on_match) is False (WARN-equivalent) — Satan explicitly
       overrides to True in DocumentOrchestrator._build_egress_chain(). The
       BLOCK enforcement in this row is true for Satan's deployment, not
       for the framework's shipped default.
DP-02  SecretExposureCheck         AGT_PRE                BLOCK  CHEAP   DETERMINISTIC/PARTIAL
DP-03  SecretLeakageCheck          AGT_POST               BLOCK  CHEAP   DETERMINISTIC/PARTIAL
DP-04  MemoryIntegrityCheck        ORC, AGT_PRE, MEM      BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-05  RecordHashValidationCheck   MEM                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-06  SessionIsolationCheck       MEM                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-07  CrossTenantIsolationCheck   MEM                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-08  CrossSessionLeakCheck       ORC, MEM               BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/PARTIAL
DP-09  WriterAuthorizationCheck    MEM                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-10  ReplayAttackCheck           MEM, TOOL              BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-11  VersionConsistencyCheck     MEM                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-12  MemoryTTLCheck              MEM                    BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-13  ProvenanceValidationCheck   MEM, EXT               BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/PARTIAL
DP-14  RetrievalProvenanceCheck    EXT, MEM               BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/PARTIAL
DP-15  CacheIntegrityCheck         AGT_PRE                BLOCK  cost_profile: {default: CHEAP, redis: IO}   DETERMINISTIC/COMPLETE
DP-16  CacheAnomalyPatternCheck (proposed rename — see Step 3 report; ID reserved, not yet assigned)
       Formerly asserted as "MemoryPoisoningCheck" MEM / WARN / MODEL /
       RESEARCH. Same finding as EG-29: the shipped k9x_satan implementation
       (target/memory_poisoning_check.py) is zero-LLM-call — a
       CacheFactory-backed session-fact fingerprint comparison plus a
       regex phrase-list for "claims a prior session state" language.
       Enforced as BLOCK by default. Same live Rule-2 violation under the
       old label. DP-16 (MemoryPoisoningCheck, true semantic memory/context
       poisoning detection) remains RESEARCH, now formally
       NO_IMPLEMENTATION. The regex+cache-fingerprint checker needs its own
       honest ID (see Step 3 report) — not assigned here.
DP-17  ContextPoisoningCheck       ORC, MEM               WARN   cost_profile: {default: CHEAP, redis: IO}   RESEARCH/UNBOUNDED
DP-18  ContextMergeValidationCheck SQD                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL

# =============================================================

# FAMILY 4: TOOL & EXTERNAL SURFACE

# =============================================================

TX-01  ToolAuthorizationCheck      AGT_PRE, TOOL          BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       deviations: k9x_satan wires this at ORC (egress), not AGT_PRE/TOOL.
       Rationale: Satan's target has no distinct TOOL-invocation attachment
       point at all — tool identity/backend checks run in the same egress
       VulnerabilityChain as everything else. COVERAGE is PARTIAL: an
       allowlist covers exactly the tools/backends enumerated, nothing
       else — same shape as any allowlist.
       # Step 1 security fix applied (independent of this reconciliation):
       # the backend-allowlist match was substring containment
       # (`approved in host`), which let "evil-localhost.attacker.com"
       # through on the strength of containing "localhost". Fixed to exact
       # match or dot-boundary suffix match; regression tests added
       # (tests/test_tool_authorization_check.py, 17 cases: exact,
       # dot-suffix, substring-attack, prefix-attack, case variation, port
       # variation, IDN/punycode, IP literal).
TX-02  ToolAvailabilityCheck       AGT_PRE                BLOCK  IO      DETERMINISTIC/COMPLETE
TX-03  ToolArgumentCheck           TOOL                   BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       # Round-1 finding 2b, corrected: COST was STATIC, asserted on a
       # runtime attachment point (TOOL) — this check inspects the actual
       # tool_arguments payload value via regex on every call; it cannot
       # run at design time. This directly contradicted the catalog's own
       # Rule 3 ("STATIC on a runtime attachment point is a build
       # failure"). Corrected to CHEAP. STATIC is now reserved for
       # schema/config-shape validation only (IP-02, TX-04, and the
       # *_PolicyCheck rows — EG-14/17/23/26, with EG-17/23/26 flagged as
       # disputed on inspection, see those rows).
       # Note: the shipped ToolArgumentCheck (framework OOB) internally
       # bundles four distinct pattern classes — SQL injection, command
       # injection, path traversal, SSRF — that this catalog's own
       # preamble ("Unit of implementation = SBB... each SBB implements
       # once") would treat as four separate rows (TX-05/06/07/08 below).
       # They exist only as unexposed internal branches of this one class,
       # not as independent SBBs. Flagged as a Unit-of-implementation
       # deviation, not corrected here — collapsing categories into one
       # class may be the right call operationally; it's inconsistent with
       # the catalog's stated unit-of-implementation rule as written.
TX-04  ParameterSchemaValidationCheck TOOL                BLOCK  STATIC  DETERMINISTIC/COMPLETE
TX-05  SQLInjectionCheck           TOOL                   BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-06  CommandInjectionCheck       TOOL                   BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-07  PathTraversalCheck          TOOL                   BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-08  SSRFCheck                   TOOL, EXT              BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-09  URLAllowlistCheck           TOOL, EXT              BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-10  EndpointAllowlistCheck      EXT                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-11  OutputSizeBudgetCheck       TOOL, EXT              BLOCK  CHEAP   DETERMINISTIC/COMPLETE
TX-12  MCPServerIdentityCheck      TOOL, EXT              BLOCK  IO      DETERMINISTIC/COMPLETE
TX-13  ConnectorAuthorizationCheck TOOL                   BLOCK  CHEAP   DETERMINISTIC/COMPLETE
TX-14  ProviderIdentityCheck       EXT                    BLOCK  IO      DETERMINISTIC/COMPLETE
TX-15  TLSValidationCheck          EXT                    BLOCK  IO      DETERMINISTIC/COMPLETE
TX-16  CertificateValidationCheck  EXT                    BLOCK  IO      DETERMINISTIC/COMPLETE
TX-17  APIKeyProtectionCheck       EXT                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-18  ResponseIntegrityCheck      EXT                    BLOCK  CHEAP   DETERMINISTIC/PARTIAL
TX-19  SupplyChainValidationCheck  EXT                    BLOCK  STATIC  DETERMINISTIC/PARTIAL
       # 2b audit note: plausibly a legitimate STATIC fit (dependency/
       # package manifest provenance checked at build/deploy time, not
       # per-request) — but EXT is defined as a runtime attachment point
       # in this same taxonomy, so it carries the identical Rule-3 tension
       # as every other STATIC row. Flagged, not corrected — see the
       # taxonomy-level open question noted after Rule 3, below.
TX-20  ModelProvenanceCheck        EXT                    BLOCK  STATIC  DETERMINISTIC/COMPLETE
       # Same taxonomy-level flag as TX-19.

# =============================================================

# FAMILY 5: OUTPUT PROTECTION

# =============================================================

OP-01  OutputSanitizationCheck     AGT_POST               BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       deviations: k9x_satan wires this at ORC (egress-as-post-agent-gate),
       not a distinct AGT_POST hook — Satan's target has no separate
       per-agent post-execution attachment point; egress runs once after
       the whole squad completes.
       # Round-1 dispute upheld (Step 4): literal markup/script pattern
       # list — DETERMINISTIC (exact regex match, testable), PARTIAL
       # coverage (HTML-entity encoding, unicode homoglyphs evade it by
       # construction). Enforcement unaffected by the corrected Rule 2 —
       # DETERMINISTIC may BLOCK regardless of coverage.
OP-02  SystemPromptLeakageCheck    AGT_POST               BLOCK  CHEAP   DETERMINISTIC/PARTIAL
       deviations: same as OP-01 — wired at ORC, not a distinct AGT_POST
       hook.
       # Round-1 dispute upheld (Step 4), and self-documented in this
       # codebase: guardian_governance.py's own docstring states Guardian
       # exists specifically to catch "paraphrase/encoding evasion" of
       # pattern checks like this one. DETERMINISTIC/PARTIAL is the honest
       # classification — not a demotion, a decomposition. The blocklist's
       # exactness is real (DETERMINISTIC) and its incompleteness is also
       # real (PARTIAL); both were true simultaneously under the old single
       # MATURITY=SOLVED label, which could only express one of them.
OP-03  SensitiveInformationDisclosureCheck AGT_POST       BLOCK  CHEAP   HEURISTIC/PARTIAL
OP-04  JailbreakResponseCheck      AGT_POST               WARN   CHEAP   HEURISTIC/PARTIAL
OP-05  ToxicContentCheck           AGT_POST               WARN   MODEL   HEURISTIC/PARTIAL
OP-06  CitationValidationCheck     AGT_POST               WARN   IO      HEURISTIC/PARTIAL
OP-07  HallucinationRiskCheck      AGT_POST               LOG    MODEL   RESEARCH/UNBOUNDED
OP-08  ConfidenceThresholdCheck    AGT_POST               WARN   CHEAP   HEURISTIC/PARTIAL

# =============================================================

# FAMILY 6: GOVERNANCE & AUDIT  —  RESTRUCTURED (2c)

# =============================================================

# Round-1 finding upheld: AUD is an emission sink, not a decision point.
# "Block at the audit-emission point" is incoherent — nothing can be
# blocked after the fact. All 13 round-1 rows asserted enforcement at AUD;
# that column was decorative for every one of them. Restructured below:
# 8 rows were never checks — they're structural requirements on the
# Verdict/audit record itself. 5 rows are real checks whose *decision*
# happens elsewhere (ORC/AGT_POST/RTR) and are merely *recorded* to AUD —
# AUD removed from their attachment_default; the decision-point attachment
# retained or assigned where the round-1 row had none.
#
# Net: Family 6 shrinks from 13 rows to 5.

## Verdict schema invariants (not checks — required fields on every Verdict)

# Formerly GA-01 CorrelationIdCheck, GA-05 PolicyVersionCheck,
# GA-06 NonRepudiationCheck, GA-07 DigitalSignatureCheck.
# These describe properties every Verdict must carry at construction time
# (correlation_id, policy_version, a non-repudiable actor identity, a
# signature), not independent runtime checks with their own enforcement
# verb. Enforcement is "the Verdict constructor rejects an incomplete
# Verdict" — a schema invariant, not a BLOCK/WARN/LOG decision about
# payload content. Moved out of the check catalog entirely.

INV-CORR   Verdict.correlation_id is required, non-empty.
INV-POLVER Verdict.policy_version is required, matches an active policy version.
INV-NOREPU Verdict.actor_identity is required, non-repudiable (see INV-SIG).
INV-SIG    Verdict carries a digital signature over its immutable fields.

## Framework guarantees (not checks — INV-7, delivered by the framework itself)

# Formerly GA-02 AuditTrailCheck, GA-03 EvidenceCaptureCheck,
# GA-04 DecisionTraceCheck, GA-08 ComplianceLoggingCheck.
# These describe things the FRAMEWORK guarantees happen for every Verdict
# (an audit trail exists, evidence is captured, the decision trace is
# recorded, logging is compliant) — not a per-request check with a
# pass/fail verdict of its own. Moved out of the check catalog; expressed
# as framework invariant INV-7: "every Verdict emission is durably
# recorded with its evidence and decision trace, in compliance-loggable
# form, before the pipeline returns." Rule 6 (below) already states the
# behavioral requirement this backs — INV-7 is its formal name.

## Real checks (enforcement is coherent — decision happens at the listed point, recorded to AUD after)

GA-09  ExplainabilityCheck         ORC, AGT_POST          WARN   CHEAP   HEURISTIC/PARTIAL
       # attachment_default assigned here — round 1 listed AUD only, which
       # after the restructure is not a valid attachment for a check.
       # Explainability is naturally produced wherever a BLOCK/WARN
       # decision is made, so: ORC, AGT_POST.
GA-10  RiskScoringCheck            ORC, AGT_POST          WARN   CHEAP   HEURISTIC/PARTIAL
       # AUD removed from attachment_default (round 1: ORC, AGT_POST, AUD).
GA-11  ThreatIntelligenceCheck     RTR, EXT               WARN   IO      HEURISTIC/PARTIAL
       # Unchanged — round 1 never listed AUD here.
GA-12  BehavioralAnomalyCheck      ORC, AGT_POST          LOG    MODEL   RESEARCH/UNBOUNDED
       # AUD removed from attachment_default (round 1: ORC, AGT_POST, AUD).
GA-13  GuardianSemanticCheck       RTR, ORC, SQD, AGT_PRE, AGT_POST, MEM
                                                          WARN   MODEL   RESEARCH/UNBOUNDED
       # Unchanged — round 1 never listed AUD here. This is the closest
       # catalog entry to k9x_satan's actual GuardianGovernance, which
       # currently wires at AGT_PRE/AGT_POST only (pre/post hooks on
       # DocumentExtractionAgent, AuditAgent) — RTR/ORC/SQD/MEM attachment
       # is aspirational relative to the shipped implementation.

TASK for Implementation:

Every SBB implements a single interface:

```
class ShieldCheck(SBB):
        id: str                    # e.g. "IP-11"
        family: Family
        enforcement: BLOCK | WARN | LOG
        cost: STATIC | CHEAP | IO | MODEL | cost_profile: dict[str, Cost]
        determinism: DETERMINISTIC | HEURISTIC | RESEARCH
        coverage: COMPLETE | PARTIAL | UNBOUNDED
        attachment_default: frozenset[AttachmentPoint]
        deviations: list[Deviation]   # optional — (attachment, rationale) pairs
```

```
def evaluate(self, ctx: ShieldContext) -> Verdict: ...
```

Verdict carries: passed, confidence, evidence[], correlation_id, sbb_id, policy_version, actor_identity, signature (see Verdict schema invariants above).

RULES — enforce these in the framework, not per-check:

1. An SBB is instantiated ONCE and registered at each attachment point.
   Duplicate implementations of the same id are a build failure.
   (Audit note: ToolArgumentCheck bundles TX-05/06/07/08's detection logic
   into one class rather than four SBBs — see TX-03 row. Whether that is a
   Rule 1 violation or a legitimate single-SBB-multiple-pattern-class
   design depends on whether "unit of implementation" is meant at the
   check-class granularity or the threat-class granularity. Not resolved
   here — flagged for the same human decision as the STATIC carve-outs.)
2. determinism=RESEARCH may never have enforcement=BLOCK. Assert at
   registration. COVERAGE does NOT gate enforcement — a PARTIAL-coverage
   DETERMINISTIC check is exactly what you want blocking.
3. cost=STATIC checks run in `k9aif inspect` at design time. If a STATIC
   check is registered on a runtime attachment point, it is a build
   failure.
   OPEN QUESTION (not resolved by this reconciliation): every attachment
   point in this taxonomy (RTR/ORC/SQD/AGT_PRE/TOOL/EXT/AGT_POST/MEM) is,
   by its own definition, a runtime hook — there is no design-time/BUILD
   attachment point in the taxonomy at all. As written, Rule 3 makes
   EVERY STATIC row (IP-02, TX-04, EG-14/17/23/26, TX-19/20) a violation,
   not just the corrected TX-03/EG-16. Two ways to resolve, neither
   applied here without a human call: (a) add a design-time attachment
   point (e.g. BUILD) that STATIC checks bind to instead of a runtime
   point, or (b) reinterpret a STATIC row's attachment_default as "the
   runtime point whose config/schema this check validates the SHAPE of at
   build time" rather than "where this check executes" — which matches
   how IP-02/TX-04/EG-14 are actually described, but is not what the
   literal text of Rule 3 says today.
4. cost=MODEL checks are sampled, never inline-blocking on the hot path.
5. Ordering at any attachment point: CHEAP -> IO -> MODEL. Short-circuit on
   first BLOCK verdict. Framework enforces ordering; checks do not self-order.
6. Every Verdict emits to AUD regardless of outcome. No silent passes.
   (Formalized as INV-7 — see Framework guarantees, above.)
