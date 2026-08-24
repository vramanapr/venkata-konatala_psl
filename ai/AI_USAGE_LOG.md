# AI Usage Log

This log records meaningful AI-assisted engineering interactions. Dates are
included when available from the session history. Commit references are marked
as not committed when no commit was created.

## Interaction 1

Date: 2026-08-23 (historical session date unavailable)

Task: Analyze audit log assignment requirements.

Prompt: Analyze the assignment requirements and create a requirements
classification covering functional, non-functional, API, retention, and
redaction requirements without writing code.

AI recommendation: Separate explicit requirements from ambiguities,
engineering assumptions, and out-of-scope items.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The classification established an explicit requirements baseline
without silently filling gaps.

Human validation performed: Requirements document reviewed by the engineer.

Tests performed: None; documentation-only task.

Commit: Not committed.

## Interaction 2

Date: 2026-08-23 (historical session date unavailable)

Task: Expand requirements ambiguity analysis.

Prompt: Review the requirements document and identify every requirement that
needs an engineering decision or clarification, including timestamps,
ordering, concurrency, canonicalization, genesis, retention, redaction,
authentication, authorization, and duplicate events.

AI recommendation: Create a decision and clarification register with options,
trade-offs, implementation impact, and testing impact.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The register made unresolved design choices reviewable before
implementation.

Human validation performed: Decision register reviewed and selected decisions
were later approved.

Tests performed: None; documentation-only task.

Commit: Not committed.

## Interaction 3

Date: 2026-08-23 (historical session date unavailable)

Task: Define the implementation plan.

Prompt: Convert the approved architecture into small, independently
reviewable, dependency-ordered engineering tasks with acceptance criteria,
tests, security considerations, failure cases, and definitions of done.

AI recommendation: Use a dependency-ordered multi-task implementation plan
covering contracts, bootstrap, schema, hashing, append, APIs, verification,
security, retention, redaction, export, recovery, and observability.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted with incremental task selection.

Reason: The plan supported human review and independent commits.

Human validation performed: Engineer selected individual tasks for execution.

Tests performed: None; planning-only task.

Commit: Not committed.

## Interaction 4

Date: 2026-08-23 (historical session date unavailable)

Task: Bootstrap the Spring Boot project.

Prompt: Implement the initial Java 21 Spring Boot, Maven, PostgreSQL, Docker,
configuration, health endpoint, and application-context test foundation without
unrelated functionality.

AI recommendation: Add environment-based database configuration, Actuator,
Docker Compose, test profile, and context tests without hardcoded credentials.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted with review fixes.

Reason: The foundation met the requested runtime and configuration boundary.

Human validation performed: Reviewed configuration and corrected hardcoded
credential handling and test injection issues.

Tests performed: Maven tests and package build passed. Testcontainers tests
were blocked by unavailable Docker.

Commit: Not committed.

## Interaction 5

Date: 2026-08-23 (historical session date unavailable)

Task: Implement the audit schema.

Prompt: Implement the PostgreSQL/Flyway schema needed for append-only audit
records, chain state, idempotency, redaction, retention, archive, and
checkpoint support.

AI recommendation: Use migrations with constraints, indexes, chain-head state,
archive structures, redaction metadata, and restricted public update/delete
privileges.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted with later migration review required.

Reason: The schema supported the core append-only and verification model.

Human validation performed: Reviewed migration structure and noted that
database-owner privileges and archive-table semantics require deployment review.

Tests performed: Compilation and non-container tests passed. Docker integration
tests were unavailable.

Commit: Not committed.

## Interaction 6

Date: 2026-08-23 (historical session date unavailable)

Task: Implement deterministic audit hashing.

Prompt: Implement the audit hash-chain component using SHA-256, deterministic
serialization, a defined genesis value, and tests for event and predecessor
changes.

AI recommendation: Use versioned canonical JSON, UTF-8, sorted object keys,
normalized numbers, deterministic escaping, UTC timestamps, lowercase
hexadecimal SHA-256, and a fixed genesis hash.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The design provides reproducible hashes and independent verification.

Human validation performed: Reviewed canonicalization rules and corrected
test literals and expected digest values.

Tests performed: Hash, canonicalization, golden-vector, and regression tests
passed.

Commit: Not committed.

## Interaction 7

Date: 2026-08-23 (historical session date unavailable)

Task: Make the append path safe for concurrent application instances.

Prompt: Review concurrent audit-log writes, compare database locking, serialized
state, and sequence mechanisms, recommend a production-appropriate approach,
and implement it with concurrency tests.

AI recommendation: Use PostgreSQL as the authority, lock one chain-head row with
`SELECT FOR UPDATE`, and atomically allocate sequence, select predecessor,
insert the record, handle idempotency, and update chain head.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: Database locking is simple, works across instances, and preserves one
deterministic chain order.

Human validation performed: Reviewed trade-offs and requested implementation
of the recommended approach.

Tests performed: Concurrent, rollback, duplicate, and restart-like tests
compiled. Docker integration execution was unavailable.

Commit: Not committed.

## Interaction 8

Date: 2026-08-23 (historical session date unavailable)

Task: Implement Scenario A.

Prompt: Implement the core audit append, query, pagination, filtering, and
verification APIs and associated Scenario A behavior.

AI recommendation: Add append, query, verification endpoints with cursor
pagination, filters, full-chain verification, and tamper detection.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted with cursor-semantics correction.

Reason: The API covered the baseline scenario while preserving immutable chain
ordering.

Human validation performed: Reviewed and corrected `nextSequence` semantics
and chain-head deletion detection.

Tests performed: API/unit/context tests passed. Testcontainers tests required
Docker and were not executed.

Commit: Not committed.

## Interaction 9

Date: 2026-08-23 (historical session date unavailable)

Task: Implement retention and checkpoints.

Prompt: Implement the Scenario B retention requirement and then implement the
low- and medium-complexity retention approaches.

AI recommendation: Support soft archival and archive-table mode, keep archived
records in logical verification, and add durable chain checkpoints as
additional evidence.

Decision: Accepted for the prototype.

Accepted / Modified / Rejected: Accepted with scheduler feature flags.

Reason: The approach preserves logical chain continuity without physical
destruction or external archival infrastructure.

Human validation performed: Reviewed retention design and disabled schedulers
in the test profile to avoid test-context side effects.

Tests performed: Retention and checkpoint unit tests were added; PostgreSQL
integration tests were blocked by unavailable Docker.

Commit: Not committed.

## Interaction 10

Date: 2026-08-23T16:45:12+05:30

Task: Design structured field-level redaction.

Prompt: Compare hash recomputation, immutable commitments, separate integrity
envelopes, cryptographic commitments, and encryption/key destruction, then
recommend an assignment-suitable approach without writing code.

AI recommendation: Use an immutable integrity envelope, separate redacted
presentation payload, per-field salted commitments, and append-only redaction
metadata. Keep encryption and key destruction out of scope.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The design preserves historical chain integrity while allowing
presentation redaction and makes privacy claims explicit.

Human validation performed: Approved the architecture and prototype boundary.

Tests performed: None; design-only task.

Commit: Not committed.

## Interaction 11

Date: 2026-08-23T16:50:49+05:30

Task: Create the redaction design document.

Prompt: Document the approved redaction architecture in
`docs/redaction-design.md`, including data model, commitments, salts,
metadata, state transitions, verification, security, privacy, testing, and
open decisions without modifying code.

AI recommendation: Document decisions, alternatives, reasons, trade-offs,
limitations, and unresolved approvals across 24 sections.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The document established an implementation gate and explicit privacy
boundaries.

Human validation performed: Document reviewed by the engineer.

Tests performed: Formatting check only; no code tests required.

Commit: Not committed.

## Interaction 12

Date: 2026-08-23T16:58:08+05:30

Task: Security review of the redaction design.

Prompt: Review the redaction design as a skeptical senior security engineer,
covering tamper evidence, canonicalization, commitments, salts, idempotency,
concurrency, path manipulation, verification, transactions, privacy leakage,
and proof claims without modifying the document.

AI recommendation: Require explicit canonical path rules, independent
integrity protection for redaction metadata/projection state, database
transaction coordination, and narrower claims after irreversible redaction.

Decision: Accepted as implementation guidance.

Accepted / Modified / Rejected: Accepted.

Reason: The review identified that the chain alone does not protect a mutable
presentation projection or uncommitted redaction metadata.

Human validation performed: High-priority issues were approved for remediation.

Tests performed: None; review-only task.

Commit: Not committed.

## Interaction 13

Date: 2026-08-23T17:01:50+05:30

Task: Clarify integrity terminology.

Prompt: Explain the difference between canonical payload, payload commitment,
field-level commitment, content hash, and previousHash, including lifecycle,
chain participation, and API exposure.

AI recommendation: Treat canonical payload as representation, commitments as
payload/field digests, content hash as the complete chain record digest, and
previousHash as the predecessor link.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The distinction clarified what redaction can and cannot change or
prove.

Human validation performed: Reviewed against the existing implementation.

Tests performed: None; explanatory task.

Commit: Not committed.

## Interaction 14

Date: 2026-08-23T17:01:50+05:30

Task: Implement the redaction prototype.

Prompt: Fix high-priority redaction issues and implement the approved
immutable-envelope, presentation-payload, field-commitment, append-only
metadata, concurrency, idempotency, and verification recommendations.

AI recommendation: Add RFC 6901 paths, random 128-bit salts, presentation
hashes, operation hash chains, transactional locking, idempotency keys, and
separate redaction verification.

Decision: Accepted for the prototype.

Accepted / Modified / Rejected: Accepted with test and migration corrections.

Reason: The implementation preserves historical content hashes while making
redaction state independently checkable.

Human validation performed: Reviewed code and fixed constructor selection,
legacy migration versioning, timestamp precision, JSON Pointer root handling,
and focused test expectations.

Tests performed: Focused redaction, context, API, hashing, and regression tests
passed. Docker integration tests were unavailable.

Commit: Not committed.

## Interaction 15

Date: 2026-08-23T17:12:01+05:30

Task: Design bulk export.

Prompt: Design an independently verifiable audit-log export for actor or
resource selection, including format, metadata, proof, archives, redaction,
versioning, and offline tamper detection without writing code.

AI recommendation: Use a versioned ZIP with canonical JSON, full-prefix chain
proof from genesis, component SHA-256 digests, safe redaction payloads, and
optional digital signatures.

Decision: Accepted as the approved prototype boundary.

Accepted / Modified / Rejected: Accepted.

Reason: Full-prefix proof is the simplest self-contained proof for a linear
chain without external anchors.

Human validation performed: Export boundary and out-of-scope capabilities
were explicitly approved.

Tests performed: None; design-only task.

Commit: Not committed.

## Interaction 16

Date: 2026-08-23T17:15:43+05:30

Task: Create the finalized export design document.

Prompt: Create `docs/export-design.md` covering the approved ZIP format,
manifest, records, proof, redactions, canonicalization, SHA-256, offline
verification, signatures, security, privacy, testing, limitations, and open
decisions without modifying code.

AI recommendation: Specify separate component, chain, redaction, and signature
verification results and state that export completeness and original plaintext
cannot be proved solely by the bundle.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The document prevents the export mechanism from overstating its
integrity, authenticity, completeness, or privacy guarantees.

Human validation performed: Document reviewed by the engineer.

Tests performed: Formatting check only; no code tests required.

Commit: Not committed.

## Interaction 17

Date: 2026-08-23T21:48:27+05:30

Task: Implement the bulk export pipeline and optional digital signature.

Prompt: Implement canonical JSON export, records, manifest, component digests,
full-prefix proof, redaction metadata, offline verification, tests, and
optional digital signature in the specified dependency order.

AI recommendation: Add a versioned ZIP bundle, actor/resource selection,
`SELECTED` and `CHAIN_CONTEXT` records, archive-aware logical-chain export,
SHA-256 digests, offline verification, and optional Ed25519 manifest signing.

Decision: Accepted for the prototype.

Accepted / Modified / Rejected: Accepted.

Reason: The implementation follows the approved export boundary without
external anchoring or production key management.

Human validation performed: Reviewed the generated export classes and test
coverage.

Tests performed: Complete non-container Maven test suite and package build
passed. Docker/Testcontainers tests were unavailable.

Commit: Not committed.

## Interaction 18

Date: 2026-08-23T21:48:27+05:30

Task: Normalize the compliance requirement for regulator auditing.

Prompt: Analyze the requirement that regulators need to audit access to client
account data, identify ambiguities, and provide clarifying questions,
assumptions, a normalized requirement, acceptance criteria, API/data-model
proposals, implementation scope, and exclusions without coding.

AI recommendation: Separate access-event capture, authorization evidence,
identity attribution, report completeness, privacy, retention, and
tamper-evidence claims.

Decision: Accepted as a clarification baseline.

Accepted / Modified / Rejected: Accepted.

Reason: A generic compliance statement cannot be implemented safely without
defining access scope, evidence, retention, and jurisdiction.

Human validation performed: Requirement analysis reviewed; no legal
interpretation was accepted as authoritative.

Tests performed: None; analysis-only task.

Commit: Not committed.

## Interaction 19

Date: 2026-08-24T11:19:47+05:30

Task: Implement actor identity, delegation, authorization evidence, and access
boundaries.

Prompt: Implement authenticated actor identity and delegation, authorization
evidence, audit-record permissions, and database/application/infrastructure
access boundaries.

AI recommendation: Use deny-by-default Spring Security HTTP Basic for the
prototype, environment-configured users/scopes, server-derived principals,
admin-only delegation, hash-bound authorization evidence, and documented
least-privilege database/infrastructure roles.

Decision: Accepted for the prototype.

Accepted / Modified / Rejected: Accepted with deployment-level controls
remaining configuration responsibilities.

Reason: The implementation establishes a local prototype security boundary
without inventing an external identity provider or production key-management
system.

Human validation performed: Reviewed principal attribution, delegation
requirements, endpoint scopes, and least-privilege documentation.

Tests performed: Maven tests and package build passed. Docker/Testcontainers
tests were unavailable.

Commit: Not committed.

## Interaction 20

Date: 2026-08-24T11:19:47+05:30

Task: Create the AI usage log.

Prompt: Create `ai/AI_USAGE_LOG.md` and record the required fields for every
meaningful AI interaction: date, task, prompt, recommendation, decision,
acceptance status, reason, human validation, tests, and commit.

AI recommendation: Maintain a chronological, human-reviewable log of
meaningful AI-assisted decisions and validation results.

Decision: Accepted.

Accepted / Modified / Rejected: Accepted.

Reason: The log provides traceability for AI-assisted engineering work and
separates AI recommendations from human approval.

Human validation performed: The engineer requested and reviewed this log.

Tests performed: Documentation formatting check only.

Commit: Not committed.
