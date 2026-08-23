# Audit Log Service Requirements Analysis

## Source and scope

This analysis is based on `Interview_Assignment_Audit_Log_Service.pdf` in the
repository. It distinguishes behavior required of the service from assignment
deliverables and engineering choices that the assignment leaves open.

The assignment describes three scenarios:

- **Scenario A:** Greenfield core audit log service.
- **Scenario B:** Retention, structured redaction, and bulk export extensions.
- **Scenario C:** Ambiguous compliance reporting.

Scenario A is the clearest baseline. Scenarios B and C are extensions that
should be implemented or explicitly bounded and justified in the submission.

## 1. Functional requirements

| ID | Requirement | Classification |
| --- | --- | --- |
| F-01 | Accept an audit event through a write API. | Explicitly required |
| F-02 | An event contains at least `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, and `timestamp`. | Explicitly required |
| F-03 | `eventType` identifies what happened, such as `USER_LOGIN`, `RECORD_UPDATED`, or `PERMISSION_GRANTED`. | Explicitly required |
| F-04 | `actorId` identifies the actor or system that caused the event. | Explicitly required |
| F-05 | `resourceType` and `resourceId` identify the affected resource. | Explicitly required |
| F-06 | `payload` is a structured object containing event-specific details. | Explicitly required |
| F-07 | The timestamp may be caller-supplied or server-assigned, but the choice must be documented. | Explicitly required |
| F-08 | Records are append-only. | Explicitly required |
| F-09 | The public API must not expose update or delete operations for records. | Explicitly required |
| F-10 | Retrieve events through a query API. | Explicitly required |
| F-11 | Query filtering supports any combination of `actorId`, `resourceType` plus `resourceId`, `eventType`, and a time range (`from`/`to`). | Explicitly required |
| F-12 | Query results support pagination for large result sets. | Explicitly required |
| F-13 | Each stored record includes a hash of its event content. | Explicitly required |
| F-14 | Each stored record includes a hash of the immediately preceding record, or a defined genesis value for the first record. | Explicitly required |
| F-15 | The hashes form a chain such that tampering with a past record invalidates that record and every following record. | Explicitly required |
| F-16 | `GET /audit/verify` walks the full chain and reports whether it is intact. | Explicitly required |
| F-17 | If verification fails, report the first inconsistent record and the type of violation detected. | Explicitly required |
| F-18 | The service must support an end-to-end flow of writing events, querying them, verifying the chain, modifying a record directly in storage, and verifying again to detect the modification. | Explicitly required |
| F-19 | Records older than a configurable retention window can be archived or soft-deleted. | Explicitly required for Scenario B |
| F-20 | Chain verification handles legitimately archived records without reporting a false break. | Explicitly required for Scenario B |
| F-21 | Certain fields inside a payload can be structurally redacted for privacy. | Explicitly required for Scenario B |
| F-22 | Redaction preserves tamper evidence while removing or protecting the sensitive value. | Explicitly required for Scenario B |
| F-23 | Export all records for a specified `resourceId` or `actorId`. | Explicitly required for Scenario B |
| F-24 | An export is a self-contained, verifiable bundle with sufficient chain metadata for independent verification after export. | Explicitly required for Scenario B |
| F-25 | Clarify, normalize, design, and scope the intentionally ambiguous compliance-reporting requirement before implementation. | Explicitly required for Scenario C |
| F-26 | Record the clarified compliance requirement, assumptions or questions, resulting design decisions, and implementation boundary. | Explicitly required for Scenario C |
| F-27 | The compliance statement concerns regulators auditing access to client account data. | Explicitly required as the scenario prompt; the detailed behavior is ambiguous |

### Functional ambiguities

- The event identifier, record identifier, and ordering key are not specified.
- The required validation rules, allowed values, maximum sizes, and nullability of
  fields are not specified.
- The behavior for duplicate submissions and retries is not specified.
- The ordering basis for the chain is not specified, including concurrent writes.
- The hash algorithm, canonical serialization, encoding, and representation are
  not specified.
- The persistence transaction and concurrency guarantees are not specified.
- The exact verification response schema and violation categories are not
  specified.
- It is not specified whether query results include archived or soft-deleted
  records.
- Retention semantics are open: archive versus soft-delete, restoration,
  physical deletion, operational scheduling, and treatment of archived data are
  not defined.
- Redaction authorization, allowed paths, reversibility, auditability, and
  whether redaction is itself an event are not defined.
- Export format, authentication, authorization, integrity boundary, and
  handling of filtered-out chain records are not defined.
- Scenario C does not define which account-access events are required, who may
  query them, reporting formats, time ranges, retention, or regulator
  workflows.

## 2. Non-functional requirements

| ID | Requirement | Classification |
| --- | --- | --- |
| NF-01 | The prototype should be runnable end-to-end with setup instructions. | Explicitly required |
| NF-02 | The outcome should be production-quality, clean, and maintainable. | Explicitly required |
| NF-03 | The design must explain components, data model, API design, key decisions, trade-offs, hash algorithm, and chain design. | Explicitly required |
| NF-04 | Testing and validation must cover the implemented behavior and document limitations and trade-offs. | Explicitly required |
| NF-05 | Risks, failure scenarios, validation, and safety guardrails must be identified. | Explicitly required |
| NF-06 | Security and production readiness must be considered. | Explicitly required |
| NF-07 | Engineer-led execution and human sign-off are required for high-impact changes. | Explicitly required for the assignment process |
| NF-08 | AI usage must be traceable, including accepted, edited, or rejected output and rationale. | Explicitly required for the assignment process |
| NF-09 | The engineer retains ownership of correctness, maintainability, and production readiness. | Explicitly required for the assignment process |
| NF-10 | The service must make unauthorized modification or deletion detectable. | Explicitly required |
| NF-11 | Availability, latency, throughput, scalability, recovery point objective, recovery time objective, and consistency targets are specified. | Ambiguous |
| NF-12 | Authentication, authorization, encryption, key management, and audit-log access controls are specified. | Ambiguous |
| NF-13 | The service is required to provide confidentiality of payload data beyond the redaction scenario. | Ambiguous |
| NF-14 | Multi-instance deployment, cross-region behavior, and disaster recovery are required. | Out of scope |
| NF-15 | A specific operational observability stack, service-level objective, or deployment platform is required. | Out of scope |

## 5. API requirements

| ID | Requirement | Classification |
| --- | --- | --- |
| API-01 | Provide a write endpoint for event records. | Explicitly required |
| API-02 | Provide a query endpoint for event retrieval. | Explicitly required |
| API-03 | Query filtering accepts any combination of the listed actor, resource, event-type, and time-range filters. | Explicitly required |
| API-04 | Query supports pagination. | Explicitly required |
| API-05 | Do not expose update or delete endpoints for audit records. | Explicitly required |
| API-06 | Provide `GET /audit/verify`. | Explicitly required |
| API-07 | Verification reports intact/broken status and, on failure, the first inconsistent record and violation type. | Explicitly required |
| API-08 | Provide an export endpoint for records selected by `resourceId` or `actorId`. | Explicitly required for Scenario B |
| API-09 | The export response is independently verifiable and includes required chain metadata. | Explicitly required for Scenario B |
| API-10 | Endpoint paths other than `/audit/verify`, HTTP methods for write/query/export, request and response schemas, status codes, error format, authentication, authorization, rate limits, and versioning are specified. | Ambiguous |
| API-11 | A redaction endpoint or command and its authorization model are specified. | Ambiguous |
| API-12 | A separate public API for retention/archive administration is required. | Out of scope |
| API-13 | An external application or consumer integration is required. | Out of scope |

## 6. Retention requirements

| ID | Requirement | Classification |
| --- | --- | --- |
| RET-01 | Support a configurable retention window. | Explicitly required for Scenario B |
| RET-02 | Records older than the window may be archived or soft-deleted. | Explicitly required for Scenario B |
| RET-03 | Verification must account for records archived according to policy without a false-positive chain break. | Explicitly required for Scenario B |
| RET-04 | The retention duration, configuration mechanism, enforcement schedule, archive location, soft-delete representation, restoration behavior, and permanent deletion policy are specified. | Ambiguous |
| RET-05 | Whether archived records remain queryable, exportable, and included in compliance reports is specified. | Ambiguous |
| RET-06 | Destruction of records is required independent of the permitted archive/soft-delete behavior. | Out of scope |
| RET-07 | Legal or regulatory retention periods and jurisdiction-specific requirements are provided. | Out of scope |

## 7. Redaction requirements

| ID | Requirement | Classification |
| --- | --- | --- |
| RED-01 | Support structured redaction of selected fields within an event payload. | Explicitly required for Scenario B |
| RED-02 | Redaction addresses sensitive data such as account numbers or personal identifiers. | Explicitly required for Scenario B |
| RED-03 | Redaction must not break the hash chain or eliminate the ability to detect unauthorized tampering. | Explicitly required for Scenario B |
| RED-04 | The redaction design, trade-offs, and limitations must be documented. | Explicitly required for Scenario B |
| RED-05 | The exact field-path syntax, supported data types, whether arrays are supported, and whether partial or whole-object redaction is required are specified. | Ambiguous |
| RED-06 | The redaction actor, authorization, approval, timing, reason, audit trail, idempotency, and reversibility are specified. | Ambiguous |
| RED-07 | The privacy objective and threat model are specified, including whether hashes, commitments, salts, or encrypted backups may retain evidence about the original value. | Ambiguous |
| RED-08 | A specific cryptographic redaction scheme, key-management system, or external privacy service is mandated. | Out of scope |
| RED-09 | Arbitrary mutation of non-sensitive event fields after append is permitted. | Out of scope |

## Explicit engineering assumptions requiring approval

The following are not assignment requirements and must be treated as decisions
for review rather than hidden defaults:

1. A deterministic canonical representation is needed before hashing.
2. A specific cryptographic hash algorithm and encoding must be selected.
3. A total ordering and concurrency strategy must be selected for append
   operations.
4. Timestamp ownership (server-assigned, caller-supplied, or both with separate
   meanings) must be selected.
5. The persistence model must define how append-only behavior is protected from
   ordinary API callers and how direct datastore mutation remains detectable.
6. Retention and redaction need an explicit chain model: whether they create
   successor records, preserve historical commitments, or use another
   verifiable representation.
7. API authentication and authorization should be added if the prototype is
   treated as more than a local demonstration, although the assignment does not
   define an identity provider or policy.

These decisions should be recorded with their rationale before implementation
and should not be presented as requirements originating from the assignment.

## Engineering decision and clarification register

The following register expands every ambiguity identified above. No option is
treated as selected until it is approved and documented as an engineering
decision.

### D-01: Timestamp ownership and meaning

- **Requirement:** Each event has a `timestamp`; it may be caller-supplied or
  server-assigned.
- **Why it is ambiguous:** The source of time, trust model, precision, time
  zone, and whether the timestamp controls query order or chain order are not
  defined.
- **Possible interpretations:** Accept only a trusted server timestamp; accept
  a caller event time and record a separate ingestion time; or allow either
  with explicit provenance.
- **Options:** Server-assigned UTC time; caller-supplied UTC time; or both
  `occurredAt` and immutable server `recordedAt`.
- **Trade-offs:** Server time is consistent and harder to forge but may not
  represent when the event occurred. Caller time preserves business context but
  is untrusted and can be outside normal ranges. Two timestamps preserve both
  meanings but increase schema and query complexity.
- **Impact on implementation:** Defines request validation, stored columns,
  hash inputs, ordering, clock handling, and query semantics.
- **Impact on testing:** Requires tests for missing, malformed, future, old,
  different-offset, precision-boundary, and conflicting timestamps, plus
  assertions about ordering and hash stability.

### D-02: Record identity

- **Requirement:** Records are stored and verification reports the first
  inconsistent record.
- **Why it is ambiguous:** No event ID, record ID, uniqueness rule, or
  externally visible identifier is specified.
- **Possible interpretations:** Generate an ID per append; use a client
  idempotency key as the ID; or identify records only by sequence position.
- **Options:** UUID; database-generated numeric ID; immutable sequence number;
  or a separate UUID plus sequence number.
- **Trade-offs:** UUIDs are safe to generate across instances but do not
  naturally order records. Numeric sequences are compact and ordered but
  require coordination. A client key supports retries but must handle reuse and
  conflicts.
- **Impact on implementation:** Affects primary keys, API responses, indexes,
  verification diagnostics, and export references.
- **Impact on testing:** Requires uniqueness, collision, malformed ID,
  retry/conflict, ordering, and first-failure reporting tests.

### D-03: Chain ordering and concurrent writes

- **Requirement:** Each record references the immediately preceding record.
- **Why it is ambiguous:** The assignment does not define the total order,
  behavior when writes overlap, or whether multiple chains are allowed.
- **Possible interpretations:** Order by server sequence, database commit order,
  request arrival, caller timestamp, or permit independent partitions.
- **Options:** Serialize all appends through one sequence; use a database
  sequence and transaction; create per-resource or per-tenant chains; or use a
  branching structure with a later merge.
- **Trade-offs:** A single chain is simple to verify but limits write
  concurrency. Partitioned chains scale better but require multiple verification
  scopes and complicate exports. Caller-time ordering is meaningful to users
  but cannot reliably determine commit order.
- **Impact on implementation:** Determines locking/transaction strategy,
  sequence storage, indexes, verification traversal, and whether a record can
  be accepted when another append is in progress.
- **Impact on testing:** Requires concurrent append tests, deterministic
  predecessor assertions, rollback/failure tests, and verification tests under
  contention.

### D-04: Duplicate events and retries

- **Requirement:** The service accepts event records, but duplicate behavior is
  not defined.
- **Why it is ambiguous:** Network retries can submit the same logical event
  more than once, and the assignment does not say whether that is valid or
  erroneous.
- **Possible interpretations:** Every accepted request is a distinct audit
  record; retries are deduplicated; or duplicates are accepted only when they
  have distinct client identities.
- **Options:** No idempotency support; require an idempotency key with replay
  of the original response; detect duplicates from a content digest; or reject
  exact duplicates.
- **Trade-offs:** Append-everything preserves an exact request history but can
  pollute business audit results. Idempotency improves retry safety but adds
  storage, expiration, and conflict rules. Content matching can incorrectly
  collapse legitimate repeated events.
- **Impact on implementation:** Defines request headers/fields, uniqueness
  constraints, replay behavior, conflict responses, and hash-chain insertion.
- **Impact on testing:** Requires repeated requests, same key with different
  payloads, concurrent retries, expired keys, and response replay tests.

### D-05: Payload validation and limits

- **Requirement:** The payload is a structured object and the other fields are
  required at minimum.
- **Why it is ambiguous:** Nullability, formats, allowed values, maximum sizes,
  nesting, unknown fields, and error behavior are unspecified.
- **Possible interpretations:** Accept any JSON object; enforce a small common
  schema; or validate event-specific schemas.
- **Options:** Minimal type/presence validation; configurable limits and
  reserved-field validation; or a schema registry per `eventType`.
- **Trade-offs:** Minimal validation is flexible but increases malformed-data
  risk. Strong validation improves quality but couples producers to schema
  evolution and adds maintenance.
- **Impact on implementation:** Affects DTOs, canonicalization, database
  storage, request limits, error responses, and indexes.
- **Impact on testing:** Requires boundary, malformed JSON, nested object,
  oversized payload, unknown field, and event-type validation tests.

### D-06: Hash algorithm, canonicalization, and encoding

- **Requirement:** Store a hash of event content and a hash of the preceding
  record.
- **Why it is ambiguous:** Algorithm, exact input fields, field ordering,
  number/date representation, omission/null rules, Unicode normalization,
  delimiters, and output encoding are not specified.
- **Possible interpretations:** Hash serialized JSON; hash a canonical
  normalized representation; or hash a versioned binary envelope.
- **Options:** Versioned canonical JSON plus SHA-256; SHA-512/256; or a
  canonical binary format with a cryptographic digest.
- **Trade-offs:** Canonical JSON is inspectable and convenient but requires
  strict normalization. Binary formats can be precise and compact but are less
  accessible. A stronger algorithm may increase interoperability or policy
  confidence but does not fix ambiguous input construction.
- **Impact on implementation:** Defines a shared immutable hashing component,
  schema versioning, storage encoding, migration strategy, and redaction
  representation.
- **Impact on testing:** Requires golden digest vectors, key-order and
  whitespace invariance, Unicode/number/date cases, null handling, version
  compatibility, and tamper mutation tests.

### D-07: Genesis value and chain scope

- **Requirement:** The first record uses a defined genesis value.
- **Why it is ambiguous:** The value, format, chain scope, and whether the
  genesis is externally anchored are not defined.
- **Possible interpretations:** A fixed public constant; a configured secret or
  random value; a synthetic genesis record; or one genesis per tenant,
  partition, or archive segment.
- **Options:** Versioned fixed constant; persisted configuration value; or an
  explicit genesis record containing chain metadata.
- **Trade-offs:** A fixed value makes independent verification easy but allows
  an attacker who rewrites the entire store to reproduce the chain. A secret
  anchor improves resistance to full replacement but complicates exports and
  key management. Multiple genesis values improve isolation but require scope
  metadata.
- **Impact on implementation:** Affects first-write logic, verification,
  export bundles, configuration, and chain reset/restore behavior.
- **Impact on testing:** Requires empty-chain, first-record, wrong-genesis,
  isolated-chain, export, and full-rewrite detection tests.

### D-08: Persistence atomicity and append-only enforcement

- **Requirement:** Records are append-only and direct datastore modification
  must become detectable.
- **Why it is ambiguous:** The transaction boundary, database constraints,
  privilege model, and behavior after partial failure are unspecified.
- **Possible interpretations:** Rely on application code; enforce database
  permissions/triggers; or use an append-only storage mechanism.
- **Options:** Transactional insert with predecessor locking; database role
  separation and constraints; or immutable external/WORM storage.
- **Trade-offs:** Application-only enforcement is simple but weak against
  privileged access. Database controls improve protection but add operational
  complexity. WORM storage provides stronger guarantees but is unsuitable for
  a small local prototype without adapters.
- **Impact on implementation:** Determines transactions, indexes, roles,
  migration scripts, error handling, and the direct-mutation demonstration.
- **Impact on testing:** Requires rollback, crash/partial-write simulation,
  unauthorized update/delete checks, direct mutation detection, and concurrent
  append tests.

### D-09: Verification scope and violation taxonomy

- **Requirement:** `GET /audit/verify` walks the full chain and reports the
  first inconsistency and violation type.
- **Why it is ambiguous:** “Full chain,” first record ordering, response shape,
  and violation categories are not defined.
- **Possible interpretations:** Verify one global chain; verify every partition;
  or verify only the active chain while trusting archived checkpoints.
- **Options:** Return a single summary; return summary plus first failure; or
  return a list of failures with the first explicitly marked.
- **Trade-offs:** A minimal response is easy to consume but less diagnostic.
  Detailed failures aid operations but can expose record metadata and increase
  response size. Verifying all partitions is thorough but may be expensive.
- **Impact on implementation:** Defines traversal, query limits, response DTOs,
  status codes, timeout behavior, and access control.
- **Impact on testing:** Requires intact, content-hash, predecessor-hash,
  missing-record, reordered-record, genesis, archive, and multiple-failure
  cases, including first-failure determinism.

### D-10: Query semantics and pagination

- **Requirement:** Filter by combinations of actor, resource, event type, and
  time range, with pagination.
- **Why it is ambiguous:** Inclusive/exclusive boundaries, missing paired
  resource filters, sort order, page token versus offset, snapshot consistency,
  and archived-record visibility are unspecified.
- **Possible interpretations:** Offset pages sorted by timestamp; cursor pages
  sorted by chain sequence; or a consistent snapshot per request.
- **Options:** Offset/limit; opaque cursor; or cursor plus a fixed read
  timestamp/sequence.
- **Trade-offs:** Offset is simple but becomes unstable and slow as data grows.
  Cursors are efficient and stable but harder to use and validate. Snapshot
  semantics improve repeatability but can increase database cost.
- **Impact on implementation:** Determines indexes, query validation, response
  metadata, sorting, and handling of records appended during pagination.
- **Impact on testing:** Requires every filter combination, boundary dates,
  invalid ranges, empty pages, inserts between pages, duplicate prevention,
  stable ordering, and archived visibility tests.

### D-11: Retention, archive, soft-delete, and chain continuity

- **Requirement:** Older records may be archived or soft-deleted, and
  verification must not falsely report a break.
- **Why it is ambiguous:** Archive location, schedule, duration, query/export
  visibility, restoration, physical deletion, and how predecessor links cross
  the boundary are unspecified.
- **Possible interpretations:** Keep all records in verification storage and
  hide them from normal queries; move records with signed checkpoints; or mark
  them inactive while retaining their hashes.
- **Options:** Archive without deletion; soft-delete in place; or archive
  segments with a signed boundary commitment.
- **Trade-offs:** Keeping records is easiest to verify but does not reduce
  storage of sensitive data. Soft-delete preserves continuity but is not
  physical retention enforcement. Segmented archives reduce active storage but
  require trusted checkpoints and cross-segment verification.
- **Impact on implementation:** Defines lifecycle state, jobs/configuration,
  archive schema, verification traversal, restore behavior, and API filters.
- **Impact on testing:** Requires age-boundary, scheduled execution, archive
  failure/retry, restored records, hidden-query behavior, deleted-record
  detection, and verification across archive boundaries.

### D-12: Redaction semantics and privacy boundary

- **Requirement:** Selected payload fields can be structurally redacted without
  breaking the chain.
- **Why it is ambiguous:** Field paths, supported structures, replacement
  value, reversibility, authorization, timing, auditability, and whether the
  original value may remain recoverable are unspecified.
- **Possible interpretations:** Replace with a marker; replace with a one-way
  commitment; encrypt the original and remove access; or append a redaction
  event while preserving the original record.
- **Options:** Immutable original plus redacted projection; hash/commitment of
  the original value; envelope encryption with key destruction; or a versioned
  redacted record linked to the original.
- **Trade-offs:** A projection preserves the original hash but may leave
  sensitive data in storage. A commitment supports later verification but can
  permit guessing low-entropy values. Encryption supports controlled recovery
  but requires key management. Rewriting the record simplifies reads but needs
  a carefully defined commitment scheme.
- **Impact on implementation:** Determines payload model, canonical hash input,
  redaction API, permissions, key/secret handling, and verification rules.
- **Impact on testing:** Requires nested paths, arrays, missing paths, repeated
  redaction, unauthorized requests, original-value non-disclosure, chain
  verification, and tampering with redaction metadata.

### D-13: Authentication and authorization

- **Requirement:** Security and production readiness must be considered, and
  records may contain sensitive data.
- **Why it is ambiguous:** No identity provider, principals, roles, endpoint
  permissions, tenant boundary, or machine-to-machine model is specified.
- **Possible interpretations:** Local unauthenticated prototype; API-key
  protection; or role-based/tenant-aware authentication.
- **Options:** Documented local-only trust boundary; Spring Security with
  configured tokens; or integration with an external OAuth2/OIDC provider.
- **Trade-offs:** No authentication is easiest but unsafe outside a local demo.
  Token-based protection is realistic but requires key/configuration handling.
  External identity integration is stronger but exceeds the assignment's
  defined scope and complicates setup.
- **Impact on implementation:** Defines middleware, principal propagation,
  endpoint policies, tenant scoping, redaction/export permissions, and
  operational configuration.
- **Impact on testing:** Requires unauthenticated, authenticated, forbidden,
  cross-tenant, privilege-escalation, and sensitive-data exposure tests.

### D-14: Export integrity boundary and access

- **Requirement:** Export records by `resourceId` or `actorId` as a
  self-contained independently verifiable bundle.
- **Why it is ambiguous:** Format, signing/anchoring, omitted chain records,
  archived records, authorization, and recipient verification procedure are
  not defined.
- **Possible interpretations:** Export full chain context; export selected
  records with predecessor/successor proofs; or export a signed snapshot.
- **Options:** JSON bundle with all required records; Merkle/proof metadata;
  or a signed manifest with record hashes and chain boundaries.
- **Trade-offs:** Full context is easiest to verify but can disclose unrelated
  records. Proofs reduce disclosure but are more complex. A signed manifest
  adds key management and verifies authenticity only while the signing key is
  trusted.
- **Impact on implementation:** Determines export query strategy, bundle
  schema, redaction/archive handling, signing or proof generation, and size
  limits.
- **Impact on testing:** Requires actor/resource selection, empty results,
  pagination/large exports, independent verification, omitted-record
  tampering, altered metadata, and unauthorized export tests.

### D-15: Compliance-reporting scope

- **Requirement:** Regulators must be able to audit access to client account
  data, but the requirement must first be clarified and normalized.
- **Why it is ambiguous:** Event vocabulary, account identity, report users,
  evidence fields, time range, output, retention, and regulatory rules are not
  provided.
- **Possible interpretations:** Search raw access events; generate a
  regulator-specific report; or provide an immutable evidence export.
- **Options:** Implement a narrowly defined account-access event and filtered
  query; implement a report endpoint; or document the design and leave
  integration out of scope.
- **Trade-offs:** A narrow implementation is testable and honest but may not
  satisfy an actual regulator. A general reporting system is flexible but
  requires domain and compliance decisions absent from the assignment.
- **Impact on implementation:** Defines event schema, authorization, indexes,
  reporting queries, redaction, export, and documentation boundaries.
- **Impact on testing:** Requires representative access events, authorized
  regulator queries, incomplete data, time boundaries, redaction, and
  independent verification tests.

### D-16: Non-functional targets and operational scope

- **Requirement:** The prototype should be production-quality and consider
  security, validation, risks, and production readiness.
- **Why it is ambiguous:** No availability, latency, throughput, scale,
  consistency, recovery, observability, or deployment targets are stated.
- **Possible interpretations:** Local single-instance demonstration; modest
  production baseline; or highly available regulated service.
- **Options:** Document measurable prototype limits; define target budgets for
  the prototype; or obtain operational requirements before design.
- **Trade-offs:** Explicit limits prevent overengineering but constrain claims.
  Production targets improve design credibility but require load, resilience,
  and operational work not required by the scenario.
- **Impact on implementation:** Affects indexes, caching, deployment,
  transaction design, timeouts, monitoring, backup, and recovery features.
- **Impact on testing:** Determines whether unit/integration tests are
  sufficient or whether load, failure-injection, resilience, and recovery
  tests are necessary.

### D-17: Export/query/redaction error and lifecycle semantics

- **Requirement:** The service exposes write, query, verify, export, and
  redaction-related behavior, but response contracts are not fully defined.
- **Why it is ambiguous:** HTTP status codes, error format, timeout behavior,
  idempotency, partial results, and long-running operation handling are absent.
- **Possible interpretations:** Synchronous APIs with bounded payloads;
  asynchronous jobs for export/retention; or best-effort partial responses.
- **Options:** Standard synchronous REST responses; job resources for expensive
  operations; or synchronous core APIs plus asynchronous export.
- **Trade-offs:** Synchronous behavior is simple for the prototype but can
  exceed request limits. Jobs improve reliability for large work but add state,
  polling, and cleanup concerns. Partial results are useful but weaken
  verifiability unless explicitly marked.
- **Impact on implementation:** Defines controllers, error DTOs, limits,
  persistence for jobs, retry behavior, and operational cleanup.
- **Impact on testing:** Requires validation errors, not-found/conflict cases,
  timeout/retry behavior, partial failure, and complete-bundle guarantees.
