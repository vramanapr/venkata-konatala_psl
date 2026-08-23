# Structured Field-Level Redaction Design

## 1. Problem statement

An audit event payload may contain sensitive fields that must later be hidden
from normal readers. The audit log is tamper-evident: its historical event
content and chain links are committed at ingestion. Replacing the payload and
recomputing the historical hash would make an authorized redaction
indistinguishable from rewriting history.

This design separates the immutable integrity evidence from the current
presentation representation. Redaction changes what is exposed, but does not
replace the historical integrity commitment.

## 2. Goals

- Preserve the existing SHA-256 hash-chain model.
- Keep the integrity envelope immutable after ingestion.
- Support structured redaction at selected payload field paths.
- Store versioned, salted commitments for designated redactable fields.
- Store redaction operations as append-only metadata.
- Make repeated identical redactions idempotent.
- Reject conflicting redaction operations.
- Verify chain integrity separately from redaction consistency.
- Avoid exposing original sensitive values or salts by default.
- Keep the prototype implementable without distributed systems or an external
  key-management service.

**Decision:** Use an immutable envelope, a separate presentation payload,
field-level commitments, and append-only redaction metadata.

**Alternatives considered:** Recompute the historical hash; retain only one
whole-payload hash; mutate the stored payload while retaining a prior hash;
encrypt the original payload.

**Reason for selection:** This preserves historical chain evidence while
allowing the exposed representation to change. It also supports a useful
field-level commitment without changing the core chain algorithm.

**Trade-offs:** The model requires additional storage, projection validation,
and distinct verification results. It does not provide recovery of redacted
values or cryptographic proof of the original plaintext after that plaintext
has been destroyed.

## 3. Non-goals

- Encryption of original values.
- Key destruction or integration with an external KMS.
- Recovery of redacted values.
- External or public anchoring of commitments.
- Distributed redaction coordination.
- Arbitrary mutation of event metadata.
- Claiming that a redacted payload equals the original payload.
- Physical destruction policy beyond the assignment's stated redaction need.

**Decision:** Keep these concerns outside the prototype.

**Alternatives considered:** Build envelope encryption, KMS integration, or
external notarization now.

**Reason for selection:** They are not explicitly required and would add
operational and security complexity unrelated to the approved prototype
boundary.

**Trade-offs:** The prototype cannot support controlled recovery and relies on
the database and application security boundary for commitment metadata.

## 4. Data model

The logical model has four parts:

1. **Audit record / integrity envelope:** immutable event metadata, canonical
   payload commitment, sequence, predecessor hash, and content hash.
2. **Presentation payload:** the currently exposed event representation.
3. **Field commitments:** one immutable commitment per designated redactable
   field occurrence.
4. **Redaction metadata:** append-only records describing authorized changes
   to the presentation state.

The existing chain record remains the authoritative sequence and predecessor
link. Redaction metadata does not become a replacement for the original
chain record.

**Decision:** Model redaction as a projection over an immutable event rather
than as an update to historical event identity.

**Alternatives considered:** Store only a mutable payload; create a new
successor audit event for every redaction; move redacted records to a separate
chain.

**Reason for selection:** A projection preserves stable record identity and
keeps verification compatible with the current chain.

**Trade-offs:** Readers and verifiers must understand both the envelope and
the projection. A successor-event model would provide a stronger audit trail
but would complicate normal reads and is not required for this prototype.

## 5. Immutable integrity envelope design

The envelope contains, at minimum:

- record identifier;
- chain identifier;
- immutable sequence;
- event type;
- actor identifier;
- resource type and identifier;
- occurrence timestamp;
- server recording timestamp;
- canonical payload commitment;
- payload schema/canonicalization version;
- previous hash;
- content hash.

The envelope hash is calculated once at ingestion using the existing canonical
event representation and SHA-256. Redaction never changes the envelope hash,
sequence, predecessor, event metadata, or original payload commitment.

The envelope's payload commitment represents the complete original payload.
Field commitments supplement it for designated paths.

**Decision:** Continue hashing the original event representation, not the
redacted presentation payload.

**Alternatives considered:** Hash the current presentation payload; hash both
original and presentation payloads as interchangeable chain content.

**Reason for selection:** The chain must retain a stable historical meaning.
Otherwise a later presentation change would rewrite the event committed at
ingestion.

**Trade-offs:** Chain verification cannot independently reconstruct a
redacted original payload from the presentation representation. It can verify
the envelope and its commitment, while redaction verification handles the
projection separately.

## 6. Presentation payload design

The presentation payload is the representation returned to callers with
permission to read the event. It is derived from the original payload and the
ordered redaction metadata for that record.

An unredacted field is represented by its original value. A redacted field is
replaced by a deterministic object, for example:

```json
{
  "redacted": true,
  "commitment": "v1:sha256:..."
}
```

The exact public marker shape remains an open API decision. The marker must
not contain the original value or the salt.

The presentation representation must preserve object structure. Redacting a
field removes its value but does not change unrelated fields. Array element
paths require an explicit supported-path decision before implementation.

**Decision:** Generate a structured redacted projection and never use it to
overwrite the historical envelope commitment.

**Alternatives considered:** Return null; remove the field; replace it with a
fixed string; store a second mutable JSON document without deterministic
markers.

**Reason for selection:** A structured marker makes redaction visible,
consistent, and verifiable without confusing intentional unavailability with
an absent source field.

**Trade-offs:** The marker reveals that a field existed and may reveal a
commitment identifier. Removing the field would disclose less structure but
would be harder to distinguish from an originally absent field.

## 7. Field-level commitment design

At ingestion, the service identifies fields designated as redactable. For each
field occurrence it computes a commitment over:

- commitment format version;
- canonical field path;
- canonical field value;
- random field salt.

The commitment is stored independently of the presentation value. It is
immutable. Fields not designated as redactable do not automatically receive
field commitments.

The whole-payload commitment remains required even when field commitments are
present. Field commitments are not a substitute for the chain content hash.

**Decision:** Commit only to explicitly designated redactable fields.

**Alternatives considered:** Commit every payload field; commit only when a
redaction request is received; commit the entire payload once.

**Reason for selection:** Ingestion-time commitment is required to establish
evidence before a later redaction. Explicit designation avoids unnecessary
storage and avoids silently expanding the privacy/security contract.

**Trade-offs:** A field that was not designated at ingestion cannot later gain
the same original-value commitment without retaining or reprocessing the
original value. Committing every field would improve coverage but increase
storage and privacy exposure.

## 8. Commitment format

The proposed internal format is:

```text
v1:sha256:<lowercase-hex-digest>
```

The digest input is a versioned canonical object containing the field path,
field value, and salt. The path is included so that moving the same value to
another field cannot be mistaken for the original commitment.

The commitment record should retain the format version and algorithm as
separate database fields where practical, even if the API displays the
combined string.

**Decision:** Use a versioned SHA-256 commitment format with lowercase
hexadecimal output, consistent with the current hash representation.

**Alternatives considered:** Bare SHA-256; HMAC; SHA-512; a binary
commitment format; a standard such as a separately adopted password-hashing
scheme.

**Reason for selection:** Versioning supports future migration, and SHA-256
matches the approved chain algorithm and existing tooling. Including path,
value, and salt prevents context ambiguity.

**Trade-offs:** SHA-256 is not a hiding mechanism for low-entropy values if
salts are exposed or guessable. A bare digest would be simpler but would
provide weaker domain separation and migration support.

## 9. Salt generation and storage

Each field occurrence receives a cryptographically secure random salt generated
by the application at ingestion. Salts must be unique with overwhelming
probability and must not be generated from timestamps, identifiers, or
predictable request data.

The salt is stored in restricted integrity metadata so that the application
can verify a supplied original value when policy permits. It is not returned
by default in event queries, redaction responses, or exports unless a future
approved verifier contract explicitly requires it.

Because encryption and key destruction are out of scope, salt storage is
confidentiality-sensitive but not treated as a recoverability key.

**Decision:** Use per-field cryptographically random salts stored separately
from the public presentation payload.

**Alternatives considered:** One salt per record; deterministic salt derived
from record ID; no salt; external secret storage.

**Reason for selection:** Per-field random salts reduce equality leakage and
prevent simple precomputed dictionary attacks. The approach remains local and
does not introduce an external KMS.

**Trade-offs:** Salt storage and access control add complexity. If salts are
lost, original-value matching cannot be performed, although chain integrity
remains verifiable. If salts are exposed, low-entropy values may still be
guessed offline.

## 10. Redaction metadata model

Each redaction metadata record contains:

- audit record identifier;
- canonical field path;
- redaction reason;
- requesting principal;
- redaction timestamp;
- resulting presentation state;
- reference to the field commitment, where applicable;
- a stable redaction operation identifier.

The metadata is append-only. The resulting presentation state may be stored
as a state marker or derived from the operation history. The prototype should
prefer derivation when practical to avoid two mutable sources of truth.

Redaction metadata is auditable metadata, but it is not silently inserted into
the historical event hash.

**Decision:** Store one append-only operation per logical redacted field path
and derive the visible state from the operation history.

**Alternatives considered:** Mutate a redaction flag on the audit record;
store only a fully materialized presentation payload; append a normal business
event for each redaction.

**Reason for selection:** Append-only operations preserve who, why, and when,
while derivation reduces the risk of metadata/presentation divergence.

**Trade-offs:** Projection reads and verification require replaying or
collapsing operations. A materialized view may be faster but requires
transactional synchronization and repair behavior.

## 11. Redaction state transitions

The logical states for a field are:

1. **UNREDACTED:** the field is exposed according to read authorization.
2. **REDACTION_REQUESTED:** a request is being validated and authorized.
3. **REDACTED:** an immutable operation records the redacted presentation
   state.
4. **REDACTION_REJECTED:** no presentation change is made; the failure is
   surfaced to the caller.

There is no prototype transition from REDACTED back to UNREDACTED. There is
also no transition that changes the historical envelope.

**Decision:** Make redaction one-way for the prototype.

**Alternatives considered:** Allow unredaction; allow replacement redactions;
represent each presentation version as a mutable document.

**Reason for selection:** Reversal would require a recovery policy and could
re-expose sensitive data. The approved direction explicitly excludes
controlled recovery and key management.

**Trade-offs:** Mistaken redactions cannot be undone through the service.
Operational recovery would require a separately approved process.

## 12. Idempotency behavior

An identical redaction request for the same record, canonical path, and
effective redaction state returns the existing redaction result and does not
create a second logical state change.

Idempotency must be based on a stable operation key or an equivalent
fingerprint. The request reason and principal handling must be defined
carefully: a repeated request may be considered identical only when all
auditable fields match, or the system may use an explicit client idempotency
key and retain the first operation's metadata.

**Decision:** Require a stable idempotency mechanism for retry-safe redaction;
do not infer idempotency from the sensitive value.

**Alternatives considered:** Treat every request as a new event; deduplicate
only by record and path; deduplicate by payload/value comparison.

**Reason for selection:** Value comparison can expose or require access to the
sensitive value. A stable operation key handles network retries without
collapsing distinct administrative actions accidentally.

**Trade-offs:** Additional key storage and expiration rules are required.
Without a mandatory key, exact retry semantics remain ambiguous.

## 13. Conflict behavior

A redaction request conflicts when it targets a non-existent path, a
non-redactable field, an already redacted field with incompatible state, or
reuses an idempotency key for different request data.

Conflicts must fail without changing the envelope, presentation payload, or
redaction metadata. The API should return a distinct client error, proposed as
HTTP `409 Conflict` for state/key conflicts and `400 Bad Request` for invalid
path syntax, subject to API approval.

**Decision:** Reject conflicting operations atomically.

**Alternatives considered:** Last-write-wins; silently accept duplicate
operations; overwrite the existing redaction metadata.

**Reason for selection:** Last-write-wins is inappropriate for an auditable
privacy operation and can conceal administrative mistakes.

**Trade-offs:** Operators must use a separate corrective process for mistakes.
The service must define precise path and state comparison rules.

## 14. Chain verification behavior

Chain verification remains based on the immutable envelope:

- load the logical chain, including retained/archive records according to the
  existing retention model;
- verify sequence continuity;
- verify each predecessor hash;
- recompute each envelope content hash;
- verify the chain head;
- report the first chain-integrity failure.

Redaction does not cause a content-hash mismatch because the historical
envelope is unchanged. A redacted presentation payload is not substituted
into the existing hash calculation.

**Decision:** Preserve the current chain verifier as the source of chain
integrity evidence and add separate redaction checks.

**Alternatives considered:** Teach the existing content hash to accept either
the original or redacted payload; create a second chain for presentation
updates.

**Reason for selection:** The current hash-chain contract remains stable and
independent of privacy lifecycle operations.

**Trade-offs:** Verification results must expose two dimensions instead of
one. Existing clients expecting only an `intact` flag may need a compatible
extension.

## 15. Redaction consistency verification

Redaction consistency verification is distinct from chain integrity. It must:

- validate redaction metadata schema and required fields;
- confirm the referenced record exists;
- validate canonical field-path syntax;
- confirm the path exists in the original committed payload or is otherwise
  covered by a recorded field commitment;
- confirm the field is designated redactable;
- confirm the commitment reference and format are valid;
- replay operations in deterministic order;
- confirm the resulting presentation payload matches the authorized redaction
  state;
- detect altered, missing, duplicated, or conflicting metadata;
- avoid claiming that the visible redacted marker equals the original value.

Proposed result categories are:

- `CHAIN_INTEGRITY_FAILURE`;
- `REDACTION_METADATA_FAILURE`;
- `REDACTION_PROJECTION_FAILURE`;
- `REDACTION_COMMITMENT_FAILURE`.

If the original value and protected salt are available, the verifier may
validate a supplied candidate value against its field commitment. If the
original value has been irreversibly destroyed, verification reports only
that the field was committed and intentionally unavailable.

**Decision:** Return separate chain and redaction-consistency status.

**Alternatives considered:** Treat any projection mismatch as a chain break;
ignore presentation state during verification; claim successful recovery of
the original value from the commitment.

**Reason for selection:** It accurately represents what each artifact proves.

**Trade-offs:** The result schema and tests become more detailed. A clean
chain can coexist with a broken presentation projection, and clients must
handle both outcomes.

## 16. API impact

The existing event write and query APIs need a defined distinction between
envelope fields and presentation fields. Normal event reads should return the
presentation payload and redaction status, not salts or original values beyond
the caller's authorization.

The proposed redaction endpoint is:

```text
POST /api/v1/audit/events/{recordId}/redactions
```

The request should contain a canonical field path, reason, and an
idempotency key. The response should identify the record, path, resulting
state, operation identifier, and whether the operation was newly applied or
replayed.

The verification endpoint should expose chain status and redaction
consistency status separately, while preserving compatibility with the
existing chain verification contract where possible.

**Decision:** Add a dedicated redaction operation endpoint and keep original
values and salts out of ordinary API responses.

**Alternatives considered:** Add a redaction flag to event creation; use a
generic record update endpoint; expose commitment salts for client-side
verification.

**Reason for selection:** A dedicated operation makes authorization,
idempotency, auditability, and conflict handling explicit.

**Trade-offs:** It adds an endpoint and response-schema work. Exact HTTP
status codes, authentication scopes, path syntax, and export behavior remain
open decisions.

## 17. Database impact

The database must represent:

- immutable envelope content and payload commitment;
- current presentation payload or sufficient data to derive it;
- immutable field commitments, including path, version, algorithm, digest,
  and restricted salt storage;
- append-only redaction metadata;
- uniqueness constraints supporting idempotency and conflict detection;
- indexes for record/path and operation lookup.

Database privileges must prevent ordinary application callers from updating or
deleting envelope and redaction rows. Application transactions must atomically
validate the target, create the redaction metadata, and update any
materialized presentation state if one is used.

The existing hash-chain tables and core hash calculation should not be
replaced. A migration should be additive and preserve existing records. Older
records without field commitments require an explicit migration policy; they
must not silently receive fabricated commitments.

**Decision:** Use additive schema changes with immutable commitment and
append-only redaction structures.

**Alternatives considered:** Replace `payload_document` in place; create a
second independent audit table; store redaction state only in application
cache.

**Reason for selection:** Additive structures preserve history and survive
application restarts.

**Trade-offs:** Storage and migration complexity increase. Database-level
immutability is not absolute for the table owner or privileged operators and
must be combined with deployment-role separation.

## 18. Security considerations

- Redaction authorization must be deny-by-default and separate from ordinary
  read/write permissions.
- The requesting principal and reason must be recorded.
- Salts and any retained original payload must have tighter access than normal
  event reads.
- Error responses must not echo sensitive values.
- Logs, traces, metrics, dead-letter records, exports, and backups must not
  accidentally contain original values or salts.
- Path validation must prevent traversal-like ambiguity and prototype/object
  pollution issues in any JSON processing library.
- Redaction must be atomic so a partially applied operation cannot expose an
  inconsistent state.
- Database role separation is required for meaningful protection against
  privileged mutation.
- A commitment is not encryption; access to low-entropy data and salts may
  permit guessing.

**Decision:** Treat commitments as integrity/privacy-supporting metadata, not
as a confidentiality boundary equivalent to encryption.

**Alternatives considered:** Rely on obscurity of the marker; use unsalted
hashes; expose all verification metadata to every reader.

**Reason for selection:** The approved design excludes encryption but still
requires honest threat-model boundaries.

**Trade-offs:** Strong privacy guarantees cannot be claimed against database
administrators, backups, or any system retaining the original payload.

## 19. Privacy considerations

The design supports data minimization in returned representations but does not
automatically erase every copy of a sensitive value. Before implementation,
the system must identify whether originals remain in the database, backups,
replicas, application logs, exports, and test fixtures.

After irreversible destruction of an original value, the service may claim:

> This field was originally committed, and the current value is intentionally
> unavailable under the recorded redaction operation.

It must not claim that the redacted marker contains, equals, or reconstructs
the original value.

**Decision:** Make privacy claims conditional on the actual storage and backup
lifecycle.

**Alternatives considered:** Claim complete erasure from redaction alone;
retain plaintext indefinitely; expose commitments as proof of the plaintext.

**Reason for selection:** Redaction of the presentation payload alone does not
erase copies elsewhere and cannot prove an unavailable plaintext.

**Trade-offs:** Compliance language must be conservative and may require
operational deletion controls outside this service.

## 20. Failure scenarios

The implementation and tests must cover:

- invalid or unsupported field path;
- path absent from the original payload;
- field not designated redactable;
- malformed commitment or missing salt;
- duplicate redaction request;
- idempotency-key reuse with different data;
- concurrent redactions of the same field;
- transaction rollback after metadata insertion;
- presentation update failure;
- modified envelope;
- modified field commitment;
- modified redaction metadata;
- modified presentation payload;
- deleted redaction metadata;
- application restart during or after redaction;
- redaction of a retained/archive record;
- unauthorized redaction attempt.

**Decision:** Fail closed for validation, authorization, and consistency
errors; do not silently return an apparently successful redaction.

**Alternatives considered:** Best-effort projection updates; continue after
metadata corruption; repair metadata automatically during verification.

**Reason for selection:** Silent recovery would conceal tampering or
administrative errors.

**Trade-offs:** Availability may be reduced when metadata is inconsistent, and
repair requires an explicit operational procedure.

## 21. Concurrency considerations

Redaction must use a database transaction. The target record and its existing
redaction state must be read under a lock or protected by a uniqueness
constraint so that concurrent requests cannot both apply conflicting state.

The redaction transaction must atomically:

1. authenticate and authorize the caller;
2. validate the path and commitment;
3. establish idempotency;
4. insert immutable redaction metadata;
5. update a materialized presentation payload, if used;
6. commit all changes.

Concurrent redactions of different fields on one record may be serialized for
simplicity. Redaction must not acquire or change the core chain-head state,
because it does not append a business event to the historical chain.

**Decision:** Use database transactionality and row/unique-key coordination,
not in-memory locks.

**Alternatives considered:** JVM locks; distributed locks; asynchronous
redaction queues.

**Reason for selection:** Database coordination works across application
instances and survives restarts without introducing a distributed lock
service.

**Trade-offs:** Lock contention can reduce redaction throughput. The
prototype does not require independent high-scale redaction workers.

## 22. Testing strategy

### Unit tests

- Canonical field-path parsing and normalization.
- Commitment generation and verification.
- Different values, paths, salts, and versions produce distinct commitments.
- Stable commitment output for identical inputs.
- Deterministic presentation marker generation.
- Projection replay for nested objects.
- Invalid path and unsupported structure handling.
- Idempotency and conflict decision logic.

### Integration/database tests

- Ingestion creates immutable envelope and field commitments.
- Redaction metadata is inserted atomically.
- Repeated identical requests do not create duplicate state.
- Conflicting requests fail without mutation.
- Database update/delete tampering is detected where privileges permit the
  test.
- Rollback leaves envelope, commitments, metadata, and presentation state
  unchanged.
- Restart-like operation preserves redaction state.
- Concurrent same-field redactions yield one deterministic result.

### API/security tests

- Authorized redaction succeeds.
- Missing authentication or insufficient scope is rejected.
- Cross-resource or cross-tenant access is rejected when tenancy is enabled.
- Responses do not expose original values or salts.
- Verification reports chain integrity and redaction consistency separately.
- Modified presentation payload is reported as a redaction-consistency
  failure, not incorrectly as a clean chain.
- A clean chain with a legitimate redaction does not produce a false chain
  failure.

### Privacy tests

- Redacted query responses contain no original sensitive value.
- Error messages and audit application logs do not echo the value.
- After original-value destruction, verification makes only the limited
  approved claim.

**Decision:** Test integrity, projection consistency, authorization, and
non-disclosure as separate properties.

**Alternatives considered:** Test only the final JSON response; test only the
chain hash; rely on manual inspection.

**Reason for selection:** A passing chain hash does not prove a correct
presentation projection, and a correct projection does not prove chain
integrity.

**Trade-offs:** The test suite is larger and requires explicit tampering and
concurrency fixtures.

## 23. Limitations

- The immutable whole-payload commitment does not reveal the original payload
  after redaction and cannot by itself prove the redacted value.
- Field commitments can be vulnerable to offline guessing for low-entropy
  values, especially if salts are exposed.
- No encryption or key destruction is implemented.
- Database administrators or backup operators may still access retained
  plaintext copies.
- Existing records may not have field commitments.
- The exact supported path syntax and array semantics are not yet approved.
- A fixed internal commitment is not an external trust anchor.
- Projection verification depends on the integrity and availability of
  commitment and metadata storage.
- Redaction is one-way in the prototype.

**Decision:** Document these limitations instead of presenting commitments as
confidential storage or redaction as universal erasure.

**Alternatives considered:** Hide limitations behind a generic "verified"
status.

**Reason for selection:** Security claims must match what the implementation
can actually establish.

**Trade-offs:** The prototype's guarantees are narrower, but they are
defensible and testable.

## 24. Open engineering decisions

The following require explicit approval before implementation:

1. **Redactable-field policy:** Which fields are designated at ingestion:
   event-type schema, configuration, request metadata, or a fixed prototype
   allowlist?
2. **Field-path syntax:** JSON Pointer, dot notation, or another canonical
   syntax?
3. **Array support:** Are array indexes supported, and how are repeated
   elements identified?
4. **Whole-object redaction:** Is a parent object redacted as one value, or
   must each child receive a commitment?
5. **Null and absent values:** Are null fields redactable, and how is an
   absent path distinguished from a present null?
6. **Commitment visibility:** May privileged verifiers receive salts or
   candidate-value verification, or are commitments always internal?
7. **Salt retention:** How long must salts be retained, and what is the
   approved behavior if a salt is lost?
8. **Original payload lifecycle:** Does the database retain the original
   payload after redaction, or is a separate deletion process required?
9. **Presentation storage:** Store a materialized presentation payload, derive
   it on reads, or use a hybrid cache/materialization model?
10. **Redaction API contract:** Exact request/response schemas, status codes,
    error envelope, and idempotency-key requirements.
11. **Authorization:** Which principals may redact, verify, export, or view
    commitment metadata?
12. **Redaction audit trail:** Is redaction metadata alone sufficient, or must
    each redaction also create a normal chained audit event?
13. **Verification response:** Exact fields and whether chain and redaction
    statuses are nested or top-level.
14. **Legacy records:** How should records created before field commitments be
    queried and represented?
15. **Retention interaction:** Are archived records redaction-eligible, and
    are redaction operations archived with the record?
16. **Privacy claim:** Whether the assignment requires only presentation
    masking or an operational deletion guarantee for all plaintext copies.
17. **Commitment algorithm policy:** Confirm version `v1` SHA-256 and the exact
    canonicalization rules for field values and paths.

Until these decisions are approved, they are design proposals rather than
implemented requirements.
