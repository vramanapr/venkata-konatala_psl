# Final Engineering Summary

**Project:** Tamper-Evident Audit Log Service  
**Summary date:** 2026-08-24  
**Technology:** Java 21, Spring Boot, Maven, PostgreSQL, Flyway, Docker, JUnit 5, Testcontainers

## 1. Engineering plan and rationale

The implementation was completed incrementally so that each major concern
could be reviewed independently:

1. Analyze and classify assignment requirements.
2. Record ambiguities and obtain decisions before implementation.
3. Bootstrap the Spring Boot, Maven, PostgreSQL, Docker, and health-check
   foundation.
4. Create the append-only database schema and migrations.
5. Implement deterministic canonicalization and SHA-256 hash chaining.
6. Implement transactional append ordering using a locked PostgreSQL chain
   head.
7. Add idempotency handling for safe retries.
8. Implement Scenario A append, query, pagination, and verification APIs.
9. Implement retention, archive-table support, and durable checkpoints.
10. Design and implement structured field-level redaction.
11. Implement versioned offline-verifiable bulk export.
12. Add optional Ed25519 export-manifest signatures.
13. Add actor identity, delegation, authorization evidence, and endpoint
   permissions.
14. Add setup, security, requirements, design, attestation, and AI-usage
   documentation.

The central design principle is that historical integrity must not be
rewritten by lifecycle operations. Retention and redaction therefore modify
visibility or storage state while preserving the original chain commitment.

## 2. Core design decisions

### Hash chain

- SHA-256 with lowercase hexadecimal digests.
- Versioned deterministic canonical JSON.
- Object keys sorted by Unicode code-point order.
- Arrays retain order.
- UTF-8 hash input.
- UTC timestamp normalization.
- Fixed versioned genesis hash.
- Immutable sequence order determined by database chain-head locking.
- `previousHash` references the immediately preceding `contentHash`.

### Concurrent append behavior

- PostgreSQL is the authoritative writer.
- One chain-head row is locked with `SELECT FOR UPDATE`.
- Sequence allocation, predecessor selection, record insert, idempotency
  insert, and chain-head update occur in one transaction.
- Rollback leaves no partial chain state.

### Retention

- Configurable `SOFT_DELETE` mode.
- Configurable `ARCHIVE_TABLE` mode.
- Archived records remain in the logical verification chain.
- Physical destruction is not implemented.
- Durable checkpoints provide additional evidence but do not replace full
  verification.

### Redaction

- Immutable historical integrity envelope.
- Separate presentation payload and presentation hash.
- Versioned SHA-256 field commitments with 128-bit random salts.
- RFC 6901 JSON Pointer paths.
- Append-only redaction metadata and operation hash chaining.
- Idempotency keys and conflict rejection.
- Same-record database locking for concurrent redaction requests.
- Verification separates chain integrity from redaction consistency.
- Original values and salts are not exposed through normal APIs.
- Encryption and key destruction are intentionally out of scope.

### Bulk export

- Versioned ZIP bundle containing:
  - `manifest.json`
  - `records.json`
  - `proof.json`
  - `redactions.json`
- Actor or resource selection.
- Full-prefix chain proof from genesis.
- `SELECTED` and `CHAIN_CONTEXT` record markers.
- SHA-256 component digests.
- Archive-aware logical-chain representation.
- Offline verification without database access.
- Optional Ed25519 manifest signing.

### Identity and authorization

- Prototype Spring Security HTTP Basic authentication.
- Environment-configured users and scopes.
- Server-authenticated principal takes precedence over caller-supplied actor
  identity.
- Delegation requires admin authority, a reason, and delegation evidence.
- Authorization evidence is persisted and included in the event hash.
- Endpoint scopes cover write, read, verify, export, redact, and admin.
- Health endpoints are public; management endpoints require admin authority.

## 3. Repository artifacts

### Documentation

- `README.md`
- `SETUP.md`
- `ATTESTATION.md`
- `docs/requirements.md`
- `docs/redaction-design.md`
- `docs/export-design.md`
- `docs/security-and-operations.md`
- `docs/scenario-a-test-strategy.md`
- `docs/final-engineering-summary.md`
- `ai/AI_USAGE_LOG.md`

### Application and domain components

- Spring Boot application bootstrap.
- Audit append, query, verification, retention, checkpoint, redaction, and
  export services.
- Hashing and canonical JSON components.
- Domain models for audit records, events, commitments, paths, and redaction
  operations.
- REST API controllers and error handling.
- Spring Security prototype configuration.

### Persistence

- Flyway migrations for:
  - audit chain state;
  - audit records;
  - archive records;
  - idempotency;
  - redaction metadata;
  - checkpoints;
  - field commitments;
  - presentation payloads;
  - authorization evidence.
- JDBC repository for append, query, verification, archive, redaction,
  checkpoint, and export reads.

### Testing

- Application context and health tests.
- Canonicalization and hash-chain unit tests.
- Redaction path, commitment, and projection tests.
- API validation and endpoint tests.
- Security and delegation tests.
- Concurrent append, rollback, duplicate, and restart-like tests.
- Retention and checkpoint tests.
- Export, full-prefix, component-tamper, and offline-verification tests.
- PostgreSQL/Testcontainers integration tests.

## 4. Risks and trade-offs

### Single chain throughput

A single locked chain head provides deterministic ordering across application
instances but serializes appends. Partitioned chains would scale better but
would complicate verification and exports.

### Fixed genesis and internal checkpoints

The chain detects partial tampering but cannot detect an attacker who rewrites
the complete database and recomputes every hash. External anchoring is not
implemented.

### Full-prefix exports

Independent verification without external range proofs requires all records
from genesis through the last selected record. This can disclose unrelated
events and create large exports.

### Redaction and confidentiality

Field commitments support integrity evidence but are not encryption. Low
entropy values may be susceptible to guessing, especially if salts are
exposed. Retained database, backup, replica, log, or export copies may still
contain original values.

### Prototype authentication

HTTP Basic and in-memory environment-configured users are suitable for local
demonstration only. Production identity federation, token validation, mTLS,
secret rotation, and key management are not included.

### Database immutability

Application permissions and public privilege revocation do not protect against
the database owner or privileged administrators. Deployment role separation is
required for stronger guarantees.

### Archive storage

Archive-table mode copies and marks records archived but does not physically
remove the active copy. This favors recovery and verification safety over
storage minimization.

### Authorization evidence scope

The service records the authorization decision supplied by the application
boundary. It does not independently prove that an external identity provider
or policy engine made the correct decision.

## 5. Assumptions

The following assumptions were used for the prototype:

- One global default chain is sufficient.
- PostgreSQL is the authoritative primary database for the chain.
- Caller timestamps represent event occurrence time; server recording time is
  separate where applicable.
- Existing append API compatibility is more important than immediately
  removing caller actor fields.
- Prototype redaction permits all stored payload paths to receive field
  commitments because no event-schema allowlist has yet been configured.
- RFC 6901 paths and array indexes are supported subject to canonical syntax.
- Redaction is one-way.
- Archived records remain logically verifiable.
- Export selection uses actor/resource `OR` semantics.
- Export completeness is an exporter assertion unless independently anchored.
- Optional signatures are disabled unless configured with keys.
- Deployment infrastructure supplies secrets, database roles, network
  restrictions, backups, and operational monitoring.

These assumptions are not legal or regulatory determinations.

## 6. Verification and validation status

Completed validation includes:

- focused unit and API tests;
- application context tests;
- redaction and export tests;
- security and delegation tests;
- complete non-container Maven test execution;
- Maven package build;
- formatting and whitespace checks.

PostgreSQL/Testcontainers integration tests were added but could not be
executed in the development environment because Docker was unavailable.

## 7. Testing approach, coverage, and gaps

Testing follows the architecture boundaries rather than relying only on
end-to-end tests:

- **Unit tests** cover canonical JSON, SHA-256 hashing, genesis behavior,
  field commitments, JSON Pointer paths, and redaction projection logic.
- **Application tests** cover append ordering, idempotency, rollback behavior,
  retention decisions, checkpoints, redaction state, and export verification.
- **API tests** cover validation, pagination, verification, redaction, export,
  authentication, authorization scopes, actor attribution, and delegation.
- **Tamper tests** cover modified records, hashes, redaction metadata,
  presentation payloads, export components, proof data, and signatures.
- **Concurrency tests** cover multiple appenders, duplicate requests, rollback
  under contention, and concurrent redaction attempts.
- **Database integration tests** use PostgreSQL/Testcontainers for schema,
  migration, persistence, archive, and transaction behavior.

The testing approach intentionally verifies separate claims:

1. chain integrity;
2. export/component integrity;
3. redaction consistency;
4. signature validity;
5. authorization and actor attribution.

Not covered by the current validation:

- PostgreSQL/Testcontainers execution in this environment, because Docker was
  unavailable;
- production identity-provider integration;
- production key rotation, revocation, or compromise recovery;
- performance, load, soak, and large-scale export benchmarks;
- disaster recovery, backup restoration, and cross-region behavior;
- completeness of upstream access-event capture across external systems;
- legal admissibility or regulator acceptance.

These gaps remain because they require deployment infrastructure, approved
compliance policy, production identity/key services, or operational targets
that are outside the prototype boundary.

## 8. Limitations

- No external identity provider.
- No production authorization-policy integration.
- No external KMS, encryption, or key destruction.
- No external chain-head anchoring.
- No WORM storage.
- No external timestamping.
- No selective-disclosure or advanced range proofs.
- No guarantee against complete privileged database replacement.
- No guarantee that every upstream application access is logged unless those
  applications emit events.
- No legal determination of regulator, jurisdiction, retention period, or
  admissibility.
- No claim that a redacted payload equals the original payload.
- No claim that a redacted value was destroyed from backups, replicas, logs,
  or exports.
- No claim that a valid hash chain proves access authorization.
- No claim that a signed export proves query completeness.
- Performance, availability, recovery, and multi-region targets remain
  unspecified.

## 9. Human review required

Before production use, a reviewer must approve:

- regulator and jurisdiction scope;
- exact client/account access-event semantics;
- identity, delegation, and authorization policy;
- tenant and resource access boundaries;
- retention and legal-hold requirements;
- field-path and redactable-field policy;
- original-payload and backup deletion lifecycle;
- export disclosure and completeness claims;
- signing-key lifecycle and trust distribution;
- database roles and infrastructure network controls;
- performance, availability, recovery, and monitoring objectives.

The current implementation is a production-quality prototype foundation, not a
claim of regulatory certification or a complete production deployment.
