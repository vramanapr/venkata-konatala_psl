# Scenario A Test Strategy

Scenario A verifies append-only audit writes, filtered retrieval, deterministic
hash chaining, and detection of direct datastore tampering. PostgreSQL
integration tests use Testcontainers and should run with Docker available.

| ID | Test | Classification | Expected result |
| --- | --- | --- | --- |
| A-01 | Create a valid event with all required fields. | API, integration | Returns `201 Created`, a record ID, sequence, hashes, and persisted event data. |
| A-02 | Omit each required request field. | API, unit | Returns `400 Bad Request`; no record is appended. |
| A-03 | Submit a non-object or malformed payload. | API, unit | Returns `400 Bad Request`; no record is appended. |
| A-04 | Query using each supported filter and valid combinations. | API, database, integration | Returns only matching records in sequence order. |
| A-05 | Paginate using `limit` and `nextSequence`. | API, database, integration | Pages are bounded, ordered, non-overlapping, and eventually complete. |
| A-06 | Query a filter with no matches. | API, integration | Returns `200 OK` with an empty event list and no next cursor. |
| A-07 | Recompute a stored hash from the canonical event representation. | unit | Recomputed SHA-256 equals the stored content hash. |
| A-08 | Append multiple records. | integration, database | Sequences are contiguous and each predecessor hash equals the prior content hash. |
| A-09 | Append the first record. | unit, integration | Its predecessor hash equals the defined genesis hash. |
| A-10 | Verify an intact chain. | API, integration | Returns `intact: true` and the last verified sequence. |
| A-11 | Mutate a non-payload event field directly in the database. | database, failure/chaos | Verification returns the first record with `CONTENT_HASH_MISMATCH`. |
| A-12 | Mutate `payload_document` directly in the database. | database, failure/chaos | Verification returns the first record with `CONTENT_HASH_MISMATCH`. |
| A-13 | Mutate `content_hash` directly in the database. | database, failure/chaos | Verification returns the first record with `CONTENT_HASH_MISMATCH`. |
| A-14 | Mutate `previous_hash` directly in the database. | database, failure/chaos | Verification returns the affected record with `PREVIOUS_HASH_MISMATCH`. |
| A-15 | Delete a record directly in the database, including the final record. | database, failure/chaos | Verification reports a sequence gap or chain-head mismatch. |
| A-16 | Append concurrently from independent application instances. | integration, database, failure/chaos | Sequences are unique and contiguous; the chain has no conflicting predecessor links. |
| A-17 | Fail an append after record insertion is attempted. | integration, database, failure/chaos | The record, idempotency state, and chain head all roll back. |
| A-18 | Retry a request with the same idempotency key. | API, integration | Same request returns the original record; conflicting reuse returns `409 Conflict`. |
| A-19 | Query a large history. | integration, database, failure/chaos | Results remain bounded by the page limit and all records can be traversed without duplication or omission. |
| A-20 | Run API coverage with application security disabled. | API, configuration | An unauthenticated valid request reaches the controller and is tested against the API contract; this does not validate authentication or authorization. |

## Execution levels

- **Unit:** Canonicalization, hashing, domain validation, cursor validation,
  and controller error mapping.
- **API:** MockMvc tests for HTTP contracts, validation, filtering, pagination,
  empty results, and idempotency headers.
- **Integration/database:** Testcontainers PostgreSQL with Flyway migrations,
  real transactions, direct datastore mutation, and chain verification.
- **Failure/chaos:** Transaction-trigger failures, concurrent appends,
  deletion, mutation, and large-history traversal.
- **Security:** API contract coverage explicitly disables security through
  `audit.security.enabled=false` in `AuditControllerTest` and
  `AuditScenarioAIT`. Authentication, authorization, and delegation coverage
  remain separate in `AuditSecurityApiTest`; they must not be inferred from
  the security-disabled API scenarios.

## Exit criteria

All unit and API tests pass locally. All PostgreSQL integration tests pass in an
environment with Docker. Any unsupported operational behavior, such as
multi-region writes or physical deletion, remains explicitly out of scope.
