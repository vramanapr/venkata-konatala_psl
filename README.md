# Tamper-Evident Audit Log Service

## Project overview

This project is a Spring Boot audit-log service for append-only, tamper-evident
event recording. It uses a PostgreSQL-backed SHA-256 hash chain to preserve
deterministic record ordering and detect unauthorized changes.

The service includes:

- append, query, pagination, and chain-verification APIs;
- PostgreSQL persistence with Flyway migrations;
- concurrent-safe chain appends using a locked chain-head row;
- idempotency support for retried writes;
- configurable soft-delete and archive-table retention;
- durable chain checkpoints;
- structured field-level redaction with salted commitments;
- redaction-consistency verification;
- independently verifiable ZIP exports with full-prefix chain proofs;
- optional Ed25519 export-manifest signatures;
- authenticated prototype access with actor attribution, delegation, and
  authorization evidence.

The implementation is a production-quality prototype foundation. It does not
claim regulatory certification, production identity integration, external
integrity anchoring, WORM storage, encryption/key destruction, or complete
upstream access-event coverage.

## Quick start

### Prerequisites

- Java 21 JDK
- Maven 3.9+
- Docker Desktop or another Docker-compatible runtime
- Git
- Available local ports `5432` and `8080`

Docker is required for the local PostgreSQL database and Testcontainers
integration tests.

### Start PostgreSQL

From the repository root:

```bash
export POSTGRES_DB=auditlog
export POSTGRES_USER=auditlog_app
export POSTGRES_PASSWORD=change-this-locally
docker compose up -d postgres
```

### Configure and run the service

```bash
export DB_URL=jdbc:postgresql://localhost:5432/auditlog
export DB_USERNAME="$POSTGRES_USER"
export DB_PASSWORD="$POSTGRES_PASSWORD"
export AUDIT_SECURITY_USERS='writer=change-writer-password|audit:write,reader=change-reader-password|audit:read+audit:verify,admin=change-admin-password|audit:admin'
mvn spring-boot:run
```

Flyway applies database migrations during startup. Health is available at:

```text
http://localhost:8080/actuator/health
```

To disable application security globally for a local prototype run:

```bash
export AUDIT_SECURITY_ENABLED=false
```

This permits API requests without authentication and must not be used outside
an isolated development environment.

### Run tests

```bash
mvn test
```

Run the PostgreSQL/Testcontainers integration tests when Docker is available:

```bash
mvn verify
```

## Test and coverage artifacts

Behavioral coverage is documented in
[`docs/scenario-a-test-strategy.md`](docs/scenario-a-test-strategy.md). The
corresponding test artifacts are organized as follows:

- `src/test/java/com/vkonatala/auditlog/domain/hash/`: canonicalization and
  hash-chain unit tests.
- `src/test/java/com/vkonatala/auditlog/domain/redaction/`: path, commitment,
  and projection tests.
- `src/test/java/com/vkonatala/auditlog/application/`: append concurrency,
  retention, checkpoint, and export tests.
- `src/test/java/com/vkonatala/auditlog/api/`: validation, query,
  verification, redaction, export, authentication, and delegation tests.
- `AuditControllerTest` and `AuditScenarioAIT` explicitly set
  `audit.security.enabled=false` so API contract coverage can run without
  credentials; `AuditSecurityApiTest` covers the enabled-security behavior
  separately.
- `src/test/java/com/vkonatala/auditlog/AuditSchemaIT.java` and
  `PostgreSqlConnectionIT.java`: schema and database connectivity tests.

Run `mvn test` for non-container tests. Run `mvn verify` with Docker available
for the Testcontainers integration artifacts. The project does not currently
include a line-coverage reporting plugin; these artifacts provide behavioral
and integration coverage rather than a numeric coverage percentage.

## Documentation

- [`SETUP.md`](SETUP.md): complete local setup, configuration, API examples,
  troubleshooting, and shutdown instructions.
- [`docs/requirements.md`](docs/requirements.md): requirements and engineering
  decisions.
- [`docs/final-engineering-summary.md`](docs/final-engineering-summary.md):
  final architecture, artifacts, risks, testing, and limitations.
- [`docs/security-and-operations.md`](docs/security-and-operations.md):
  prototype security and least-privilege deployment guidance.
- [`docs/redaction-design.md`](docs/redaction-design.md): field-level
  redaction design.
- [`docs/export-design.md`](docs/export-design.md): bulk export and offline
  verification design.
- [`ai/AI_USAGE_LOG.md`](ai/AI_USAGE_LOG.md): meaningful AI-assisted
  engineering interactions.
- [`ATTESTATION.md`](ATTESTATION.md): submission attestation.

## Stop local PostgreSQL

```bash
docker compose down
```
