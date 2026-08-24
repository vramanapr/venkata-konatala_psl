# Local Setup

## Prerequisites

- Java 21 JDK
- Maven 3.9 or later
- Docker Desktop or another Docker-compatible runtime
- Git
- Ports `5432` and `8080` available locally

Docker is required for PostgreSQL and for Testcontainers integration tests.

## Configure PostgreSQL

From the repository root, set local development credentials in the shell:

```bash
export POSTGRES_DB=auditlog
export POSTGRES_USER=auditlog_app
export POSTGRES_PASSWORD=change-this-locally
```

Start PostgreSQL:

```bash
docker compose up -d postgres
```

Flyway applies the database migrations when the application starts.

## Configure the application

The application reads database settings from environment variables:

```bash
export DB_URL=jdbc:postgresql://localhost:5432/auditlog
export DB_USERNAME="$POSTGRES_USER"
export DB_PASSWORD="$POSTGRES_PASSWORD"
```

Security is enabled by default. Configure at least one local user and scope:

```bash
export AUDIT_SECURITY_USERS='writer=change-writer-password|audit:write,reader=change-reader-password|audit:read+audit:verify,admin=change-admin-password|audit:admin'
```

Supported prototype scopes are:

- `audit:write`
- `audit:read`
- `audit:verify`
- `audit:export`
- `audit:redact`
- `audit:admin`

Do not commit real passwords or private keys. The prototype uses HTTP Basic
authentication; production deployments should replace this with an approved
identity provider and secret-management solution.

Optional retention and checkpoint settings can be configured through:

```bash
export AUDIT_RETENTION_MODE=SOFT_DELETE
export AUDIT_RETENTION_WINDOW=365d
export AUDIT_RETENTION_ENABLED=true
export AUDIT_CHECKPOINT_ENABLED=true
```

Optional export signing is disabled by default. It requires an Ed25519 private
key and matching public key supplied through environment variables:

```bash
export AUDIT_EXPORT_SIGNATURE_ENABLED=false
export AUDIT_EXPORT_SIGNATURE_KEY_ID=export-key-1
```

## Run the application

```bash
mvn spring-boot:run
```

The service starts on port `8080`.

Health checks:

```bash
curl http://localhost:8080/actuator/health
```

## Example API calls

Append an event:

```bash
curl -u writer:change-writer-password \
  -X POST http://localhost:8080/api/v1/audit/events \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: local-event-1' \
  -d '{
    "eventType": "USER_LOGIN",
    "actorId": "ignored-when-authenticated",
    "resourceType": "CLIENT_ACCOUNT",
    "resourceId": "account-1",
    "payload": {"method": "password"},
    "timestamp": "2026-08-24T09:00:00Z"
  }'
```

Query events:

```bash
curl -u reader:change-reader-password \
  'http://localhost:8080/api/v1/audit/events?actorId=writer'
```

Verify the chain:

```bash
curl -u reader:change-reader-password \
  http://localhost:8080/api/v1/audit/verify
```

Export records for an actor or resource:

```bash
curl -u admin:change-admin-password \
  -o audit-export.zip \
  'http://localhost:8080/api/v1/audit/exports?actorId=writer'
```

## Run tests

Run unit, API, context, and other non-container tests:

```bash
mvn test
```

Run the full suite, including Testcontainers integration tests, after Docker
is available:

```bash
mvn verify
```

Integration tests create their own PostgreSQL containers and do not use the
local Compose database.

## Stop local services

```bash
docker compose down
```

To remove the local PostgreSQL volume and all local database data:

```bash
docker compose down -v
```

## Troubleshooting

- If startup reports missing `DB_USERNAME` or `DB_PASSWORD`, export both
  variables before running Maven.
- If PostgreSQL connection fails, check `docker compose ps` and confirm port
  `5432` is available.
- If API requests return `401`, provide valid Basic credentials.
- If API requests return `403`, use a user configured with the required scope.
- If Testcontainers cannot start, verify that Docker is running and accessible
  to the current user.
- If migrations fail, inspect the application logs before changing the
  database manually. Flyway migration history must remain consistent.

## Prototype limitations

- HTTP Basic and environment-configured in-memory users are for local
  prototyping only.
- Database role separation, network restrictions, secret rotation, and
  production signing-key management must be configured by the deployment
  environment.
- The service currently uses one default audit chain.
