# Security and least-privilege prototype

Application security is enabled by default (`AUDIT_SECURITY_ENABLED=true`).
Prototype HTTP Basic users are supplied only through `AUDIT_SECURITY_USERS`:

```text
writer=${SECRET}|audit:write
reader=${SECRET}|audit:read+audit:verify
operator=${SECRET}|audit:export+audit:redact
admin=${SECRET}|audit:admin
```

Passwords must be injected by the deployment secret store; no password is
stored in source or the container image. The API denies unknown routes and
requires the following scopes: `audit:write`, `audit:read`, `audit:verify`,
`audit:export`, `audit:redact`, or `audit:admin`. Delegation requires
`audit:admin`. Health probes are public; all other management endpoints require
`audit:admin`.

The database application role should have only the JDBC privileges needed by
the service: `SELECT` on audit tables, `INSERT` on append/idempotency and
redaction tables, and narrowly scoped `UPDATE` on chain heads and presentation
projections. It should not have `CREATE`, `DROP`, or unrestricted `UPDATE` /
`DELETE` privileges. Flyway migrations should run with a separate deployment
role. PostgreSQL network access should be restricted to the application and
the migration job; management endpoints should be reachable only from the
operations network.

This is intentionally a prototype. External identity providers, mTLS, and
KMS-backed secret/signing key management are not implemented.
