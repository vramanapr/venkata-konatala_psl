CREATE TABLE audit_chain_head
(
    chain_id       VARCHAR(100) PRIMARY KEY,
    next_sequence  BIGINT       NOT NULL,
    last_record_id UUID,
    genesis_hash   CHAR(64)     NOT NULL,
    last_hash      CHAR(64)     NOT NULL,
    version        BIGINT       NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_chain_head_next_sequence_positive CHECK (next_sequence > 0),
    CONSTRAINT audit_chain_head_version_non_negative CHECK (version >= 0),
    CONSTRAINT audit_chain_head_genesis_hash_format
        CHECK (genesis_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_head_last_hash_format
        CHECK (last_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE audit_record
(
    record_id             UUID PRIMARY KEY,
    chain_id              VARCHAR(100) NOT NULL,
    sequence              BIGINT       NOT NULL,
    event_type            VARCHAR(200) NOT NULL,
    actor_id              VARCHAR(500) NOT NULL,
    resource_type         VARCHAR(200) NOT NULL,
    resource_id           VARCHAR(500) NOT NULL,
    occurred_at           TIMESTAMPTZ,
    recorded_at           TIMESTAMPTZ  NOT NULL,
    payload_document      JSONB        NOT NULL,
    payload_schema_version INTEGER      NOT NULL,
    content_hash          CHAR(64)     NOT NULL,
    previous_hash         CHAR(64)     NOT NULL,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_record_chain_sequence_unique UNIQUE (chain_id, sequence),
    CONSTRAINT audit_record_sequence_positive CHECK (sequence > 0),
    CONSTRAINT audit_record_payload_object CHECK (jsonb_typeof(payload_document) = 'object'),
    CONSTRAINT audit_record_payload_schema_version_positive
        CHECK (payload_schema_version > 0),
    CONSTRAINT audit_record_content_hash_format
        CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_record_previous_hash_format
        CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_record_chain_fk
        FOREIGN KEY (chain_id) REFERENCES audit_chain_head (chain_id)
);

CREATE INDEX audit_record_actor_sequence_idx
    ON audit_record (actor_id, sequence);

CREATE INDEX audit_record_resource_sequence_idx
    ON audit_record (resource_type, resource_id, sequence);

CREATE INDEX audit_record_event_type_sequence_idx
    ON audit_record (event_type, sequence);

CREATE INDEX audit_record_occurred_at_sequence_idx
    ON audit_record (occurred_at, sequence);

CREATE INDEX audit_record_recorded_at_sequence_idx
    ON audit_record (recorded_at, sequence);

CREATE TABLE audit_record_archive
(
    LIKE audit_record INCLUDING ALL
);

ALTER TABLE audit_record_archive
    ADD COLUMN archived_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE audit_idempotency
(
    idempotency_key   VARCHAR(500) PRIMARY KEY,
    request_fingerprint CHAR(64)   NOT NULL,
    record_id         UUID         NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TIMESTAMPTZ,
    CONSTRAINT audit_idempotency_fingerprint_format
        CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_idempotency_record_fk
        FOREIGN KEY (record_id) REFERENCES audit_record (record_id)
);

CREATE TABLE audit_redaction
(
    redaction_id UUID PRIMARY KEY,
    record_id    UUID         NOT NULL,
    path         VARCHAR(1000) NOT NULL,
    commitment   CHAR(64)     NOT NULL,
    reason       VARCHAR(2000) NOT NULL,
    requested_by VARCHAR(500) NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_redaction_commitment_format
        CHECK (commitment ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_redaction_record_fk
        FOREIGN KEY (record_id) REFERENCES audit_record (record_id)
);

CREATE INDEX audit_redaction_record_idx
    ON audit_redaction (record_id);

CREATE TABLE audit_archive_segment
(
    segment_id      UUID PRIMARY KEY,
    chain_id        VARCHAR(100) NOT NULL,
    first_sequence  BIGINT       NOT NULL,
    last_sequence   BIGINT       NOT NULL,
    first_hash      CHAR(64)     NOT NULL,
    last_hash       CHAR(64)     NOT NULL,
    record_count    BIGINT       NOT NULL,
    archived_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_archive_segment_range_valid
        CHECK (first_sequence > 0 AND last_sequence >= first_sequence),
    CONSTRAINT audit_archive_segment_record_count_positive
        CHECK (record_count > 0),
    CONSTRAINT audit_archive_segment_first_hash_format
        CHECK (first_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_archive_segment_last_hash_format
        CHECK (last_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_archive_segment_chain_fk
        FOREIGN KEY (chain_id) REFERENCES audit_chain_head (chain_id),
    CONSTRAINT audit_archive_segment_range_unique
        UNIQUE (chain_id, first_sequence, last_sequence)
);

REVOKE UPDATE, DELETE ON
    audit_chain_head,
    audit_record,
    audit_record_archive,
    audit_idempotency,
    audit_redaction,
    audit_archive_segment
FROM PUBLIC;
