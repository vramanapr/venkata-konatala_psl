ALTER TABLE audit_record
    ADD COLUMN payload_commitment CHAR(64),
    ADD COLUMN presentation_payload JSONB,
    ADD COLUMN presentation_hash CHAR(64),
    ADD COLUMN canonicalization_version INTEGER;

UPDATE audit_record
SET payload_commitment = content_hash,
    presentation_payload = payload_document,
    presentation_hash = content_hash,
    canonicalization_version = 0
WHERE payload_commitment IS NULL;

ALTER TABLE audit_record
    ALTER COLUMN payload_commitment SET NOT NULL,
    ALTER COLUMN presentation_payload SET NOT NULL,
    ALTER COLUMN presentation_hash SET NOT NULL,
    ALTER COLUMN canonicalization_version SET NOT NULL;

ALTER TABLE audit_record_archive
    ADD COLUMN payload_commitment CHAR(64),
    ADD COLUMN presentation_payload JSONB,
    ADD COLUMN presentation_hash CHAR(64),
    ADD COLUMN canonicalization_version INTEGER;

UPDATE audit_record_archive
SET payload_commitment = content_hash,
    presentation_payload = payload_document,
    presentation_hash = content_hash,
    canonicalization_version = 0
WHERE payload_commitment IS NULL;

ALTER TABLE audit_record_archive
    ALTER COLUMN payload_commitment SET NOT NULL,
    ALTER COLUMN presentation_payload SET NOT NULL,
    ALTER COLUMN presentation_hash SET NOT NULL,
    ALTER COLUMN canonicalization_version SET NOT NULL;

CREATE TABLE audit_field_commitment
(
    commitment_id UUID PRIMARY KEY,
    record_id UUID NOT NULL,
    path VARCHAR(1000) NOT NULL,
    format_version INTEGER NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    digest CHAR(64) NOT NULL,
    salt BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_field_commitment_path_unique UNIQUE (record_id, path),
    CONSTRAINT audit_field_commitment_digest_format CHECK (digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_field_commitment_salt_size CHECK (octet_length(salt) = 16),
    CONSTRAINT audit_field_commitment_record_fk
        FOREIGN KEY (record_id) REFERENCES audit_record(record_id)
);

ALTER TABLE audit_redaction
    ADD COLUMN commitment_id UUID,
    ADD COLUMN request_key VARCHAR(500),
    ADD COLUMN request_fingerprint CHAR(64),
    ADD COLUMN redaction_sequence BIGINT,
    ADD COLUMN previous_redaction_hash CHAR(64),
    ADD COLUMN presentation_hash CHAR(64),
    ADD COLUMN operation_hash CHAR(64);

CREATE UNIQUE INDEX audit_redaction_request_key_unique
    ON audit_redaction(request_key)
    WHERE request_key IS NOT NULL;
CREATE UNIQUE INDEX audit_redaction_record_path_unique
    ON audit_redaction(record_id, path);

ALTER TABLE audit_redaction
    ADD CONSTRAINT audit_redaction_commitment_fk
        FOREIGN KEY (commitment_id) REFERENCES audit_field_commitment(commitment_id),
    ADD CONSTRAINT audit_redaction_fingerprint_format
        CHECK (request_fingerprint IS NULL OR request_fingerprint ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT audit_redaction_previous_hash_format
        CHECK (previous_redaction_hash IS NULL OR previous_redaction_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT audit_redaction_presentation_hash_format
        CHECK (presentation_hash IS NULL OR presentation_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT audit_redaction_operation_hash_format
        CHECK (operation_hash IS NULL OR operation_hash ~ '^[0-9a-f]{64}$');

REVOKE UPDATE, DELETE ON audit_field_commitment FROM PUBLIC;
