ALTER TABLE audit_record
    ADD COLUMN principal_id VARCHAR(500),
    ADD COLUMN effective_actor_id VARCHAR(500),
    ADD COLUMN delegated_by VARCHAR(500),
    ADD COLUMN authorization_outcome VARCHAR(100),
    ADD COLUMN authorization_policy VARCHAR(500),
    ADD COLUMN authorization_reason VARCHAR(2000),
    ADD COLUMN request_context JSONB;

UPDATE audit_record
SET principal_id = actor_id,
    effective_actor_id = actor_id,
    authorization_outcome = 'ALLOWED',
    authorization_policy = 'audit:write',
    authorization_reason = 'legacy record',
    request_context = '{}'::jsonb
WHERE principal_id IS NULL;

-- Version zero preserves verification of records written before evidence was
-- added; all records written after this migration use version one.
UPDATE audit_record
SET canonicalization_version = 0
WHERE principal_id IS NOT NULL AND canonicalization_version = 1;

ALTER TABLE audit_record
    ALTER COLUMN principal_id SET NOT NULL,
    ALTER COLUMN effective_actor_id SET NOT NULL,
    ALTER COLUMN authorization_outcome SET NOT NULL,
    ALTER COLUMN authorization_policy SET NOT NULL,
    ALTER COLUMN authorization_reason SET NOT NULL,
    ALTER COLUMN request_context SET NOT NULL,
    ADD CONSTRAINT audit_record_request_context_object
        CHECK (jsonb_typeof(request_context) = 'object');

ALTER TABLE audit_record_archive
    ADD COLUMN principal_id VARCHAR(500),
    ADD COLUMN effective_actor_id VARCHAR(500),
    ADD COLUMN delegated_by VARCHAR(500),
    ADD COLUMN authorization_outcome VARCHAR(100),
    ADD COLUMN authorization_policy VARCHAR(500),
    ADD COLUMN authorization_reason VARCHAR(2000),
    ADD COLUMN request_context JSONB;

UPDATE audit_record_archive
SET principal_id = actor_id,
    effective_actor_id = actor_id,
    authorization_outcome = 'ALLOWED',
    authorization_policy = 'audit:write',
    authorization_reason = 'legacy record',
    request_context = '{}'::jsonb
WHERE principal_id IS NULL;

UPDATE audit_record_archive
SET canonicalization_version = 0
WHERE principal_id IS NOT NULL AND canonicalization_version = 1;

ALTER TABLE audit_record_archive
    ALTER COLUMN principal_id SET NOT NULL,
    ALTER COLUMN effective_actor_id SET NOT NULL,
    ALTER COLUMN authorization_outcome SET NOT NULL,
    ALTER COLUMN authorization_policy SET NOT NULL,
    ALTER COLUMN authorization_reason SET NOT NULL,
    ALTER COLUMN request_context SET NOT NULL,
    ADD CONSTRAINT audit_record_archive_request_context_object
        CHECK (jsonb_typeof(request_context) = 'object');

CREATE INDEX audit_record_principal_sequence_idx
    ON audit_record (principal_id, sequence);
