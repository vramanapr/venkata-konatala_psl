ALTER TABLE audit_record
    ADD COLUMN archived_at TIMESTAMPTZ;

CREATE INDEX audit_record_active_sequence_idx
    ON audit_record (chain_id, sequence)
    WHERE archived_at IS NULL;
