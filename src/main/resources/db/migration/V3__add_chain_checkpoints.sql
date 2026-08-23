CREATE TABLE audit_chain_checkpoint
(
    checkpoint_id   UUID PRIMARY KEY,
    chain_id        VARCHAR(100) NOT NULL,
    through_sequence BIGINT      NOT NULL,
    last_hash       CHAR(64)     NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_chain_checkpoint_sequence_positive
        CHECK (through_sequence > 0),
    CONSTRAINT audit_chain_checkpoint_hash_format
        CHECK (last_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_checkpoint_chain_fk
        FOREIGN KEY (chain_id) REFERENCES audit_chain_head (chain_id),
    CONSTRAINT audit_chain_checkpoint_unique
        UNIQUE (chain_id, through_sequence)
);

CREATE INDEX audit_chain_checkpoint_latest_idx
    ON audit_chain_checkpoint (chain_id, through_sequence DESC);
