package com.vkonatala.auditlog.persistence.append;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.hash.AuditAuthorizationEvidence;
import com.vkonatala.auditlog.domain.query.AuditQueryCriteria;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class AuditRecordRepository {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public AuditRecordRepository(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void initializeChain(String chainId, String genesisHash) {
        jdbcTemplate.update("""
                INSERT INTO audit_chain_head
                    (chain_id, next_sequence, last_record_id, genesis_hash, last_hash, version)
                VALUES (?, 1, NULL, ?, ?, 0)
                ON CONFLICT (chain_id) DO NOTHING
                """, chainId, genesisHash, genesisHash);
    }

    public ChainHead lockChainHead(String chainId) {
        return jdbcTemplate.queryForObject("""
                SELECT chain_id, next_sequence, last_record_id, genesis_hash, last_hash, version
                FROM audit_chain_head
                WHERE chain_id = ?
                FOR UPDATE
                """, (resultSet, rowNumber) -> new ChainHead(
                resultSet.getString("chain_id"),
                resultSet.getLong("next_sequence"),
                (UUID) resultSet.getObject("last_record_id"),
                resultSet.getString("genesis_hash"),
                resultSet.getString("last_hash"),
                resultSet.getLong("version")), chainId);
    }

    public void insert(AuditRecord record) {
        jdbcTemplate.update("""
                INSERT INTO audit_record
                    (record_id, chain_id, sequence, event_type, actor_id, resource_type,
                     resource_id, occurred_at, recorded_at, payload_document,
                     payload_schema_version, content_hash, previous_hash,
                     payload_commitment, presentation_payload, presentation_hash,
                     canonicalization_version, principal_id, effective_actor_id, delegated_by,
                     authorization_outcome, authorization_policy, authorization_reason, request_context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?::jsonb, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?::jsonb)
                """,
                record.recordId(),
                record.chainId(),
                record.sequence(),
                record.eventType(),
                record.actorId(),
                record.resourceType(),
                timestamp(record.occurredAt()),
                timestamp(record.recordedAt()),
                toJson(record.payload()),
                record.payloadSchemaVersion(),
                record.contentHash(),
                record.previousHash(),
                record.payloadCommitment(),
                toJson(record.presentationPayload()),
                record.presentationHash(),
                record.canonicalizationVersion(),
                record.authorization().principal(), record.authorization().effectiveActor(),
                record.authorization().delegatedBy(), record.authorization().outcome(),
                record.authorization().policy(), record.authorization().reason(),
                toJson(record.authorization().requestContext()));
    }

    public void updateChainHead(String chainId, long nextSequence, UUID lastRecordId, String lastHash) {
        int updated = jdbcTemplate.update("""
                UPDATE audit_chain_head
                SET next_sequence = ?, last_record_id = ?, last_hash = ?,
                    version = version + 1, updated_at = CURRENT_TIMESTAMP
                WHERE chain_id = ?
                """, nextSequence, lastRecordId, lastHash, chainId);
        if (updated != 1) {
            throw new IllegalStateException("Expected exactly one chain head to be updated");
        }
    }

    public Optional<IdempotencyEntry> findIdempotency(String idempotencyKey) {
        return jdbcTemplate.query("""
                SELECT request_fingerprint, record_id
                FROM audit_idempotency
                WHERE idempotency_key = ?
                """, resultSet -> {
            if (!resultSet.next()) {
                return Optional.empty();
            }
            return Optional.of(new IdempotencyEntry(
                    resultSet.getString("request_fingerprint"),
                    (UUID) resultSet.getObject("record_id")));
        }, idempotencyKey);
    }

    public void insertIdempotency(String idempotencyKey, String requestFingerprint, UUID recordId) {
        jdbcTemplate.update("""
                INSERT INTO audit_idempotency
                    (idempotency_key, request_fingerprint, record_id)
                VALUES (?, ?, ?)
                """, idempotencyKey, requestFingerprint, recordId);
    }

    public Optional<AuditRecord> findById(UUID recordId) {
        return jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record
                WHERE record_id = ?
                """, resultSet -> {
            if (!resultSet.next()) {
                return Optional.empty();
            }
            return Optional.of(mapRecord(resultSet));
        }, recordId);
    }

    public Page findPage(String chainId, AuditQueryCriteria criteria) {
        StringBuilder sql = new StringBuilder("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record
                WHERE chain_id = ?
                  AND archived_at IS NULL
                """);
        List<Object> parameters = new ArrayList<>();
        parameters.add(chainId);

        if (criteria.actorId() != null) {
            sql.append(" AND actor_id = ?");
            parameters.add(criteria.actorId());
        }
        if (criteria.resourceType() != null) {
            sql.append(" AND resource_type = ? AND resource_id = ?");
            parameters.add(criteria.resourceType());
            parameters.add(criteria.resourceId());
        }
        if (criteria.eventType() != null) {
            sql.append(" AND event_type = ?");
            parameters.add(criteria.eventType());
        }
        if (criteria.from() != null) {
            sql.append(" AND occurred_at >= ?");
            parameters.add(timestamp(criteria.from()));
        }
        if (criteria.to() != null) {
            sql.append(" AND occurred_at <= ?");
            parameters.add(timestamp(criteria.to()));
        }
        if (criteria.afterSequence() > 0) {
            sql.append(" AND sequence > ?");
            parameters.add(criteria.afterSequence());
        }

        sql.append(" ORDER BY sequence LIMIT ?");
        parameters.add(criteria.limit() + 1);

        List<AuditRecord> records = jdbcTemplate.query(
                sql.toString(),
                (resultSet, rowNumber) -> mapRecord(resultSet),
                parameters.toArray());
        Long nextSequence = null;
        if (records.size() > criteria.limit()) {
            records.remove(criteria.limit());
            nextSequence = records.getLast().sequence();
        }
        return new Page(records, nextSequence);
    }

    public List<AuditRecord> findAllForVerification(String chainId) {
        return jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record
                WHERE chain_id = ? AND archived_at IS NULL
                UNION ALL
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record_archive
                WHERE chain_id = ?
                ORDER BY sequence
                """, (resultSet, rowNumber) -> mapRecord(resultSet), chainId, chainId);
    }

    /**
     * Returns the logical chain, merging active rows, soft-archived rows and
     * rows moved to the archive table without duplicating moved rows.
     */
    public List<ExportRecord> findLogicalRecordsForExport(String chainId) {
        return jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context,
                       archived
                FROM (
                    SELECT ar.record_id, ar.chain_id, ar.sequence, ar.event_type, ar.actor_id,
                           ar.resource_type, ar.resource_id, ar.occurred_at, ar.recorded_at,
                           ar.payload_document, ar.payload_schema_version, ar.content_hash,
                           ar.previous_hash, ar.payload_commitment, ar.presentation_payload,
                           ar.presentation_hash, ar.canonicalization_version,
                           ar.principal_id, ar.effective_actor_id, ar.delegated_by,
                           ar.authorization_outcome, ar.authorization_policy, ar.authorization_reason,
                           ar.request_context,
                           (ar.archived_at IS NOT NULL) AS archived
                    FROM audit_record ar
                    WHERE ar.chain_id = ?
                      AND NOT EXISTS (
                          SELECT 1 FROM audit_record_archive aa
                          WHERE aa.record_id = ar.record_id
                      )
                    UNION ALL
                    SELECT aa.record_id, aa.chain_id, aa.sequence, aa.event_type, aa.actor_id,
                           aa.resource_type, aa.resource_id, aa.occurred_at, aa.recorded_at,
                           aa.payload_document, aa.payload_schema_version, aa.content_hash,
                           aa.previous_hash, aa.payload_commitment, aa.presentation_payload,
                           aa.presentation_hash, aa.canonicalization_version,
                           aa.principal_id, aa.effective_actor_id, aa.delegated_by,
                           aa.authorization_outcome, aa.authorization_policy, aa.authorization_reason,
                           aa.request_context, TRUE AS archived
                    FROM audit_record_archive aa
                    WHERE aa.chain_id = ?
                ) logical_records
                ORDER BY sequence
                """, (resultSet, rowNumber) -> new ExportRecord(
                mapRecord(resultSet), resultSet.getBoolean("archived")), chainId, chainId);
    }

    public int markArchivedBefore(Instant cutoff) {
        return jdbcTemplate.update("""
                UPDATE audit_record
                SET archived_at = CURRENT_TIMESTAMP
                WHERE archived_at IS NULL
                  AND recorded_at < ?
                """, timestamp(cutoff));
    }

    public int archiveToTableBefore(Instant cutoff, int batchSize) {
        List<AuditRecord> eligibleRecords = jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record
                WHERE archived_at IS NULL
                  AND recorded_at < ?
                ORDER BY sequence
                LIMIT ?
                FOR UPDATE SKIP LOCKED
                """, (resultSet, rowNumber) -> mapRecord(resultSet),
                timestamp(cutoff), batchSize);

        for (AuditRecord record : eligibleRecords) {
            jdbcTemplate.update("""
                    INSERT INTO audit_record_archive
                        (record_id, chain_id, sequence, event_type, actor_id, resource_type,
                         resource_id, occurred_at, recorded_at, payload_document,
                         payload_schema_version, content_hash, previous_hash,
                         payload_commitment, presentation_payload, presentation_hash,
                         canonicalization_version, principal_id, effective_actor_id, delegated_by,
                         authorization_outcome, authorization_policy, authorization_reason, request_context)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?::jsonb, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?::jsonb)
                    ON CONFLICT (record_id) DO NOTHING
                    """,
                    record.recordId(),
                    record.chainId(),
                    record.sequence(),
                    record.eventType(),
                    record.actorId(),
                    record.resourceType(),
                    record.resourceId(),
                    timestamp(record.occurredAt()),
                    timestamp(record.recordedAt()),
                    toJson(record.payload()),
                    record.payloadSchemaVersion(),
                    record.contentHash(),
                    record.previousHash(),
                    record.payloadCommitment(),
                    toJson(record.presentationPayload()),
                    record.presentationHash(),
                    record.canonicalizationVersion(),
                    record.authorization().principal(), record.authorization().effectiveActor(),
                    record.authorization().delegatedBy(), record.authorization().outcome(),
                    record.authorization().policy(), record.authorization().reason(),
                    toJson(record.authorization().requestContext()));
            jdbcTemplate.update("""
                    UPDATE audit_record
                    SET archived_at = CURRENT_TIMESTAMP
                    WHERE record_id = ? AND archived_at IS NULL
                    """, record.recordId());
        }
        return eligibleRecords.size();
    }

    public Optional<Checkpoint> findLatestCheckpoint(String chainId) {
        return jdbcTemplate.query("""
                SELECT checkpoint_id, chain_id, through_sequence, last_hash, created_at
                FROM audit_chain_checkpoint
                WHERE chain_id = ?
                ORDER BY through_sequence DESC
                LIMIT 1
                """, resultSet -> {
            if (!resultSet.next()) {
                return Optional.empty();
            }
            return Optional.of(new Checkpoint(
                    (UUID) resultSet.getObject("checkpoint_id"),
                    resultSet.getString("chain_id"),
                    resultSet.getLong("through_sequence"),
                    resultSet.getString("last_hash"),
                    resultSet.getTimestamp("created_at").toInstant()));
        }, chainId);
    }

    public Optional<AuditRecord> findBySequence(String chainId, long sequence) {
        return jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record
                WHERE chain_id = ? AND sequence = ?
                UNION ALL
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record_archive
                WHERE chain_id = ? AND sequence = ?
                LIMIT 1
                """, resultSet -> {
            if (!resultSet.next()) {
                return Optional.empty();
            }
            return Optional.of(mapRecord(resultSet));
        }, chainId, sequence, chainId, sequence);
    }

    public void insertCheckpoint(
            UUID checkpointId,
            String chainId,
            long throughSequence,
            String lastHash) {
        jdbcTemplate.update("""
                INSERT INTO audit_chain_checkpoint
                    (checkpoint_id, chain_id, through_sequence, last_hash)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (chain_id, through_sequence) DO NOTHING
                """, checkpointId, chainId, throughSequence, lastHash);
    }

    public Optional<ChainHead> findChainHead(String chainId) {
        return jdbcTemplate.query("""
                SELECT chain_id, next_sequence, last_record_id, genesis_hash, last_hash, version
                FROM audit_chain_head
                WHERE chain_id = ?
                """, resultSet -> {
            if (!resultSet.next()) {
                return Optional.empty();
            }
            return Optional.of(new ChainHead(
                    resultSet.getString("chain_id"),
                    resultSet.getLong("next_sequence"),
                    (UUID) resultSet.getObject("last_record_id"),
                    resultSet.getString("genesis_hash"),
                    resultSet.getString("last_hash"),
                    resultSet.getLong("version")));
        }, chainId);
    }

    private AuditRecord mapRecord(ResultSet resultSet) throws SQLException {
        Timestamp occurredAt = resultSet.getTimestamp("occurred_at");
        return new AuditRecord(
                (UUID) resultSet.getObject("record_id"),
                resultSet.getString("chain_id"),
                resultSet.getLong("sequence"),
                resultSet.getString("event_type"),
                resultSet.getString("actor_id"),
                resultSet.getString("resource_type"),
                resultSet.getString("resource_id"),
                occurredAt == null ? null : occurredAt.toInstant(),
                resultSet.getTimestamp("recorded_at").toInstant(),
                readJson(resultSet.getString("payload_document")),
                resultSet.getInt("payload_schema_version"),
                resultSet.getString("content_hash"),
                resultSet.getString("previous_hash"),
                resultSet.getString("payload_commitment"),
                readJson(resultSet.getString("presentation_payload")),
                resultSet.getString("presentation_hash"),
                resultSet.getInt("canonicalization_version"),
                new AuditAuthorizationEvidence(
                        resultSet.getString("principal_id"),
                        resultSet.getString("effective_actor_id"),
                        resultSet.getString("delegated_by"),
                        resultSet.getString("authorization_outcome"),
                        resultSet.getString("authorization_policy"),
                        resultSet.getString("authorization_reason"),
                        readJson(resultSet.getString("request_context"))));
    }

    public Optional<AuditRecord> lockById(UUID recordId) {
        return jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash,
                       payload_commitment, presentation_payload, presentation_hash,
                       canonicalization_version, principal_id, effective_actor_id, delegated_by,
                       authorization_outcome, authorization_policy, authorization_reason, request_context
                FROM audit_record WHERE record_id = ? FOR UPDATE
                """, resultSet -> resultSet.next()
                ? Optional.of(mapRecord(resultSet)) : Optional.empty(), recordId);
    }

    public List<FieldCommitment> findFieldCommitments(UUID recordId) {
        return jdbcTemplate.query("""
                SELECT commitment_id, record_id, path, format_version, algorithm, digest, salt
                FROM audit_field_commitment WHERE record_id = ? ORDER BY path
                """, (rs, row) -> new FieldCommitment(
                (UUID) rs.getObject("commitment_id"), (UUID) rs.getObject("record_id"),
                rs.getString("path"), rs.getInt("format_version"),
                rs.getString("algorithm"), rs.getString("digest"), rs.getBytes("salt")), recordId);
    }

    public Optional<FieldCommitment> findFieldCommitment(UUID recordId, String path) {
        return findFieldCommitments(recordId).stream()
                .filter(commitment -> commitment.path().equals(path)).findFirst();
    }

    public void insertFieldCommitment(UUID commitmentId, UUID recordId, String path,
                                      int formatVersion, String algorithm, String digest, byte[] salt) {
        jdbcTemplate.update("""
                INSERT INTO audit_field_commitment
                    (commitment_id, record_id, path, format_version, algorithm, digest, salt)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, commitmentId, recordId, path, formatVersion, algorithm, digest, salt);
    }

    public List<Redaction> findRedactions(UUID recordId) {
        return jdbcTemplate.query("""
                SELECT redaction_id, record_id, path, commitment, reason, requested_by,
                       created_at, commitment_id, request_key, request_fingerprint,
                       redaction_sequence, previous_redaction_hash, presentation_hash, operation_hash
                FROM audit_redaction WHERE record_id = ? ORDER BY redaction_sequence, created_at, redaction_id
                """, (rs, row) -> mapRedaction(rs), recordId);
    }

    public Optional<Redaction> findRedactionByRequestKey(String requestKey) {
        return jdbcTemplate.query("""
                SELECT redaction_id, record_id, path, commitment, reason, requested_by,
                       created_at, commitment_id, request_key, request_fingerprint,
                       redaction_sequence, previous_redaction_hash, presentation_hash, operation_hash
                FROM audit_redaction WHERE request_key = ?
                """, resultSet -> resultSet.next()
                ? Optional.of(mapRedaction(resultSet)) : Optional.empty(), requestKey);
    }

    public void insertRedaction(Redaction redaction) {
        jdbcTemplate.update("""
                INSERT INTO audit_redaction
                    (redaction_id, record_id, path, commitment, reason, requested_by,
                     created_at, commitment_id, request_key, request_fingerprint,
                     redaction_sequence, previous_redaction_hash, presentation_hash, operation_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, redaction.redactionId(), redaction.recordId(), redaction.path(),
                redaction.commitment(), redaction.reason(), redaction.requestedBy(),
                Timestamp.from(redaction.createdAt()), redaction.commitmentId(),
                redaction.requestKey(), redaction.requestFingerprint(), redaction.sequence(),
                redaction.previousRedactionHash(), redaction.presentationHash(), redaction.operationHash());
    }

    public void updatePresentation(UUID recordId, JsonNode payload, String presentationHash) {
        int updated = jdbcTemplate.update("""
                UPDATE audit_record SET presentation_payload = ?, presentation_hash = ?
                WHERE record_id = ?
                """, toJson(payload), presentationHash, recordId);
        if (updated != 1) throw new IllegalStateException("Audit record disappeared during redaction");
    }

    private Redaction mapRedaction(ResultSet rs) throws SQLException {
        return new Redaction(
                (UUID) rs.getObject("redaction_id"), (UUID) rs.getObject("record_id"),
                rs.getString("path"), rs.getString("commitment"), rs.getString("reason"),
                rs.getString("requested_by"), rs.getTimestamp("created_at").toInstant(),
                (UUID) rs.getObject("commitment_id"), rs.getString("request_key"),
                rs.getString("request_fingerprint"), rs.getLong("redaction_sequence"),
                rs.getString("previous_redaction_hash"), rs.getString("presentation_hash"),
                rs.getString("operation_hash"));
    }

    private String toJson(JsonNode payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to serialize audit payload", exception);
        }
    }

    private JsonNode readJson(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to deserialize audit payload", exception);
        }
    }

    private Timestamp timestamp(java.time.Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    public record ChainHead(
            String chainId,
            long nextSequence,
            UUID lastRecordId,
            String genesisHash,
            String lastHash,
            long version) {
    }

    public record IdempotencyEntry(String requestFingerprint, UUID recordId) {
    }

    public record FieldCommitment(
            UUID commitmentId, UUID recordId, String path, int formatVersion,
            String algorithm, String digest, byte[] salt) {
        public FieldCommitment {
            salt = salt.clone();
        }
    }

    public record Redaction(
            UUID redactionId, UUID recordId, String path, String commitment,
            String reason, String requestedBy, Instant createdAt, UUID commitmentId,
            String requestKey, String requestFingerprint, long sequence,
            String previousRedactionHash, String presentationHash, String operationHash) {
    }

    public record Page(List<AuditRecord> records, Long nextSequence) {
    }

    public record ExportRecord(AuditRecord record, boolean archived) {
    }

    public record Checkpoint(
            UUID checkpointId,
            String chainId,
            long throughSequence,
            String lastHash,
            java.time.Instant createdAt) {
    }
}
