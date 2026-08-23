package com.vkonatala.auditlog.persistence.append;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.query.AuditQueryCriteria;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

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
                     payload_schema_version, content_hash, previous_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?)
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
                record.previousHash());
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
                       payload_schema_version, content_hash, previous_hash
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
                       payload_schema_version, content_hash, previous_hash
                FROM audit_record
                WHERE chain_id = ?
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
            AuditRecord cursorRecord = records.remove(criteria.limit());
            nextSequence = cursorRecord.sequence();
        }
        return new Page(records, nextSequence);
    }

    public List<AuditRecord> findAllForVerification(String chainId) {
        return jdbcTemplate.query("""
                SELECT record_id, chain_id, sequence, event_type, actor_id, resource_type,
                       resource_id, occurred_at, recorded_at, payload_document,
                       payload_schema_version, content_hash, previous_hash
                FROM audit_record
                WHERE chain_id = ?
                ORDER BY sequence
                """, (resultSet, rowNumber) -> mapRecord(resultSet), chainId);
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
                resultSet.getString("previous_hash"));
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

    public record Page(List<AuditRecord> records, Long nextSequence) {
    }
}
