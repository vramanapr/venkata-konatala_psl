package com.vkonatala.auditlog.application.retention;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.application.append.AuditLogAppender;
import com.vkonatala.auditlog.application.checkpoint.AuditCheckpointService;
import com.vkonatala.auditlog.application.query.AuditQueryService;
import com.vkonatala.auditlog.application.verify.AuditChainVerifier;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.domain.query.AuditQueryCriteria;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@SpringBootTest
class AuditRetentionIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("auditlog")
                    .withUsername("auditlog")
                    .withPassword("auditlog");

    @Autowired
    private AuditLogAppender appender;

    @Autowired
    private AuditRetentionService retentionService;

    @Autowired
    private AuditQueryService queryService;

    @Autowired
    private AuditChainVerifier verifier;

    @Autowired
    private AuditCheckpointService checkpointService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", POSTGRES::getJdbcUrl);
        registry.add("DB_USERNAME", POSTGRES::getUsername);
        registry.add("DB_PASSWORD", POSTGRES::getPassword);
        registry.add("AUDIT_RETENTION_WINDOW", () -> "30d");
        registry.add("AUDIT_RETENTION_INTERVAL_MS", () -> "3600000");
    }

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("""
                TRUNCATE TABLE audit_idempotency, audit_redaction,
                    audit_archive_segment, audit_record_archive,
                    audit_chain_checkpoint, audit_record,
                    audit_chain_head CASCADE
                """);
    }

    @Test
    void softArchivesOldRecordsAndKeepsChainVerifiable() {
        appender.append(event("old"), null);
        appender.append(event("new"), null);
        jdbcTemplate.update("""
                UPDATE audit_record
                SET recorded_at = CURRENT_TIMESTAMP - INTERVAL '31 days'
                WHERE sequence = 1
                """);

        assertThat(retentionService.archiveEligibleRecords()).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM audit_record WHERE archived_at IS NOT NULL",
                Integer.class)).isEqualTo(1);
        assertThat(queryService.query(new AuditQueryCriteria(
                null, null, null, null, null, null, 0, 50)).records())
                .extracting(record -> record.sequence())
                .containsExactly(2L);
        assertThat(verifier.verify().intact()).isTrue();
    }

    @Test
    void createsDurableCheckpointAndDetectsCheckpointMutation() {
        appender.append(event("account-1"), null);

        assertThat(checkpointService.createCheckpoint()).isPresent();
        assertThat(verifier.verify().intact()).isTrue();

        jdbcTemplate.update("""
                UPDATE audit_chain_checkpoint
                SET last_hash = repeat('0', 64)
                """);

        assertThat(verifier.verify().intact()).isFalse();
        assertThat(verifier.verify().firstFailure().violationType())
                .isEqualTo("CHECKPOINT_MISMATCH");
    }

    private AuditEvent event(String resourceId) {
        return new AuditEvent(
                "RECORD_UPDATED",
                "actor-1",
                "CLIENT_ACCOUNT",
                resourceId,
                objectMapper.createObjectNode().put("source", "test"),
                Instant.parse("2026-08-23T10:15:30Z"));
    }
}
