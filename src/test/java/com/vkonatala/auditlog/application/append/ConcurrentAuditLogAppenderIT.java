package com.vkonatala.auditlog.application.append;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
@SpringBootTest
class ConcurrentAuditLogAppenderIT {

    private static final int CONCURRENT_EVENTS = 32;

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("auditlog")
                    .withUsername("auditlog")
                    .withPassword("auditlog");

    @Autowired
    private AuditLogAppender appender;

    @Autowired
    private AuditRecordRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditHashChain hashChain;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", POSTGRES::getJdbcUrl);
        registry.add("DB_USERNAME", POSTGRES::getUsername);
        registry.add("DB_PASSWORD", POSTGRES::getPassword);
    }

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("""
                TRUNCATE TABLE audit_idempotency, audit_redaction,
                    audit_archive_segment, audit_record_archive,
                    audit_record, audit_chain_head CASCADE
                """);
    }

    @AfterEach
    void removeFailureTrigger() {
        jdbcTemplate.execute("""
                DROP TRIGGER IF EXISTS reject_failed_events ON audit_record
                """);
        jdbcTemplate.execute("DROP FUNCTION IF EXISTS reject_failed_events()");
    }

    @Test
    void concurrentAppendsProduceOneContinuousChain() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch ready = new CountDownLatch(CONCURRENT_EVENTS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuditRecord>> futures = new ArrayList<>();
        AuditLogAppender firstInstance = new AuditLogAppender(repository, hashChain, objectMapper);
        AuditLogAppender secondInstance = new AuditLogAppender(repository, hashChain, objectMapper);
        TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);

        for (int index = 0; index < CONCURRENT_EVENTS; index++) {
            int eventNumber = index;
            AuditLogAppender instance = index % 2 == 0 ? firstInstance : secondInstance;
            futures.add(executor.submit(() -> {
                ready.countDown();
                assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
                return transactionTemplate.execute(status ->
                        instance.append(event(eventNumber), null));
            }));
        }

        assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
        start.countDown();

        List<AuditRecord> records = futures.stream()
                .map(this::get)
                .toList();
        executor.shutdown();
        assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        List<ChainRow> chain = jdbcTemplate.query("""
                SELECT sequence, previous_hash, content_hash
                FROM audit_record
                ORDER BY sequence
                """, (resultSet, rowNumber) -> new ChainRow(
                resultSet.getLong("sequence"),
                resultSet.getString("previous_hash"),
                resultSet.getString("content_hash")));

        assertThat(records).hasSize(CONCURRENT_EVENTS);
        assertThat(chain).hasSize(CONCURRENT_EVENTS);
        assertThat(chain.stream().map(ChainRow::sequence).toList())
                .containsExactlyElementsOf(
                        java.util.stream.LongStream.rangeClosed(1, CONCURRENT_EVENTS)
                                .boxed()
                                .toList());
        assertThat(chain.stream().map(ChainRow::previousHash).distinct()).hasSize(CONCURRENT_EVENTS);
        assertThat(chain.getFirst().previousHash()).isEqualTo(AuditHashChain.GENESIS_HASH);
        for (int index = 1; index < chain.size(); index++) {
            assertThat(chain.get(index).previousHash())
                    .isEqualTo(chain.get(index - 1).contentHash());
        }
    }

    @Test
    void concurrentRetriesWithSameIdempotencyKeyCreateOneRecord() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuditRecord>> futures = new ArrayList<>();
        AuditEvent event = event(1);

        for (int index = 0; index < 8; index++) {
            futures.add(executor.submit(() -> {
                assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
                return appender.append(event, "retry-key");
            }));
        }
        start.countDown();

        List<AuditRecord> records = futures.stream()
                .map(this::get)
                .toList();
        executor.shutdown();
        assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        assertThat(records.stream().map(AuditRecord::recordId).distinct()).hasSize(1);
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM audit_record", Integer.class)).isEqualTo(1);
    }

    @Test
    void failedAppendRollsBackRecordAndChainHead() {
        jdbcTemplate.execute("""
                CREATE FUNCTION reject_failed_events() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.event_type = 'FAIL' THEN
                        RAISE EXCEPTION 'test append failure';
                    END IF;
                    RETURN NEW;
                END;
                $$;
                """);
        jdbcTemplate.execute("""
                CREATE TRIGGER reject_failed_events
                AFTER INSERT ON audit_record
                FOR EACH ROW EXECUTE FUNCTION reject_failed_events()
                """);

        assertThatThrownBy(() -> appender.append(failingEvent(), null))
                .isInstanceOf(DataAccessException.class);

        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM audit_record", Integer.class)).isZero();
        assertThat(jdbcTemplate.queryForObject(
                "SELECT next_sequence FROM audit_chain_head WHERE chain_id = 'default'",
                Long.class)).isEqualTo(1L);
        assertThat(jdbcTemplate.queryForObject(
                "SELECT last_hash FROM audit_chain_head WHERE chain_id = 'default'",
                String.class)).isEqualTo(AuditHashChain.GENESIS_HASH);
    }

    @Test
    void newAppenderContinuesFromDurableChainHead() {
        AuditRecord first = appender.append(event(1), null);
        AuditLogAppender restartedAppender = new AuditLogAppender(
                repository, hashChain, objectMapper);

        AuditRecord second = new TransactionTemplate(transactionManager)
                .execute(status -> restartedAppender.append(event(2), null));

        assertThat(first.sequence()).isEqualTo(1);
        assertThat(second).isNotNull();
        assertThat(second.sequence()).isEqualTo(2);
        assertThat(second.previousHash()).isEqualTo(first.contentHash());
    }

    private AuditEvent event(int eventNumber) {
        return new AuditEvent(
                "RECORD_UPDATED",
                "actor-" + eventNumber,
                "CLIENT_ACCOUNT",
                "account-" + eventNumber,
                objectMapper.createObjectNode().put("eventNumber", eventNumber),
                Instant.parse("2026-08-23T10:15:30Z"));
    }

    private AuditEvent failingEvent() {
        return new AuditEvent(
                "FAIL",
                "actor",
                "CLIENT_ACCOUNT",
                UUID.randomUUID().toString(),
                objectMapper.createObjectNode(),
                Instant.parse("2026-08-23T10:15:30Z"));
    }

    private AuditRecord get(Future<AuditRecord> future) {
        try {
            return future.get(10, TimeUnit.SECONDS);
        } catch (Exception exception) {
            throw new AssertionError("Concurrent append failed", exception);
        }
    }

    private record ChainRow(long sequence, String previousHash, String contentHash) {
    }
}
