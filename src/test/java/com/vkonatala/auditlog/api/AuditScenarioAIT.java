package com.vkonatala.auditlog.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "audit.security.enabled=false")
class AuditScenarioAIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("auditlog")
                    .withUsername("auditlog")
                    .withPassword("auditlog");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

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

    @Test
    void writesQueriesAndVerifiesAuditEvents() throws Exception {
        append("""
                {
                  "eventType": "USER_LOGIN",
                  "actorId": "user-1",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "account-1",
                  "payload": {"method": "password"},
                  "timestamp": "2026-08-23T10:15:30Z"
                }
                """);
        append("""
                {
                  "eventType": "RECORD_UPDATED",
                  "actorId": "user-2",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "account-1",
                  "payload": {"field": "address"},
                  "timestamp": "2026-08-23T10:16:30Z"
                }
                """);

        mockMvc.perform(get("/api/v1/audit/events")
                        .param("resourceType", "CLIENT_ACCOUNT")
                        .param("resourceId", "account-1")
                        .param("limit", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events.length()").value(1))
                .andExpect(jsonPath("$.events[0].sequence").value(1))
                .andExpect(jsonPath("$.nextSequence").value(1));

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.verifiedThroughSequence").value(2))
                .andExpect(jsonPath("$.firstFailure").doesNotExist());
    }

    @Test
    void detectsDirectPayloadMutation() throws Exception {
        append("""
                {
                  "eventType": "RECORD_UPDATED",
                  "actorId": "user-1",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "account-1",
                  "payload": {"amount": 10},
                  "timestamp": "2026-08-23T10:15:30Z"
                }
                """);
        jdbcTemplate.update("""
                UPDATE audit_record
                SET payload_document = '{"amount": 99}'::jsonb
                WHERE sequence = 1
                """);

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.firstFailure.sequence").value(1))
                .andExpect(jsonPath("$.firstFailure.violationType")
                        .value("CONTENT_HASH_MISMATCH"));
    }

    @Test
    void detectsDirectEventFieldMutation() throws Exception {
        append("""
                {
                  "eventType": "RECORD_UPDATED",
                  "actorId": "user-1",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "account-1",
                  "payload": {"amount": 10},
                  "timestamp": "2026-08-23T10:15:30Z"
                }
                """);
        jdbcTemplate.update("""
                UPDATE audit_record
                SET actor_id = 'different-user'
                WHERE sequence = 1
                """);

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.firstFailure.violationType")
                        .value("CONTENT_HASH_MISMATCH"));
    }

    @Test
    void detectsDirectContentHashMutation() throws Exception {
        append("""
                {
                  "eventType": "RECORD_UPDATED",
                  "actorId": "user-1",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "account-1",
                  "payload": {"amount": 10},
                  "timestamp": "2026-08-23T10:15:30Z"
                }
                """);
        jdbcTemplate.update("""
                UPDATE audit_record
                SET content_hash = repeat('0', 64)
                WHERE sequence = 1
                """);

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.firstFailure.violationType")
                        .value("CONTENT_HASH_MISMATCH"));
    }

    @Test
    void detectsDirectPreviousHashMutation() throws Exception {
        append(eventFor("user-1", "account-1", "RECORD_UPDATED", "10:15:30"));
        append(eventFor("user-1", "account-1", "RECORD_UPDATED", "10:16:30"));
        jdbcTemplate.update("""
                UPDATE audit_record
                SET previous_hash = repeat('0', 64)
                WHERE sequence = 2
                """);

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.firstFailure.sequence").value(2))
                .andExpect(jsonPath("$.firstFailure.violationType")
                        .value("PREVIOUS_HASH_MISMATCH"));
    }

    @Test
    void detectsDeletionOfFinalRecord() throws Exception {
        append(eventFor("user-1", "account-1", "RECORD_UPDATED", "10:15:30"));
        append(eventFor("user-1", "account-1", "RECORD_UPDATED", "10:16:30"));
        jdbcTemplate.update("DELETE FROM audit_record WHERE sequence = 2");

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.firstFailure.violationType")
                        .value("CHAIN_HEAD_MISMATCH"));
    }

    @Test
    void queriesByActorEventTypeAndTimeRange() throws Exception {
        append(eventFor("user-1", "account-1", "USER_LOGIN", "10:15:30"));
        append(eventFor("user-2", "account-2", "RECORD_UPDATED", "10:16:30"));
        append(eventFor("user-1", "account-3", "PERMISSION_GRANTED", "10:17:30"));

        mockMvc.perform(get("/api/v1/audit/events")
                        .param("actorId", "user-1")
                        .param("eventType", "PERMISSION_GRANTED")
                        .param("from", "2026-08-23T10:17:00Z")
                        .param("to", "2026-08-23T10:18:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events.length()").value(1))
                .andExpect(jsonPath("$.events[0].resourceId").value("account-3"));
    }

    @Test
    void traversesLargeResultSetUsingCursors() throws Exception {
        for (int index = 0; index < 101; index++) {
            append(eventFor("user-" + index, "account-" + index,
                    "RECORD_UPDATED", "10:15:30"));
        }

        mockMvc.perform(get("/api/v1/audit/events").param("limit", "100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events.length()").value(100))
                .andExpect(jsonPath("$.nextSequence").value(100));

        mockMvc.perform(get("/api/v1/audit/events")
                        .param("afterSequence", "100")
                        .param("limit", "100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events.length()").value(1))
                .andExpect(jsonPath("$.events[0].sequence").value(101));
    }

    private void append(String eventJson) throws Exception {
        mockMvc.perform(post("/api/v1/audit/events")
                        .contentType(APPLICATION_JSON)
                        .content(eventJson))
                .andExpect(status().isCreated());
    }

    private String eventFor(
            String actorId,
            String resourceId,
            String eventType,
            String time) {
        return """
                {
                  "eventType": "%s",
                  "actorId": "%s",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "%s",
                  "payload": {"source": "test"},
                  "timestamp": "2026-08-23T%sZ"
                }
                """.formatted(eventType, actorId, resourceId, time);
    }
}
