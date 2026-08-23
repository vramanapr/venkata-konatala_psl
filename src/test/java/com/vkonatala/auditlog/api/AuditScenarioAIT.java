package com.vkonatala.auditlog.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
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
                .andExpect(jsonPath("$.nextSequence").value(2));

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

    private void append(String eventJson) throws Exception {
        mockMvc.perform(post("/api/v1/audit/events")
                        .contentType(APPLICATION_JSON)
                        .content(eventJson))
                .andExpect(status().isCreated());
    }
}
