package com.vkonatala.auditlog.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.application.append.AuditLogAppender;
import com.vkonatala.auditlog.application.query.AuditQueryResult;
import com.vkonatala.auditlog.application.query.AuditQueryService;
import com.vkonatala.auditlog.application.verify.AuditChainVerifier;
import com.vkonatala.auditlog.application.verify.AuditVerificationResult;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.append.IdempotencyConflictException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuditController.class)
class AuditControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuditLogAppender appender;

    @MockBean
    private AuditQueryService queryService;

    @MockBean
    private AuditChainVerifier verifier;

    @Test
    void acceptsValidEvent() throws Exception {
        when(appender.append(any(), eq("request-1"))).thenReturn(record(1));

        mockMvc.perform(post("/api/v1/audit/events")
                        .header("Idempotency-Key", "request-1")
                        .contentType(APPLICATION_JSON)
                        .content(validEvent()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.sequence").value(1))
                .andExpect(jsonPath("$.eventType").value("USER_LOGIN"));
    }

    @Test
    void rejectsMissingRequiredField() throws Exception {
        mockMvc.perform(post("/api/v1/audit/events")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "USER_LOGIN",
                                  "resourceType": "CLIENT_ACCOUNT",
                                  "resourceId": "account-1",
                                  "payload": {},
                                  "timestamp": "2026-08-23T10:15:30Z"
                                }
                                """))
                .andExpect(status().isBadRequest());

        verify(appender, never()).append(any(), any());
    }

    @Test
    void rejectsInvalidPayload() throws Exception {
        mockMvc.perform(post("/api/v1/audit/events")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "USER_LOGIN",
                                  "actorId": "user-1",
                                  "resourceType": "CLIENT_ACCOUNT",
                                  "resourceId": "account-1",
                                  "payload": ["not", "an", "object"],
                                  "timestamp": "2026-08-23T10:15:30Z"
                                }
                                """))
                .andExpect(status().isBadRequest());

        verify(appender, never()).append(any(), any());
    }

    @Test
    void returnsFilteredPaginatedResults() throws Exception {
        when(queryService.query(any())).thenReturn(
                new AuditQueryResult(List.of(record(1)), 1L));

        mockMvc.perform(get("/api/v1/audit/events")
                        .param("actorId", "user-1")
                        .param("resourceType", "CLIENT_ACCOUNT")
                        .param("resourceId", "account-1")
                        .param("eventType", "USER_LOGIN")
                        .param("from", "2026-08-23T10:00:00Z")
                        .param("to", "2026-08-23T11:00:00Z")
                        .param("afterSequence", "0")
                        .param("limit", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events.length()").value(1))
                .andExpect(jsonPath("$.events[0].sequence").value(1))
                .andExpect(jsonPath("$.nextSequence").value(1));
    }

    @Test
    void returnsEmptyResults() throws Exception {
        when(queryService.query(any())).thenReturn(new AuditQueryResult(List.of(), null));

        mockMvc.perform(get("/api/v1/audit/events")
                        .param("actorId", "missing"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events").isEmpty())
                .andExpect(jsonPath("$.nextSequence").doesNotExist());
    }

    @Test
    void returnsVerificationResult() throws Exception {
        when(verifier.verify()).thenReturn(new AuditVerificationResult(true, 1, null));

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.verifiedThroughSequence").value(1));
    }

    @Test
    void forwardsIdempotencyKeyForDuplicateRequests() throws Exception {
        when(appender.append(any(), eq("request-1"))).thenReturn(record(1));

        mockMvc.perform(post("/api/v1/audit/events")
                        .header("Idempotency-Key", "request-1")
                        .contentType(APPLICATION_JSON)
                        .content(validEvent()))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/api/v1/audit/events")
                        .header("Idempotency-Key", "request-1")
                        .contentType(APPLICATION_JSON)
                        .content(validEvent()))
                .andExpect(status().isCreated());

        verify(appender, org.mockito.Mockito.times(2)).append(any(), eq("request-1"));
    }

    @Test
    void rejectsConflictingIdempotencyKeyReuse() throws Exception {
        when(appender.append(any(), eq("request-1")))
                .thenThrow(new IdempotencyConflictException("request-1"));

        mockMvc.perform(post("/api/v1/audit/events")
                        .header("Idempotency-Key", "request-1")
                        .contentType(APPLICATION_JSON)
                        .content(validEvent()))
                .andExpect(status().isConflict());
    }

    private String validEvent() {
        return """
                {
                  "eventType": "USER_LOGIN",
                  "actorId": "user-1",
                  "resourceType": "CLIENT_ACCOUNT",
                  "resourceId": "account-1",
                  "payload": {"method": "password"},
                  "timestamp": "2026-08-23T10:15:30Z"
                }
                """;
    }

    private AuditRecord record(long sequence) throws Exception {
        return new AuditRecord(
                UUID.randomUUID(),
                "default",
                sequence,
                "USER_LOGIN",
                "user-1",
                "CLIENT_ACCOUNT",
                "account-1",
                Instant.parse("2026-08-23T10:15:30Z"),
                Instant.parse("2026-08-23T10:15:31Z"),
                objectMapper().readTree("{\"method\":\"password\"}"),
                1,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    }

    private ObjectMapper objectMapper() {
        return objectMapper;
    }
}
