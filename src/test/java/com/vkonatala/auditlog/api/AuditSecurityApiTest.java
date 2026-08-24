package com.vkonatala.auditlog.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.application.append.AuditLogAppender;
import com.vkonatala.auditlog.application.query.AuditQueryService;
import com.vkonatala.auditlog.application.verify.AuditChainVerifier;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.security.AuditSecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuditController.class)
@Import(AuditSecurityConfiguration.class)
@TestPropertySource(properties = {
        "audit.security.enabled=true",
        "audit.security.users=writer=secret|audit:write,reader=secret|audit:read,admin=secret|audit:admin"
})
class AuditSecurityApiTest {

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
    void rejectsUnauthenticatedRequests() throws Exception {
        mockMvc.perform(get("/api/v1/audit/events"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsForbiddenScope() throws Exception {
        mockMvc.perform(post("/api/v1/audit/events")
                        .with(httpBasic("reader", "secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson()))
                .andExpect(status().isForbidden());
    }

    @Test
    void attributesAuthenticatedPrincipalInsteadOfRequestActor() throws Exception {
        AuditRecord record = new AuditRecord(UUID.randomUUID(), "default", 1,
                "USER_LOGIN", "writer", "ACCOUNT", "1",
                Instant.parse("2026-08-23T10:15:30Z"),
                Instant.parse("2026-08-23T10:15:31Z"),
                objectMapper.readTree("{\"ok\":true}"), 1,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        when(appender.append(any(), any())).thenReturn(record);

        mockMvc.perform(post("/api/v1/audit/events")
                        .with(httpBasic("writer", "secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.actorId").value("writer"))
                .andExpect(jsonPath("$.principal").value("writer"));
    }

    @Test
    void recordsAuthorizedDelegationEvidence() throws Exception {
        AuditRecord record = new AuditRecord(UUID.randomUUID(), "default", 1,
                "USER_LOGIN", "target", "ACCOUNT", "1",
                Instant.parse("2026-08-23T10:15:30Z"),
                Instant.parse("2026-08-23T10:15:31Z"),
                objectMapper.readTree("{\"ok\":true}"), 1,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        when(appender.append(any(), any())).thenReturn(record);

        mockMvc.perform(post("/api/v1/audit/events")
                        .with(httpBasic("admin", "secret"))
                        .header("X-Request-Id", "req-7")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson().replace("\"spoofed\"", "\"target\"")
                                .replace("\"timestamp\"", "\"effectiveActorId\":\"target\","
                                        + "\"delegationReason\":\"support case\","
                                        + "\"delegationEvidence\":{\"ticket\":\"INC-7\"},\"timestamp\"")))
                .andExpect(status().isCreated());

        var captor = org.mockito.ArgumentCaptor.forClass(AuditEvent.class);
        verify(appender).append(captor.capture(), any());
        assertThat(captor.getValue().authorization().principal()).isEqualTo("admin");
        assertThat(captor.getValue().authorization().effectiveActor()).isEqualTo("target");
        assertThat(captor.getValue().authorization().delegatedBy()).isEqualTo("admin");
        assertThat(captor.getValue().authorization().reason()).isEqualTo("support case");
        assertThat(captor.getValue().authorization().requestContext().path("requestId").asText())
                .isEqualTo("req-7");
    }

    @Test
    void rejectsDelegationWithoutEvidence() throws Exception {
        mockMvc.perform(post("/api/v1/audit/events")
                        .with(httpBasic("writer", "secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson().replace("\"spoofed\"", "\"target\"")
                                .replace("\"timestamp\"", "\"effectiveActorId\":\"target\","
                                        + "\"delegationReason\":\"support case\",\"timestamp\"")))
                .andExpect(status().isForbidden());
    }

    private String eventJson() {
        return """
                {"eventType":"USER_LOGIN","actorId":"spoofed",
                 "resourceType":"ACCOUNT","resourceId":"1",
                 "payload":{"ok":true},"timestamp":"2026-08-23T10:15:30Z"}
                """;
    }
}
