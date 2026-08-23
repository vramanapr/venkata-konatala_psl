package com.vkonatala.auditlog.domain.redaction;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RedactionProjectionServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RedactionProjectionService service =
            new RedactionProjectionService(objectMapper);

    @Test
    void replacesOnlyTheSelectedNestedField() throws Exception {
        var payload = objectMapper.readTree("""
                {"customer":{"accountNumber":"1234","name":"Ada"},"type":"login"}
                """);

        var result = service.redact(
                payload,
                JsonPointerPath.parse("/customer/accountNumber"),
                "{\"redacted\":true}");

        assertThat(result.at("/customer/accountNumber").get("redacted").asBoolean())
                .isTrue();
        assertThat(result.at("/customer/name").asText()).isEqualTo("Ada");
        assertThat(payload.at("/customer/accountNumber").asText()).isEqualTo("1234");
    }
}
