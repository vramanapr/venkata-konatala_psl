package com.vkonatala.auditlog.domain.redaction;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JsonPointerPathTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void canonicalizesEscapedTokens() {
        JsonPointerPath path = JsonPointerPath.parse("/customer/a~1b~0c");

        assertThat(path.value()).isEqualTo("/customer/a~1b~0c");
        assertThat(path.tokens()).containsExactly("customer", "a/b~c");
    }

    @Test
    void rejectsInvalidPointers() {
        assertThatThrownBy(() -> JsonPointerPath.parse("/"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> JsonPointerPath.parse("/items/~2"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resolvesNestedValue() throws Exception {
        var payload = objectMapper.readTree("""
                {"customer":{"accountNumber":"1234"}}
                """);

        assertThat(JsonPointerPath.parse("/customer/accountNumber").resolve(payload).asText())
                .isEqualTo("1234");
    }
}
