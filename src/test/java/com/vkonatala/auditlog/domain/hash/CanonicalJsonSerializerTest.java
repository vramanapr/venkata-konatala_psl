package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class CanonicalJsonSerializerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final CanonicalJsonSerializer serializer = new CanonicalJsonSerializer();

    @Test
    void sortsObjectKeysAndRemovesWhitespace() throws Exception {
        JsonNode node = objectMapper.readTree("""
                {
                  "z": 1,
                  "a": {"second": true, "first": null}
                }
                """);

        assertThat(serializer.serialize(node))
                        .isEqualTo("{\"a\":{\"first\":null,\"second\":true},\"z\":1}");
    }

    @Test
    void preservesArrayOrder() throws Exception {
        JsonNode node = objectMapper.readTree("[3, 1, 2]");

        assertThat(serializer.serialize(node)).isEqualTo("[3,1,2]");
    }

    @Test
    void normalizesDecimalNumbers() throws Exception {
        JsonNode node = objectMapper.readTree(
                "{\"whole\":1.0,\"zero\":-0.00,\"decimal\":12.3400}");

        assertThat(serializer.serialize(node))
                .isEqualTo("{\"decimal\":12.34,\"whole\":1,\"zero\":0}");
    }

    @Test
    void appliesJsonStringEscaping() throws Exception {
        JsonNode node = objectMapper.readTree("{\"text\":\"line\\n\\\"quoted\\\"\"}");

        assertThat(serializer.serialize(node))
                .isEqualTo("{\"text\":\"line\\n\\\"quoted\\\"\"}");
    }

    @Test
    void rejectsNonJsonNodeValues() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> serializer.serialize(null));
    }
}
