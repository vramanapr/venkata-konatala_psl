package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class Sha256HashServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Sha256HashService hashService =
            new Sha256HashService(new CanonicalJsonSerializer());

    @Test
    void hashesCanonicalJsonWithSha256() throws Exception {
        JsonNode first = objectMapper.readTree("{\"b\":2,\"a\":1}");
        JsonNode equivalent = objectMapper.readTree("{\"a\":1,\"b\":2}");

        assertThat(hashService.hash(first))
                .isEqualTo("43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777");
        assertThat(hashService.hash(first)).isEqualTo(hashService.hash(equivalent));
    }

    @Test
    void returnsLowercaseFullLengthSha256DigestForBytes() {
        String hash = hashService.hash("hello".getBytes(StandardCharsets.UTF_8));

        assertThat(hash)
                .isEqualTo("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }
}
