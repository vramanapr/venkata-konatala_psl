package com.vkonatala.auditlog.domain.redaction;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.domain.hash.CanonicalJsonSerializer;
import com.vkonatala.auditlog.domain.hash.Sha256HashService;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class FieldCommitmentServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final FieldCommitmentService service = new FieldCommitmentService(
            objectMapper,
            new Sha256HashService(new CanonicalJsonSerializer()));

    @Test
    void sameValueAndSaltProduceSameCommitment() throws Exception {
        var value = objectMapper.readTree("\"account-123\"");
        var salt = HexFormat.of().parseHex("00112233445566778899aabbccddeeff");

        assertThat(service.commitment("/account", value, salt))
                .isEqualTo(service.commitment("/account", value, salt));
    }

    @Test
    void pathValueAndSaltAreBoundToCommitment() throws Exception {
        var value = objectMapper.readTree("\"account-123\"");
        var otherValue = objectMapper.readTree("\"account-999\"");
        var salt = HexFormat.of().parseHex("00112233445566778899aabbccddeeff");

        assertThat(service.commitment("/account", value, salt))
                .isNotEqualTo(service.commitment("/other", value, salt))
                .isNotEqualTo(service.commitment("/account", otherValue, salt))
                .isNotEqualTo(service.commitment("/account", value,
                        HexFormat.of().parseHex("ffeeddccbbaa99887766554433221100")));
    }
}
