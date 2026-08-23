package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class AuditHashChainTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditHashChain hashChain = new AuditHashChain(
            objectMapper,
            new Sha256HashService(new CanonicalJsonSerializer()));

    @Test
    void identicalEventsProduceIdenticalHashes() throws Exception {
        AuditEvent first = event("{\"amount\":10}");
        AuditEvent second = event("{\"amount\":10}");

        assertThat(hashChain.append(first, AuditHashChain.GENESIS_HASH))
                .isEqualTo(hashChain.append(second, AuditHashChain.GENESIS_HASH));
    }

    @Test
    void changedPayloadProducesDifferentHash() throws Exception {
        AuditHash original = hashChain.append(event("{\"amount\":10}"),
                AuditHashChain.GENESIS_HASH);
        AuditHash changed = hashChain.append(event("{\"amount\":11}"),
                AuditHashChain.GENESIS_HASH);

        assertThat(changed.contentHash()).isNotEqualTo(original.contentHash());
    }

    @Test
    void changedActorProducesDifferentHash() throws Exception {
        AuditHash original = hashChain.append(event("{\"amount\":10}"),
                AuditHashChain.GENESIS_HASH);
        AuditHash changed = hashChain.append(
                new AuditEvent(
                        "RECORD_UPDATED",
                        "different-actor",
                        "CLIENT_ACCOUNT",
                        "account-123",
                        objectMapper.readTree("{\"amount\":10}"),
                        Instant.parse("2026-08-23T10:15:30Z")),
                AuditHashChain.GENESIS_HASH);

        assertThat(changed.contentHash()).isNotEqualTo(original.contentHash());
    }

    @Test
    void changedTimestampProducesDifferentHash() throws Exception {
        AuditHash original = hashChain.append(event("{\"amount\":10}"),
                AuditHashChain.GENESIS_HASH);
        AuditHash changed = hashChain.append(
                new AuditEvent(
                        "RECORD_UPDATED",
                        "actor-123",
                        "CLIENT_ACCOUNT",
                        "account-123",
                        objectMapper.readTree("{\"amount\":10}"),
                        Instant.parse("2026-08-23T10:15:31Z")),
                AuditHashChain.GENESIS_HASH);

        assertThat(changed.contentHash()).isNotEqualTo(original.contentHash());
    }

    @Test
    void changedPreviousHashProducesDifferentChainResult() throws Exception {
        AuditHash original = hashChain.append(event("{\"amount\":10}"),
                AuditHashChain.GENESIS_HASH);
        AuditHash changed = hashChain.append(event("{\"amount\":10}"),
                "0000000000000000000000000000000000000000000000000000000000000000");

        assertThat(changed.previousHash()).isNotEqualTo(original.previousHash());
        assertThat(changed.contentHash()).isNotEqualTo(original.contentHash());
    }

    @Test
    void firstRecordUsesDefinedGenesisValue() throws Exception {
        AuditHash first = hashChain.createFirstRecord(event("{\"amount\":10}"));

        assertThat(first.previousHash()).isEqualTo(AuditHashChain.GENESIS_HASH);
        assertThat(AuditHashChain.GENESIS_HASH).hasSize(64);
    }

    private AuditEvent event(String payload) throws Exception {
        return new AuditEvent(
                "RECORD_UPDATED",
                "actor-123",
                "CLIENT_ACCOUNT",
                "account-123",
                objectMapper.readTree(payload),
                Instant.parse("2026-08-23T10:15:30Z"));
    }
}
