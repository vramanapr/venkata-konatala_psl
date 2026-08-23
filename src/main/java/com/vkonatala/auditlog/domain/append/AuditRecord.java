package com.vkonatala.auditlog.domain.append;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.UUID;

public record AuditRecord(
        UUID recordId,
        String chainId,
        long sequence,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Instant occurredAt,
        Instant recordedAt,
        JsonNode payload,
        int payloadSchemaVersion,
        String contentHash,
        String previousHash) {
}
