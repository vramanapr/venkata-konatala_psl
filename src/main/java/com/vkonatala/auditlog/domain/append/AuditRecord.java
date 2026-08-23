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
        String previousHash,
        String payloadCommitment,
        JsonNode presentationPayload,
        String presentationHash,
        int canonicalizationVersion) {

    public AuditRecord(
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
        this(recordId, chainId, sequence, eventType, actorId, resourceType, resourceId,
                occurredAt, recordedAt, payload, payloadSchemaVersion, contentHash,
                previousHash, contentHash, payload, contentHash, 1);
    }

    public AuditRecord {
        payload = payload == null ? null : payload.deepCopy();
        presentationPayload = presentationPayload == null
                ? (payload == null ? null : payload.deepCopy())
                : presentationPayload.deepCopy();
    }
}
