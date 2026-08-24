package com.vkonatala.auditlog.domain.append;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.UUID;
import com.vkonatala.auditlog.domain.hash.AuditAuthorizationEvidence;

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
        int canonicalizationVersion,
        AuditAuthorizationEvidence authorization) {

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
                previousHash, contentHash, payload, contentHash, 1,
                AuditAuthorizationEvidence.legacy(actorId));
    }

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
            String previousHash,
            String payloadCommitment,
            JsonNode presentationPayload,
            String presentationHash,
            int canonicalizationVersion) {
        this(recordId, chainId, sequence, eventType, actorId, resourceType, resourceId,
                occurredAt, recordedAt, payload, payloadSchemaVersion, contentHash,
                previousHash, payloadCommitment, presentationPayload, presentationHash,
                canonicalizationVersion, AuditAuthorizationEvidence.legacy(actorId));
    }

    public AuditRecord {
        if (authorization == null) {
            throw new IllegalArgumentException("authorization must not be null");
        }
        if (actorId == null || !actorId.equals(authorization.effectiveActor())) {
            throw new IllegalArgumentException(
                    "actorId must match authorization effectiveActor");
        }
        payload = payload == null ? null : payload.deepCopy();
        presentationPayload = presentationPayload == null
                ? (payload == null ? null : payload.deepCopy())
                : presentationPayload.deepCopy();
    }

    public String principal() {
        return authorization.principal();
    }

    public String effectiveActor() {
        return authorization.effectiveActor();
    }

    public String delegatedBy() {
        return authorization.delegatedBy();
    }

    public String authorizationOutcome() {
        return authorization.outcome();
    }

    public String authorizationPolicy() {
        return authorization.policy();
    }

    public String authorizationReason() {
        return authorization.reason();
    }

    public JsonNode requestContext() {
        return authorization.requestContext();
    }
}
