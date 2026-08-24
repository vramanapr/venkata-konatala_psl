package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;

public record AuditEvent(
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        JsonNode payload,
        Instant timestamp,
        AuditAuthorizationEvidence authorization) {

    public AuditEvent(
            String eventType,
            String actorId,
            String resourceType,
            String resourceId,
            JsonNode payload,
            Instant timestamp) {
        this(eventType, actorId, resourceType, resourceId, payload, timestamp,
                AuditAuthorizationEvidence.legacy(actorId));
    }

    public AuditEvent {
        requireText(eventType, "eventType");
        requireText(actorId, "actorId");
        requireText(resourceType, "resourceType");
        requireText(resourceId, "resourceId");
        if (payload == null || !payload.isObject()) {
            throw new IllegalArgumentException("payload must be a JSON object");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("timestamp must not be null");
        }
        if (authorization == null) {
            throw new IllegalArgumentException("authorization must not be null");
        }
        if (!actorId.equals(authorization.effectiveActor())) {
            throw new IllegalArgumentException(
                    "actorId must match authorization effectiveActor");
        }
        payload = payload.deepCopy();
    }

    @Override
    public JsonNode payload() {
        return payload.deepCopy();
    }

    private static void requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
