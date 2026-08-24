package com.vkonatala.auditlog.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vkonatala.auditlog.domain.hash.AuditAuthorizationEvidence;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import com.fasterxml.jackson.annotation.JsonAlias;

import java.time.Instant;

public record AuditEventRequest(
        @NotBlank String eventType,
        String actorId,
        @NotBlank String resourceType,
        @NotBlank String resourceId,
        @NotNull JsonNode payload,
        @NotNull Instant timestamp,
        @JsonAlias({"effectiveActor", "delegatedActorId"}) String effectiveActorId,
        String delegationReason,
        JsonNode delegationEvidence) {

    public AuditEventRequest(
            String eventType, String actorId, String resourceType, String resourceId,
            JsonNode payload, Instant timestamp) {
        this(eventType, actorId, resourceType, resourceId, payload, timestamp,
                null, null, null);
    }

    public AuditEvent toDomain() {
        return toDomain(actorId, actorId, null, "ALLOWED", "audit:write",
                "legacy request", null);
    }

    public AuditEvent toDomain(
            String principal,
            String effectiveActor,
            String delegatedBy,
            String outcome,
            String policy,
            String reason,
            ObjectNode requestContext) {
        return new AuditEvent(eventType, effectiveActor, resourceType, resourceId, payload,
                timestamp, new AuditAuthorizationEvidence(principal, effectiveActor,
                        delegatedBy, outcome, policy, reason, requestContext));
    }
}
