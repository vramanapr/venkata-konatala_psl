package com.vkonatala.auditlog.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record AuditEventRequest(
        @NotBlank String eventType,
        @NotBlank String actorId,
        @NotBlank String resourceType,
        @NotBlank String resourceId,
        @NotNull JsonNode payload,
        @NotNull Instant timestamp) {

    public AuditEvent toDomain() {
        return new AuditEvent(
                eventType,
                actorId,
                resourceType,
                resourceId,
                payload,
                timestamp);
    }
}
