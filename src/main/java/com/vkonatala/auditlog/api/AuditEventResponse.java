package com.vkonatala.auditlog.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.vkonatala.auditlog.domain.append.AuditRecord;

import java.time.Instant;
import java.util.UUID;

public record AuditEventResponse(
        UUID recordId,
        long sequence,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Instant timestamp,
        Instant recordedAt,
        JsonNode payload,
        String contentHash,
        String previousHash,
        String principal,
        String effectiveActor,
        String delegatedBy,
        String authorizationOutcome,
        String authorizationPolicy,
        String authorizationReason,
        JsonNode requestContext) {

    public static AuditEventResponse from(AuditRecord record) {
        return new AuditEventResponse(
                record.recordId(),
                record.sequence(),
                record.eventType(),
                record.actorId(),
                record.resourceType(),
                record.resourceId(),
                record.occurredAt(),
                record.recordedAt(),
                record.presentationPayload(),
                record.contentHash(),
                record.previousHash(),
                record.authorization().principal(),
                record.authorization().effectiveActor(),
                record.authorization().delegatedBy(),
                record.authorization().outcome(),
                record.authorization().policy(),
                record.authorization().reason(),
                record.authorization().requestContext());
    }
}
