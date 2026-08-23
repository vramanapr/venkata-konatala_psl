package com.vkonatala.auditlog.domain.query;

import java.time.Instant;

public record AuditQueryCriteria(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        Instant from,
        Instant to,
        long afterSequence,
        int limit) {

    public AuditQueryCriteria {
        if ((resourceType == null) != (resourceId == null)) {
            throw new IllegalArgumentException(
                    "resourceType and resourceId must be supplied together");
        }
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("from must not be after to");
        }
        if (afterSequence < 0) {
            throw new IllegalArgumentException("afterSequence must not be negative");
        }
        if (limit < 1 || limit > 100) {
            throw new IllegalArgumentException("limit must be between 1 and 100");
        }
    }
}
