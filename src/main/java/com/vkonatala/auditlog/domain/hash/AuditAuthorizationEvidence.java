package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

/**
 * Server-derived authorization context recorded with every audit event.
 */
public record AuditAuthorizationEvidence(
        String principal,
        String effectiveActor,
        String delegatedBy,
        String outcome,
        String policy,
        String reason,
        JsonNode requestContext) {

    public AuditAuthorizationEvidence {
        requireText(principal, "principal");
        requireText(effectiveActor, "effectiveActor");
        requireText(outcome, "outcome");
        requireText(policy, "policy");
        requireText(reason, "reason");
        requestContext = requestContext == null
                ? JsonNodeFactory.instance.objectNode() : requestContext.deepCopy();
        if (!requestContext.isObject()) {
            throw new IllegalArgumentException("requestContext must be a JSON object");
        }
    }

    public static AuditAuthorizationEvidence legacy(String actor) {
        return new AuditAuthorizationEvidence(actor, actor, null, "ALLOWED",
                "audit:write", "legacy event", JsonNodeFactory.instance.objectNode());
    }

    @Override
    public JsonNode requestContext() {
        return requestContext.deepCopy();
    }

    private static void requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
