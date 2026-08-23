package com.vkonatala.auditlog.api;

import com.vkonatala.auditlog.domain.redaction.RedactionResult;

import java.util.UUID;

public record AuditRedactionResponse(
        UUID recordId,
        String path,
        UUID redactionId,
        String state,
        boolean replayed) {

    public static AuditRedactionResponse from(RedactionResult result) {
        return new AuditRedactionResponse(result.recordId(), result.path(),
                result.redactionId(), result.state(), result.replayed());
    }
}
