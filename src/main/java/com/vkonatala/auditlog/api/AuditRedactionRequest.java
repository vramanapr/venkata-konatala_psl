package com.vkonatala.auditlog.api;

import com.vkonatala.auditlog.domain.redaction.RedactionCommand;
import jakarta.validation.constraints.NotBlank;

public record AuditRedactionRequest(
        @NotBlank String path,
        @NotBlank String reason,
        String requestedBy) {

    public RedactionCommand toDomain() {
        return new RedactionCommand(path, reason,
                requestedBy == null || requestedBy.isBlank() ? "system" : requestedBy);
    }
}
