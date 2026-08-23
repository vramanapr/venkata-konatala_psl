package com.vkonatala.auditlog.domain.redaction;

import java.util.UUID;

public record RedactionResult(
        UUID recordId,
        String path,
        UUID redactionId,
        String state,
        boolean replayed) {
}
