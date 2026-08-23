package com.vkonatala.auditlog.domain.redaction;

public record RedactionCommand(String path, String reason, String requestedBy) {
}
