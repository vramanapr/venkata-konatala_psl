package com.vkonatala.auditlog.domain.redaction;

public class RedactionConflictException extends RuntimeException {
    public RedactionConflictException(String message) {
        super(message);
    }
}
