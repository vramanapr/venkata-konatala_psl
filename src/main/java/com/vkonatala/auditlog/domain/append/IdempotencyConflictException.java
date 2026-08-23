package com.vkonatala.auditlog.domain.append;

public class IdempotencyConflictException extends RuntimeException {

    public IdempotencyConflictException(String idempotencyKey) {
        super("Idempotency key was already used with different event content: " + idempotencyKey);
    }
}
