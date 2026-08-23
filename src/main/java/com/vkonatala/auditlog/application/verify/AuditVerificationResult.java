package com.vkonatala.auditlog.application.verify;

public record AuditVerificationResult(
        boolean intact,
        long verifiedThroughSequence,
        FirstFailure firstFailure) {

    public record FirstFailure(
            String recordId,
            long sequence,
            String violationType) {
    }
}
