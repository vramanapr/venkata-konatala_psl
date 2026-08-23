package com.vkonatala.auditlog.application.verify;

public record AuditVerificationResult(
        boolean intact,
        long verifiedThroughSequence,
        FirstFailure firstFailure,
        boolean redactionIntact,
        RedactionFailure redactionFailure) {

    public AuditVerificationResult(boolean intact, long verifiedThroughSequence,
                                   FirstFailure firstFailure) {
        this(intact, verifiedThroughSequence, firstFailure, true, null);
    }

    public record FirstFailure(
            String recordId,
            long sequence,
            String violationType) {
    }

    public record RedactionFailure(
            String recordId,
            long sequence,
            String violationType) {
    }
}
