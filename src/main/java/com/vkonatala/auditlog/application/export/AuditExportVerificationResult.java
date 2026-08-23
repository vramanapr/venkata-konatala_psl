package com.vkonatala.auditlog.application.export;

import java.util.List;

public record AuditExportVerificationResult(
        String componentIntegrity,
        String chainIntegrity,
        String redactionConsistency,
        String signatureValidity,
        List<Failure> failures) {

    public boolean verified() {
        return "VALID".equals(componentIntegrity)
                && "VALID".equals(chainIntegrity)
                && "VALID".equals(redactionConsistency)
                && ("VALID".equals(signatureValidity) || "NOT_PRESENT".equals(signatureValidity));
    }

    public record Failure(String category, String code, String subject) {
    }
}
