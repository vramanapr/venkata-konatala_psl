package com.vkonatala.auditlog.application.query;

import com.vkonatala.auditlog.domain.append.AuditRecord;

import java.util.List;

public record AuditQueryResult(List<AuditRecord> records, Long nextSequence) {
}
