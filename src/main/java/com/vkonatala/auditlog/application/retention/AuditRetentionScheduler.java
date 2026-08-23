package com.vkonatala.auditlog.application.retention;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
        prefix = "audit.retention",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class AuditRetentionScheduler {

    private final AuditRetentionService retentionService;

    public AuditRetentionScheduler(AuditRetentionService retentionService) {
        this.retentionService = retentionService;
    }

    @Scheduled(fixedDelayString = "${audit.retention.interval-ms}")
    public void archiveEligibleRecords() {
        retentionService.archiveEligibleRecords();
    }
}
