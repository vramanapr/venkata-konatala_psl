package com.vkonatala.auditlog.application.checkpoint;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
        prefix = "audit.checkpoint",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class AuditCheckpointScheduler {

    private final AuditCheckpointService checkpointService;

    public AuditCheckpointScheduler(AuditCheckpointService checkpointService) {
        this.checkpointService = checkpointService;
    }

    @Scheduled(fixedDelayString = "${audit.checkpoint.interval-ms}")
    public void createCheckpoint() {
        checkpointService.createCheckpoint();
    }
}
