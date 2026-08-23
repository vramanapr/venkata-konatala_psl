package com.vkonatala.auditlog.application.retention;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "audit.retention")
public record AuditRetentionProperties(
        Duration window,
        long intervalMs,
        RetentionMode mode,
        int batchSize) {
}
