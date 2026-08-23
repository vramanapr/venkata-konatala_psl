package com.vkonatala.auditlog.application.retention;

import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class AuditRetentionService {

    private final AuditRecordRepository repository;
    private final AuditRetentionProperties properties;
    private final Clock clock;

    @Autowired
    public AuditRetentionService(
            AuditRecordRepository repository,
            AuditRetentionProperties properties) {
        this(repository, properties, Clock.systemUTC());
    }

    AuditRetentionService(
            AuditRecordRepository repository,
            AuditRetentionProperties properties,
            Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public int archiveEligibleRecords() {
        Instant cutoff = clock.instant().minus(properties.window());
        return switch (properties.mode()) {
            case SOFT_DELETE -> repository.markArchivedBefore(cutoff);
            case ARCHIVE_TABLE -> repository.archiveToTableBefore(cutoff, properties.batchSize());
        };
    }
}
