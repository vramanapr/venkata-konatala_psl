package com.vkonatala.auditlog.application.retention;

import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuditRetentionServiceTest {

    private final AuditRecordRepository repository = mock(AuditRecordRepository.class);
    private final Instant now = Instant.parse("2026-08-23T10:00:00Z");
    private final AuditRetentionService service = new AuditRetentionService(
            repository,
            new AuditRetentionProperties(
                    java.time.Duration.ofDays(30),
                    3_600_000,
                    RetentionMode.SOFT_DELETE,
                    500),
            Clock.fixed(now, ZoneOffset.UTC));

    @Test
    void archivesRecordsOlderThanConfiguredWindow() {
        when(repository.markArchivedBefore(Instant.parse("2026-07-24T10:00:00Z")))
                .thenReturn(4);

        assertThat(service.archiveEligibleRecords()).isEqualTo(4);

        verify(repository).markArchivedBefore(Instant.parse("2026-07-24T10:00:00Z"));
    }

    @Test
    void archivesRecordsToArchiveTableWhenConfigured() {
        AuditRetentionService archiveTableService = new AuditRetentionService(
                repository,
                new AuditRetentionProperties(
                        java.time.Duration.ofDays(30),
                        3_600_000,
                        RetentionMode.ARCHIVE_TABLE,
                        25),
                Clock.fixed(now, ZoneOffset.UTC));
        when(repository.archiveToTableBefore(
                Instant.parse("2026-07-24T10:00:00Z"), 25)).thenReturn(2);

        assertThat(archiveTableService.archiveEligibleRecords()).isEqualTo(2);

        verify(repository).archiveToTableBefore(
                Instant.parse("2026-07-24T10:00:00Z"), 25);
    }
}
