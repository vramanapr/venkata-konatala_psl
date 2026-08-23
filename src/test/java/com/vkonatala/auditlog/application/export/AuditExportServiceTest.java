package com.vkonatala.auditlog.application.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.domain.hash.CanonicalJsonSerializer;
import com.vkonatala.auditlog.domain.hash.Sha256HashService;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditExportServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final AuditRecordRepository repository = mock(AuditRecordRepository.class);
    private final AuditExportService exporter = new AuditExportService(
            repository, mapper, new CanonicalJsonSerializer(),
            new Sha256HashService(new CanonicalJsonSerializer()),
            java.time.Clock.fixed(Instant.parse("2026-08-23T10:00:00Z"),
                    java.time.ZoneOffset.UTC));
    private final AuditExportVerifier verifier = new AuditExportVerifier(
            mapper, new CanonicalJsonSerializer(),
            new Sha256HashService(new CanonicalJsonSerializer()),
            new com.vkonatala.auditlog.domain.redaction.RedactionProjectionService(mapper));

    @Test
    void exportsFullPrefixAndVerifiesUnsignedBundle() throws Exception {
        var rows = rows();
        when(repository.findLogicalRecordsForExport("default")).thenReturn(rows);
        rows.forEach(row -> when(repository.findRedactions(row.record().recordId())).thenReturn(List.of()));

        byte[] bundle = exporter.export("actor", null);
        var result = verifier.verify(bundle);

        assertThat(result.componentIntegrity()).isEqualTo("VALID");
        assertThat(result.chainIntegrity()).isEqualTo("VALID");
        assertThat(result.redactionConsistency()).isEqualTo("VALID");
        assertThat(result.signatureValidity()).isEqualTo("NOT_PRESENT");
        assertThat(result.verified()).isTrue();
        assertThat(entries(bundle)).containsExactly(
                "manifest.json", "records.json", "proof.json", "redactions.json");
        assertThat(mapper.readTree(readEntry(bundle, "records.json"))
                .path("records")).hasSize(4);
    }

    @Test
    void detectsTamperedComponent() throws Exception {
        when(repository.findLogicalRecordsForExport("default")).thenReturn(rows().subList(0, 1));
        when(repository.findRedactions(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());
        byte[] bundle = exporter.export("actor", null);
        byte[] tampered = rewriteRecords(bundle);
        assertThat(verifier.verify(tampered).componentIntegrity()).isEqualTo("INVALID");
    }

    private List<AuditRecordRepository.ExportRecord> rows() {
        var chain = new AuditHashChain(mapper,
                new Sha256HashService(new CanonicalJsonSerializer()));
        String previous = AuditHashChain.GENESIS_HASH;
        var rows = new java.util.ArrayList<AuditRecordRepository.ExportRecord>();
        for (int sequence = 1; sequence <= 4; sequence++) {
            String actor = sequence == 2 || sequence == 4 ? "actor" : "other";
            var event = new com.vkonatala.auditlog.domain.hash.AuditEvent(
                    "TEST", actor, "RESOURCE", "resource",
                    mapper.createObjectNode().put("value", sequence),
                    Instant.parse("2026-08-23T10:00:00Z"));
            var hash = chain.append(event, previous);
            rows.add(row(sequence, actor, hash.contentHash(), previous, event.payload()));
            previous = hash.contentHash();
        }
        return rows;
    }

    private AuditRecordRepository.ExportRecord row(
            long sequence, String actor, String contentHash, String previous, com.fasterxml.jackson.databind.JsonNode payload) {
        String payloadHash = new Sha256HashService(new CanonicalJsonSerializer()).hash(payload);
        AuditRecord record = new AuditRecord(
                UUID.randomUUID(), "default", sequence, "TEST", actor, "RESOURCE", "resource",
                Instant.parse("2026-08-23T10:00:00Z"),
                Instant.parse("2026-08-23T10:00:00Z"),
                payload, 1, contentHash, previous, payloadHash, payload, payloadHash, 1);
        return new AuditRecordRepository.ExportRecord(record, false);
    }

    private List<String> entries(byte[] bundle) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bundle))) {
            List<String> names = new java.util.ArrayList<>();
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) names.add(entry.getName());
            return names;
        }
    }

    private byte[] readEntry(byte[] bundle, String name) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bundle))) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) {
                if (name.equals(entry.getName())) {
                    ByteArrayOutputStream output = new ByteArrayOutputStream();
                    zip.transferTo(output);
                    return output.toByteArray();
                }
            }
        }
        throw new IllegalArgumentException("missing entry");
    }

    private byte[] rewriteRecords(byte[] bundle) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(bundle));
             ZipOutputStream zip = new ZipOutputStream(output)) {
            for (ZipEntry entry; (entry = input.getNextEntry()) != null; ) {
                byte[] bytes = input.readAllBytes();
                if ("records.json".equals(entry.getName())) bytes[bytes.length - 2] ^= 1;
                zip.putNextEntry(new ZipEntry(entry.getName()));
                zip.write(bytes);
                zip.closeEntry();
            }
        }
        return output.toByteArray();
    }
}
