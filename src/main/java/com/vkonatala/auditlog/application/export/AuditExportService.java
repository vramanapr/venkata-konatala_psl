package com.vkonatala.auditlog.application.export;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.domain.hash.CanonicalJsonSerializer;
import com.vkonatala.auditlog.domain.hash.Sha256HashService;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
public class AuditExportService {

    public static final int EXPORT_VERSION = 1;
    public static final int REDACTION_VERSION = 1;
    public static final int CANONICALIZATION_VERSION = 1;
    private static final String DEFAULT_CHAIN_ID = "default";
    private static final DateTimeFormatter EXPORT_TIME = DateTimeFormatter
            .ofPattern("uuuu-MM-dd'T'HH:mm:ss.nnnnnnnnn'Z'")
            .withZone(ZoneOffset.UTC);

    private final AuditRecordRepository repository;
    private final ObjectMapper objectMapper;
    private final CanonicalJsonSerializer canonicalizer;
    private final Sha256HashService hashes;
    private final Clock clock;
    private final AuditExportSignatureProperties signatureProperties;

    public AuditExportService(
            AuditRecordRepository repository,
            ObjectMapper objectMapper,
            CanonicalJsonSerializer canonicalizer,
            Sha256HashService hashes) {
        this(repository, objectMapper, canonicalizer, hashes, Clock.systemUTC(),
                new AuditExportSignatureProperties());
    }

    @Autowired
    public AuditExportService(
            AuditRecordRepository repository,
            ObjectMapper objectMapper,
            CanonicalJsonSerializer canonicalizer,
            Sha256HashService hashes,
            AuditExportSignatureProperties signatureProperties) {
        this(repository, objectMapper, canonicalizer, hashes, Clock.systemUTC(),
                signatureProperties);
    }

    AuditExportService(
            AuditRecordRepository repository,
            ObjectMapper objectMapper,
            CanonicalJsonSerializer canonicalizer,
            Sha256HashService hashes,
            Clock clock) {
        this(repository, objectMapper, canonicalizer, hashes, clock,
                new AuditExportSignatureProperties());
    }

    AuditExportService(
            AuditRecordRepository repository,
            ObjectMapper objectMapper,
            CanonicalJsonSerializer canonicalizer,
            Sha256HashService hashes,
            Clock clock,
            AuditExportSignatureProperties signatureProperties) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.canonicalizer = canonicalizer;
        this.hashes = hashes;
        this.clock = clock;
        this.signatureProperties = signatureProperties;
    }

    @Transactional(readOnly = true)
    public byte[] export(String actorId, String resourceId) {
        return export(DEFAULT_CHAIN_ID, actorId, resourceId);
    }

    @Transactional(readOnly = true)
    public byte[] export(String chainId, String actorId, String resourceId) {
        if ((actorId == null || actorId.isBlank())
                && (resourceId == null || resourceId.isBlank())) {
            throw new IllegalArgumentException("actorId or resourceId is required");
        }
        List<AuditRecordRepository.ExportRecord> logical =
                repository.findLogicalRecordsForExport(chainId);
        List<AuditRecordRepository.ExportRecord> selected = logical.stream()
                .filter(row -> (actorId != null && actorId.equals(row.record().actorId()))
                        || (resourceId != null && resourceId.equals(row.record().resourceId())))
                .toList();
        long lastSelected = selected.stream()
                .mapToLong(row -> row.record().sequence()).max().orElse(0);
        List<AuditRecordRepository.ExportRecord> prefix = logical.stream()
                .filter(row -> row.record().sequence() <= lastSelected)
                .toList();
        List<Long> selectedSequences = selected.stream()
                .map(row -> row.record().sequence())
                .sorted()
                .toList();

        ObjectNode records = objectMapper.createObjectNode();
        ArrayNode recordArray = records.putArray("records");
        for (AuditRecordRepository.ExportRecord row : prefix) {
            recordArray.add(recordJson(row, selectedSequences.contains(row.record().sequence())));
        }

        ObjectNode redactions = objectMapper.createObjectNode();
        redactions.put("redactionVersion", REDACTION_VERSION);
        ArrayNode operationArray = redactions.putArray("operations");
        for (AuditRecordRepository.ExportRecord row : prefix) {
            for (AuditRecordRepository.Redaction operation :
                    repository.findRedactions(row.record().recordId())) {
                operationArray.add(redactionJson(operation));
            }
        }

        ObjectNode proof = objectMapper.createObjectNode();
        proof.put("proofVersion", 1);
        proof.put("mode", "FULL_PREFIX");
        proof.put("genesisHash", AuditHashChain.GENESIS_HASH);
        proof.put("chainId", chainId);
        proof.put("firstSequence", prefix.isEmpty() ? 0 : 1);
        proof.put("lastSequence", lastSelected);
        proof.put("recordCount", prefix.size());
        addLongs(proof.putArray("selectedSequences"), selectedSequences);
        proof.put("contiguous", prefix.stream().allMatch(row ->
                row.record().sequence() == prefix.indexOf(row) + 1L));

        byte[] recordsBytes = canonicalBytes(records);
        byte[] proofBytes = canonicalBytes(proof);
        byte[] redactionsBytes = canonicalBytes(redactions);

        ObjectNode manifest = objectMapper.createObjectNode();
        manifest.put("exportVersion", EXPORT_VERSION);
        manifest.put("exportId", UUID.randomUUID().toString());
        manifest.put("chainId", chainId);
        manifest.put("createdAt", EXPORT_TIME.format(clock.instant()));
        manifest.put("exporter", "audit-log-service");
        ObjectNode selection = manifest.putObject("selection");
        if (resourceId != null && !resourceId.isBlank()) selection.put("resourceId", resourceId);
        if (actorId != null && !actorId.isBlank()) selection.put("actorId", actorId);
        manifest.put("selectionMode", "OR");
        manifest.put("selectedRecordCount", selected.size());
        addLongs(manifest.putArray("selectedSequences"), selectedSequences);
        manifest.put("proofMode", "FULL_PREFIX");
        manifest.put("lastProofSequence", lastSelected);
        manifest.put("hashAlgorithm", "SHA-256");
        manifest.put("canonicalizationVersion", CANONICALIZATION_VERSION);
        manifest.put("redactionVersion", REDACTION_VERSION);
        ObjectNode digests = manifest.putObject("componentDigests");
        digests.put("records.json", hashes.hash(recordsBytes));
        digests.put("proof.json", hashes.hash(proofBytes));
        digests.put("redactions.json", hashes.hash(redactionsBytes));
        ObjectNode signature = manifest.putObject("signature");
        signature.put("present", false);
        if (signatureProperties.enabled()) {
            if (signatureProperties.privateKey() == null || signatureProperties.privateKey().isBlank()) {
                throw new IllegalStateException("Export signing is enabled but no private key is configured");
            }
            ObjectNode unsignedManifest = manifest.deepCopy();
            unsignedManifest.remove("signature");
            byte[] signed = sign(canonicalBytes(unsignedManifest), signatureProperties.privateKey());
            signature.put("present", true);
            signature.put("algorithm", "Ed25519");
            signature.put("keyId", signatureProperties.keyId());
            signature.put("signatureEncoding", "base64url");
            signature.put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signed));
        }

        return zip(MapEntry.of("manifest.json", canonicalBytes(manifest)),
                MapEntry.of("records.json", recordsBytes),
                MapEntry.of("proof.json", proofBytes),
                MapEntry.of("redactions.json", redactionsBytes));
    }

    private ObjectNode recordJson(AuditRecordRepository.ExportRecord row, boolean selected) {
        var record = row.record();
        ObjectNode json = objectMapper.createObjectNode();
        json.put("recordId", record.recordId().toString());
        json.put("chainId", record.chainId());
        json.put("sequence", record.sequence());
        json.put("selection", selected ? "SELECTED" : "CHAIN_CONTEXT");
        json.put("eventType", record.eventType());
        json.put("actorId", record.actorId());
        json.put("principal", record.authorization().principal());
        json.put("effectiveActor", record.authorization().effectiveActor());
        if (record.authorization().delegatedBy() == null) json.putNull("delegatedBy");
        else json.put("delegatedBy", record.authorization().delegatedBy());
        json.put("authorizationOutcome", record.authorization().outcome());
        json.put("authorizationPolicy", record.authorization().policy());
        json.put("authorizationReason", record.authorization().reason());
        json.set("requestContext", record.authorization().requestContext());
        json.put("resourceType", record.resourceType());
        json.put("resourceId", record.resourceId());
        putInstant(json, "occurredAt", record.occurredAt());
        putInstant(json, "recordedAt", record.recordedAt());
        json.set("payload", record.presentationPayload());
        json.put("payloadCommitment", record.payloadCommitment());
        json.put("payloadSchemaVersion", record.payloadSchemaVersion());
        json.put("canonicalizationVersion", record.canonicalizationVersion());
        json.put("contentHash", record.contentHash());
        json.put("previousHash", record.previousHash());
        json.put("presentationHash", record.presentationHash());
        json.put("archived", row.archived());
        return json;
    }

    private ObjectNode redactionJson(AuditRecordRepository.Redaction operation) {
        ObjectNode json = objectMapper.createObjectNode();
        json.put("redactionId", operation.redactionId().toString());
        json.put("recordId", operation.recordId().toString());
        json.put("path", operation.path());
        json.put("commitment", operation.commitment());
        if (operation.commitmentId() == null) json.putNull("commitmentId");
        else json.put("commitmentId", operation.commitmentId().toString());
        json.put("reason", operation.reason());
        json.put("requestedBy", operation.requestedBy());
        json.put("requestFingerprint", operation.requestFingerprint());
        putInstant(json, "createdAt", operation.createdAt());
        json.put("redactionSequence", operation.sequence());
        json.put("previousRedactionHash", operation.previousRedactionHash());
        json.put("presentationHash", operation.presentationHash());
        json.put("operationHash", operation.operationHash());
        return json;
    }

    private void putInstant(ObjectNode node, String field, Instant value) {
        if (value == null) node.putNull(field);
        else node.put(field, EXPORT_TIME.format(value));
    }

    private void addLongs(ArrayNode target, List<Long> values) {
        values.forEach(target::add);
    }

    private byte[] canonicalBytes(JsonNode node) {
        return canonicalizer.serialize(node).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] zip(MapEntry... entries) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(output, StandardCharsets.UTF_8)) {
                for (MapEntry entry : entries) {
                    zip.putNextEntry(new ZipEntry(entry.name()));
                    zip.write(entry.bytes());
                    zip.closeEntry();
                }
            }
            return output.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to create export bundle", exception);
        }
    }

    private byte[] sign(byte[] content, String encodedKey) {
        try {
            String key = encodedKey
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            PrivateKey privateKey = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key)));
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(content);
            return signature.sign();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to sign export manifest", exception);
        }
    }

    private record MapEntry(String name, byte[] bytes) {
        static MapEntry of(String name, byte[] bytes) {
            return new MapEntry(name, bytes);
        }
    }
}
