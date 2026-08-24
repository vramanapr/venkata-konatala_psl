package com.vkonatala.auditlog.application.export;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.domain.hash.AuditAuthorizationEvidence;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.domain.hash.CanonicalJsonSerializer;
import com.vkonatala.auditlog.domain.hash.Sha256HashService;
import com.vkonatala.auditlog.domain.redaction.JsonPointerPath;
import com.vkonatala.auditlog.domain.redaction.RedactionProjectionService;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
public class AuditExportVerifier {

    private static final Set<String> REQUIRED = Set.of(
            "manifest.json", "records.json", "proof.json", "redactions.json");
    private static final int MAX_ENTRY_BYTES = 25 * 1024 * 1024;
    private static final int MAX_BUNDLE_BYTES = 100 * 1024 * 1024;

    private final ObjectMapper objectMapper;
    private final CanonicalJsonSerializer canonicalizer;
    private final Sha256HashService hashes;
    private final RedactionProjectionService projections;
    private final AuditExportSignatureProperties signatureProperties;

    public AuditExportVerifier(
            ObjectMapper objectMapper,
            CanonicalJsonSerializer canonicalizer,
            Sha256HashService hashes,
            RedactionProjectionService projections) {
        this(objectMapper, canonicalizer, hashes, projections,
                new AuditExportSignatureProperties());
    }

    @Autowired
    public AuditExportVerifier(
            ObjectMapper objectMapper,
            CanonicalJsonSerializer canonicalizer,
            Sha256HashService hashes,
            RedactionProjectionService projections,
            AuditExportSignatureProperties signatureProperties) {
        this.objectMapper = objectMapper;
        this.canonicalizer = canonicalizer;
        this.hashes = hashes;
        this.projections = projections;
        this.signatureProperties = signatureProperties;
    }

    public AuditExportVerificationResult verify(byte[] bundle) {
        List<AuditExportVerificationResult.Failure> failures = new ArrayList<>();
        Map<String, byte[]> files = readZip(bundle, failures);
        if (!files.keySet().equals(REQUIRED)) {
            failures.add(new AuditExportVerificationResult.Failure(
                    "COMPONENT", "ZIP_ENTRIES_INVALID", String.join(",", files.keySet())));
        }
        JsonNode manifest = parse(files.get("manifest.json"), "manifest.json", failures);
        JsonNode records = parse(files.get("records.json"), "records.json", failures);
        JsonNode proof = parse(files.get("proof.json"), "proof.json", failures);
        JsonNode redactions = parse(files.get("redactions.json"), "redactions.json", failures);

        String componentStatus = failures.stream().anyMatch(f -> "COMPONENT".equals(f.category()))
                ? "INVALID" : "VALID";
        if (manifest != null) {
            verifyCanonical(manifest, files.get("manifest.json"), "manifest.json", failures);
            verifyCanonical(records, files.get("records.json"), "records.json", failures);
            verifyCanonical(proof, files.get("proof.json"), "proof.json", failures);
            verifyCanonical(redactions, files.get("redactions.json"), "redactions.json", failures);
            verifyComponentDigests(manifest, files, failures);
        }
        componentStatus = failures.stream().anyMatch(f -> "COMPONENT".equals(f.category()))
                ? "INVALID" : "VALID";

        String chainStatus = verifyChain(manifest, records, proof, failures);
        String redactionStatus = verifyRedactions(manifest, records, redactions, failures);
        String signatureStatus = verifySignature(manifest, failures);
        return new AuditExportVerificationResult(
                componentStatus, chainStatus, redactionStatus, signatureStatus, List.copyOf(failures));
    }

    private Map<String, byte[]> readZip(byte[] bundle,
                                        List<AuditExportVerificationResult.Failure> failures) {
        Map<String, byte[]> files = new HashMap<>();
        if (bundle == null) {
            failures.add(failure("COMPONENT", "BUNDLE_MISSING", ""));
            return files;
        }
        try (ZipInputStream zip = new ZipInputStream(
                new ByteArrayInputStream(bundle), StandardCharsets.UTF_8)) {
            int totalBytes = 0;
            ZipEntry entry;
            byte[] buffer = new byte[8192];
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory() || entry.getName().contains("/")
                        || !REQUIRED.contains(entry.getName())) {
                    failures.add(failure("COMPONENT", "ZIP_ENTRY_INVALID", entry.getName()));
                    continue;
                }
                if (files.containsKey(entry.getName())) {
                    failures.add(failure("COMPONENT", "DUPLICATE_ENTRY", entry.getName()));
                    continue;
                }
                java.io.ByteArrayOutputStream content = new java.io.ByteArrayOutputStream();
                int read;
                while ((read = zip.read(buffer)) != -1) {
                    if (content.size() + read > MAX_ENTRY_BYTES
                            || totalBytes + content.size() + read > MAX_BUNDLE_BYTES) {
                        throw new IOException("ZIP size limit exceeded");
                    }
                    content.write(buffer, 0, read);
                }
                totalBytes += content.size();
                files.put(entry.getName(), content.toByteArray());
            }
        } catch (IOException exception) {
            failures.add(failure("COMPONENT", "ZIP_INVALID", ""));
        }
        return files;
    }

    private JsonNode parse(byte[] bytes, String name,
                           List<AuditExportVerificationResult.Failure> failures) {
        if (bytes == null) {
            failures.add(failure("COMPONENT", "MISSING_ENTRY", name));
            return null;
        }
        try {
            return objectMapper.readTree(bytes);
        } catch (IOException exception) {
            failures.add(failure("COMPONENT", "JSON_INVALID", name));
            return null;
        }
    }

    private void verifyCanonical(JsonNode node, byte[] bytes, String name,
                                 List<AuditExportVerificationResult.Failure> failures) {
        if (node != null && bytes != null
                && !canonicalizer.serialize(node).equals(new String(bytes, StandardCharsets.UTF_8))) {
            failures.add(failure("COMPONENT", "NON_CANONICAL_JSON", name));
        }
    }

    private void verifyComponentDigests(JsonNode manifest, Map<String, byte[]> files,
                                        List<AuditExportVerificationResult.Failure> failures) {
        JsonNode digests = manifest.path("componentDigests");
        for (String name : List.of("records.json", "proof.json", "redactions.json")) {
            if (!digests.has(name) || files.get(name) == null
                    || !hashes.hash(files.get(name)).equals(digests.path(name).asText())) {
                failures.add(failure("COMPONENT", "DIGEST_MISMATCH", name));
            }
        }
    }

    private String verifyChain(JsonNode manifest, JsonNode records, JsonNode proof,
                               List<AuditExportVerificationResult.Failure> failures) {
        if (manifest == null || records == null || proof == null) return "INVALID";
        if (manifest.path("exportVersion").asInt(-1) != 1
                || proof.path("proofVersion").asInt(-1) != 1
                || !"FULL_PREFIX".equals(manifest.path("proofMode").asText())
                || !"FULL_PREFIX".equals(proof.path("mode").asText())) {
            failures.add(failure("CHAIN", "UNSUPPORTED_VERSION", ""));
            return "INVALID";
        }
        if (!AuditHashChain.GENESIS_HASH.equals(proof.path("genesisHash").asText())
                || !manifest.path("chainId").asText().equals(proof.path("chainId").asText())) {
            failures.add(failure("CHAIN", "GENESIS_OR_CHAIN_MISMATCH", ""));
        }
        List<JsonNode> rows = new ArrayList<>();
        records.path("records").forEach(rows::add);
        long last = manifest.path("lastProofSequence").asLong(-1);
        if (rows.size() != proof.path("recordCount").asInt(-1)
                || rows.size() != (last == 0 ? 0 : last)
                || proof.path("lastSequence").asLong(-1) != last
                || proof.path("firstSequence").asLong(-1) != (rows.isEmpty() ? 0 : 1)) {
            failures.add(failure("CHAIN", "RANGE_OR_COUNT_MISMATCH", ""));
        }
        String previous = AuditHashChain.GENESIS_HASH;
        long expected = 1;
        Set<Long> selected = longs(manifest.path("selectedSequences"));
        if (selected.size() != manifest.path("selectedRecordCount").asInt(-1)
                || manifest.path("selectedSequences").size() != selected.size()
                || !selected.equals(longs(proof.path("selectedSequences")))) {
            failures.add(failure("CHAIN", "SELECTION_LIST_MISMATCH", ""));
        }
        String actor = manifest.path("selection").path("actorId").asText(null);
        String resource = manifest.path("selection").path("resourceId").asText(null);
        for (JsonNode row : rows) {
            long sequence = row.path("sequence").asLong(-1);
            if (sequence != expected || !manifest.path("chainId").asText()
                    .equals(row.path("chainId").asText())) {
                failures.add(failure("CHAIN", "SEQUENCE_OR_CHAIN_MISMATCH",
                        row.path("recordId").asText("")));
            }
            if (!previous.equals(row.path("previousHash").asText())) {
                failures.add(failure("CHAIN", "PREVIOUS_HASH_MISMATCH",
                        row.path("recordId").asText("")));
            }
            try {
                JsonNode payload = row.path("payload");
                boolean legacyEnvelope = row.path("canonicalizationVersion").asInt(1) == 0
                        || !row.has("principal");
                AuditEvent exportedEvent = legacyEnvelope
                        ? new AuditEvent(row.path("eventType").asText(), row.path("actorId").asText(),
                        row.path("resourceType").asText(), row.path("resourceId").asText(),
                        payload, Instant.parse(row.path("occurredAt").asText()))
                        : new AuditEvent(row.path("eventType").asText(), row.path("actorId").asText(),
                        row.path("resourceType").asText(), row.path("resourceId").asText(),
                        payload, Instant.parse(row.path("occurredAt").asText()),
                        new AuditAuthorizationEvidence(
                                row.path("principal").asText(row.path("actorId").asText()),
                                row.path("effectiveActor").asText(row.path("actorId").asText()),
                                row.path("delegatedBy").isNull() ? null
                                        : row.path("delegatedBy").asText(),
                                row.path("authorizationOutcome").asText("ALLOWED"),
                                row.path("authorizationPolicy").asText("audit:write"),
                                row.path("authorizationReason").asText("legacy record"),
                                row.path("requestContext").isObject()
                                        ? row.path("requestContext")
                                        : objectMapper.createObjectNode()));
                String recomputed = new AuditHashChain(objectMapper, hashes).append(
                        exportedEvent, row.path("previousHash").asText()).contentHash();
                boolean hasRedactionMarker = payload.toString().contains("\"redacted\":true");
                if (!hasRedactionMarker && !recomputed.equals(row.path("contentHash").asText())) {
                    failures.add(failure("CHAIN", "CONTENT_HASH_MISMATCH",
                            row.path("recordId").asText("")));
                }
                if (!hasRedactionMarker
                        && !hashes.hash(payload).equals(row.path("payloadCommitment").asText())) {
                    failures.add(failure("CHAIN", "PAYLOAD_COMMITMENT_MISMATCH",
                            row.path("recordId").asText("")));
                }
            } catch (RuntimeException exception) {
                failures.add(failure("CHAIN", "RECORD_INVALID", row.path("recordId").asText("")));
            }
            boolean shouldSelect = (actor != null && actor.equals(row.path("actorId").asText()))
                    || (resource != null && resource.equals(row.path("resourceId").asText()));
            boolean marked = "SELECTED".equals(row.path("selection").asText());
            if (marked != shouldSelect || marked != selected.contains(sequence)) {
                failures.add(failure("CHAIN", "SELECTION_MISMATCH",
                        row.path("recordId").asText("")));
            }
            previous = row.path("contentHash").asText();
            expected++;
        }
        boolean contiguous = rows.stream().allMatch(row ->
                row.path("sequence").asLong(-1) == rows.indexOf(row) + 1L);
        if (proof.path("contiguous").asBoolean(false) != contiguous) {
            failures.add(failure("CHAIN", "CONTIGUITY_MISMATCH", ""));
        }
        if (!rows.isEmpty() && rows.getLast().path("contentHash").asText().isBlank()) {
            failures.add(failure("CHAIN", "FINAL_HASH_MISSING", ""));
        }
        return failures.stream().anyMatch(f -> "CHAIN".equals(f.category())) ? "INVALID" : "VALID";
    }

    private String verifyRedactions(JsonNode manifest, JsonNode records, JsonNode redactions,
                                    List<AuditExportVerificationResult.Failure> failures) {
        if (records == null || redactions == null) return "INVALID";
        if (redactions.path("redactionVersion").asInt(-1) != 1) {
            failures.add(failure("REDACTION", "UNSUPPORTED_VERSION", ""));
            return "INVALID";
        }
        Map<String, JsonNode> byId = new HashMap<>();
        records.path("records").forEach(row -> byId.put(row.path("recordId").asText(), row));
        Map<String, List<JsonNode>> operations = new HashMap<>();
        redactions.path("operations").forEach(operation ->
                operations.computeIfAbsent(operation.path("recordId").asText(),
                        ignored -> new ArrayList<>()).add(operation));
        for (var entry : operations.entrySet()) {
            JsonNode record = byId.get(entry.getKey());
            if (record == null) {
                failures.add(failure("REDACTION", "RECORD_NOT_FOUND", entry.getKey()));
                continue;
            }
            JsonNode projected = record.path("payload").deepCopy();
            String previous = record.path("contentHash").asText();
            long sequence = 1;
            for (JsonNode operation : entry.getValue()) {
                try {
                    JsonPointerPath path = JsonPointerPath.parse(operation.path("path").asText());
                    String commitment = operation.path("commitment").asText();
                    if (!commitment.matches("v1:sha256:[0-9a-f]{64}")) throw new IllegalArgumentException();
                    if (!operation.path("presentationHash").asText()
                            .matches("[0-9a-f]{64}")) throw new IllegalArgumentException();
                    String marker = "{\"redacted\":true,\"commitment\":\"" + commitment + "\"}";
                    JsonNode current = path.resolve(projected);
                    if (!marker.equals(canonicalizer.serialize(current))) {
                        projected = projections.redact(projected, path, marker);
                    }
                    if (operation.path("redactionSequence").asLong(-1) != sequence
                            || !previous.equals(operation.path("previousRedactionHash").asText())) {
                        throw new IllegalArgumentException();
                    }
                    String operationHash = operationHash(operation, operation.path("createdAt").asText());
                    if (!operationHash.equals(operation.path("operationHash").asText())) {
                        throw new IllegalArgumentException();
                    }
                    previous = operation.path("operationHash").asText();
                    sequence++;
                } catch (RuntimeException exception) {
                    failures.add(failure("REDACTION", "OPERATION_INVALID",
                            operation.path("redactionId").asText("")));
                }
            }
            if (!hashes.hash(projected).equals(record.path("presentationHash").asText())
                    || !projected.equals(record.path("payload"))) {
                failures.add(failure("REDACTION", "PRESENTATION_MISMATCH", entry.getKey()));
            }
        }
        for (JsonNode record : records.path("records")) {
            String id = record.path("recordId").asText();
            if (!operations.containsKey(id)
                    && record.path("payload").toString().contains("\"redacted\":true")) {
                failures.add(failure("REDACTION", "MISSING_OPERATION", id));
            }
        }
        return failures.stream().anyMatch(f -> "REDACTION".equals(f.category()))
                ? "INVALID" : "VALID";
    }

    private String operationHash(JsonNode operation, String createdAt) {
        ObjectNode input = objectMapper.createObjectNode();
        input.put("version", 1);
        input.put("redactionId", operation.path("redactionId").asText());
        input.put("recordId", operation.path("recordId").asText());
        input.put("path", operation.path("path").asText());
        input.put("commitmentId", operation.path("commitmentId").asText());
        input.put("reason", operation.path("reason").asText());
        input.put("requestedBy", operation.path("requestedBy").asText());
        input.put("createdAt", Instant.parse(createdAt).toString());
        input.put("sequence", operation.path("redactionSequence").asLong());
        input.put("previousRedactionHash", operation.path("previousRedactionHash").asText());
        input.put("presentationHash", operation.path("presentationHash").asText());
        input.put("requestFingerprint", operation.path("requestFingerprint").asText(""));
        return hashes.hash(input);
    }

    private String verifySignature(JsonNode manifest,
                                   List<AuditExportVerificationResult.Failure> failures) {
        if (manifest == null) return "INVALID";
        JsonNode signature = manifest.path("signature");
        if (!signature.path("present").asBoolean(false)) return "NOT_PRESENT";
        if (!"Ed25519".equals(signature.path("algorithm").asText())
                || !"base64url".equals(signature.path("signatureEncoding").asText())) {
            failures.add(failure("SIGNATURE", "UNSUPPORTED_SIGNATURE", ""));
            return "INVALID";
        }
        if (signatureProperties.publicKey() == null || signatureProperties.publicKey().isBlank()
                || !signatureProperties.keyId().equals(signature.path("keyId").asText())) {
            failures.add(failure("SIGNATURE", "UNKNOWN_KEY", signature.path("keyId").asText("")));
            return "UNKNOWN_KEY";
        }
        try {
            ObjectNode unsigned = manifest.deepCopy();
            unsigned.remove("signature");
            String encoded = signatureProperties.publicKey()
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded)));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(canonicalizer.serialize(unsigned).getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(Base64.getUrlDecoder().decode(signature.path("signature").asText()))) {
                failures.add(failure("SIGNATURE", "INVALID_SIGNATURE", ""));
                return "INVALID";
            }
            return "VALID";
        } catch (Exception exception) {
            failures.add(failure("SIGNATURE", "MALFORMED_SIGNATURE", ""));
            return "INVALID";
        }
    }

    private Set<Long> longs(JsonNode array) {
        Set<Long> values = new HashSet<>();
        array.forEach(node -> values.add(node.asLong()));
        return values;
    }

    private AuditExportVerificationResult.Failure failure(String category, String code, String subject) {
        return new AuditExportVerificationResult.Failure(category, code, subject);
    }
}
