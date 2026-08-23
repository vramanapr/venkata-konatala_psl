package com.vkonatala.auditlog.application.redaction;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.hash.Sha256HashService;
import com.vkonatala.auditlog.domain.redaction.FieldCommitmentService;
import com.vkonatala.auditlog.domain.redaction.JsonPointerPath;
import com.vkonatala.auditlog.domain.redaction.RedactionCommand;
import com.vkonatala.auditlog.domain.redaction.RedactionConflictException;
import com.vkonatala.auditlog.domain.redaction.RedactionProjectionService;
import com.vkonatala.auditlog.domain.redaction.RedactionResult;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class AuditRedactionService {

    private final AuditRecordRepository repository;
    private final FieldCommitmentService commitments;
    private final RedactionProjectionService projections;
    private final Sha256HashService hashes;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Autowired
    public AuditRedactionService(
            AuditRecordRepository repository,
            FieldCommitmentService commitments,
            RedactionProjectionService projections,
            Sha256HashService hashes,
            ObjectMapper objectMapper) {
        this(repository, commitments, projections, hashes, objectMapper, Clock.systemUTC());
    }

    AuditRedactionService(
            AuditRecordRepository repository,
            FieldCommitmentService commitments,
            RedactionProjectionService projections,
            Sha256HashService hashes,
            ObjectMapper objectMapper,
            Clock clock) {
        this.repository = repository;
        this.commitments = commitments;
        this.projections = projections;
        this.hashes = hashes;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Transactional(timeout = 30)
    public RedactionResult redact(UUID recordId, RedactionCommand command, String requestKey) {
        if (requestKey == null || requestKey.isBlank()) {
            throw new IllegalArgumentException("Idempotency-Key is required for redaction");
        }
        JsonPointerPath path = JsonPointerPath.parse(command.path());
        AuditRecord record = repository.lockById(recordId)
                .orElseThrow(() -> new IllegalArgumentException("Audit record was not found"));
        String fingerprint = fingerprint(recordId, path.value(), command);

        var priorRequest = repository.findRedactionByRequestKey(requestKey);
        if (priorRequest.isPresent()) {
            if (!fingerprint.equals(priorRequest.get().requestFingerprint())) {
                throw new RedactionConflictException("Idempotency-Key was reused for different redaction data");
            }
            return new RedactionResult(recordId, priorRequest.get().path(),
                    priorRequest.get().redactionId(), "REDACTED", true);
        }

        var commitment = repository.findFieldCommitment(recordId, path.value())
                .orElseThrow(() -> new RedactionConflictException(
                        "Path is not a designated redactable field"));
        var redactions = repository.findRedactions(recordId);
        for (var existing : redactions) {
            if (existing.path().equals(path.value())
                    || existing.path().startsWith(path.value() + "/")
                    || path.value().startsWith(existing.path() + "/")) {
                throw new RedactionConflictException("Path conflicts with an existing redaction");
            }
        }

        JsonNodeHolder projected = new JsonNodeHolder(record.presentationPayload());
        projected.value = projections.redact(projected.value, path,
                commitments.marker(commitment.digest()));
        String presentationHash = hashes.hash(projected.value);
        Instant createdAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        String previousHash = redactions.isEmpty()
                ? record.contentHash()
                : redactions.getLast().operationHash();
        long sequence = redactions.size() + 1L;
        UUID redactionId = UUID.randomUUID();
        String operationHash = operationHash(
                redactionId, recordId, path.value(), commitment.commitmentId(),
                command, createdAt, sequence, previousHash, presentationHash, fingerprint);

        repository.insertRedaction(new AuditRecordRepository.Redaction(
                redactionId, recordId, path.value(),
                "v" + FieldCommitmentService.FORMAT_VERSION + ":"
                        + FieldCommitmentService.ALGORITHM + ":" + commitment.digest(),
                command.reason(), command.requestedBy(), createdAt, commitment.commitmentId(),
                requestKey, fingerprint, sequence, previousHash, presentationHash, operationHash));
        repository.updatePresentation(recordId, projected.value, presentationHash);
        return new RedactionResult(recordId, path.value(), redactionId, "REDACTED", false);
    }

    private String fingerprint(UUID recordId, String path, RedactionCommand command) {
        ObjectNode input = objectMapper.createObjectNode();
        input.put("recordId", recordId.toString());
        input.put("path", path);
        input.put("reason", command.reason());
        input.put("requestedBy", command.requestedBy());
        return hashes.hash(input);
    }

    public String operationHash(
            UUID redactionId, UUID recordId, String path, UUID commitmentId,
            RedactionCommand command, Instant createdAt, long sequence,
            String previousHash, String presentationHash, String fingerprint) {
        ObjectNode input = objectMapper.createObjectNode();
        input.put("version", 1);
        input.put("redactionId", redactionId.toString());
        input.put("recordId", recordId.toString());
        input.put("path", path);
        input.put("commitmentId", commitmentId.toString());
        input.put("reason", command.reason());
        input.put("requestedBy", command.requestedBy());
        input.put("createdAt", createdAt.toString());
        input.put("sequence", sequence);
        input.put("previousRedactionHash", previousHash);
        input.put("presentationHash", presentationHash);
        input.put("requestFingerprint", fingerprint);
        return hashes.hash(input);
    }

    private static final class JsonNodeHolder {
        private com.fasterxml.jackson.databind.JsonNode value;
        private JsonNodeHolder(com.fasterxml.jackson.databind.JsonNode value) {
            this.value = value;
        }
    }
}
