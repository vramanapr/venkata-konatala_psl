package com.vkonatala.auditlog.application.verify;

import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.domain.hash.AuditHash;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.domain.redaction.FieldCommitmentService;
import com.vkonatala.auditlog.domain.redaction.JsonPointerPath;
import com.vkonatala.auditlog.domain.redaction.RedactionCommand;
import com.vkonatala.auditlog.domain.redaction.RedactionProjectionService;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AuditChainVerifier {

    private static final String DEFAULT_CHAIN_ID = "default";

    private final AuditRecordRepository repository;
    private final AuditHashChain hashChain;
    private final FieldCommitmentService commitments;
    private final RedactionProjectionService projections;
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;
    private final com.vkonatala.auditlog.domain.hash.Sha256HashService hashes;

    public AuditChainVerifier(
            AuditRecordRepository repository,
            AuditHashChain hashChain,
            FieldCommitmentService commitments,
            RedactionProjectionService projections,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper,
            com.vkonatala.auditlog.domain.hash.Sha256HashService hashes) {
        this.repository = repository;
        this.hashChain = hashChain;
        this.commitments = commitments;
        this.projections = projections;
        this.objectMapper = objectMapper;
        this.hashes = hashes;
    }

    @Transactional(readOnly = true)
    public AuditVerificationResult verify() {
        List<com.vkonatala.auditlog.domain.append.AuditRecord> records =
                repository.findAllForVerification(DEFAULT_CHAIN_ID);
        var chainHead = repository.findChainHead(DEFAULT_CHAIN_ID);
        String expectedPreviousHash = AuditHashChain.GENESIS_HASH;
        long expectedSequence = 1;
        long verifiedThroughSequence = 0;

        if (records.isEmpty()) {
            if ((chainHead.isPresent() && chainHead.get().nextSequence() != 1)
                    || repository.findLatestCheckpoint(DEFAULT_CHAIN_ID).isPresent()) {
                return failure(0, null, 0, "CHAIN_HEAD_MISMATCH");
            }
            return new AuditVerificationResult(true, 0, null);
        }

        for (var record : records) {
            if (record.sequence() != expectedSequence) {
                return failure(
                        verifiedThroughSequence,
                        record.recordId().toString(),
                        record.sequence(),
                        "SEQUENCE_GAP");
            }
            if (!expectedPreviousHash.equals(record.previousHash())) {
                return failure(
                        verifiedThroughSequence,
                        record.recordId().toString(),
                        record.sequence(),
                        "PREVIOUS_HASH_MISMATCH");
            }

            AuditHash expectedHash;
            try {
                AuditEvent event = record.canonicalizationVersion() == 0
                        ? new AuditEvent(record.eventType(), record.actorId(),
                        record.resourceType(), record.resourceId(), record.payload(),
                        record.occurredAt())
                        : new AuditEvent(record.eventType(), record.actorId(),
                        record.resourceType(), record.resourceId(), record.payload(),
                        record.occurredAt(), record.authorization());
                expectedHash = hashChain.append(event, record.previousHash());
            } catch (IllegalArgumentException exception) {
                return failure(
                        verifiedThroughSequence,
                        record.recordId().toString(),
                        record.sequence(),
                        "INVALID_RECORD");
            }

            if (!expectedHash.contentHash().equals(record.contentHash())) {
                return failure(
                        verifiedThroughSequence,
                        record.recordId().toString(),
                        record.sequence(),
                        "CONTENT_HASH_MISMATCH");
            }
            if (record.canonicalizationVersion() == 1
                    && !hashes.hash(record.payload()).equals(record.payloadCommitment())) {
                return failure(
                        verifiedThroughSequence,
                        record.recordId().toString(),
                        record.sequence(),
                        "PAYLOAD_COMMITMENT_MISMATCH");
            }

            expectedPreviousHash = record.contentHash();
            expectedSequence++;
            verifiedThroughSequence = record.sequence();
        }

        if (chainHead.isEmpty()
                || chainHead.get().nextSequence() != expectedSequence
                || !chainHead.get().lastHash().equals(expectedPreviousHash)) {
            return failure(
                    verifiedThroughSequence,
                    records.getLast().recordId().toString(),
                    records.getLast().sequence(),
                    "CHAIN_HEAD_MISMATCH");
        }

        var checkpoint = repository.findLatestCheckpoint(DEFAULT_CHAIN_ID);
        if (checkpoint.isPresent()) {
            if (checkpoint.get().throughSequence() > verifiedThroughSequence
                    || !checkpoint.get().lastHash().equals(
                    records.stream()
                            .filter(record -> record.sequence()
                                    == checkpoint.get().throughSequence())
                            .findFirst()
                            .map(record -> record.contentHash())
                            .orElse(null))) {
                return failure(
                        verifiedThroughSequence,
                        records.getLast().recordId().toString(),
                        records.getLast().sequence(),
                        "CHECKPOINT_MISMATCH");
            }
        }

        var redactionFailure = verifyRedactions(records);
        return redactionFailure == null
                ? new AuditVerificationResult(true, verifiedThroughSequence, null)
                : new AuditVerificationResult(true, verifiedThroughSequence, null, false, redactionFailure);
    }

    private AuditVerificationResult failure(
            long verifiedThroughSequence,
            String recordId,
            long sequence,
            String violationType) {
        return new AuditVerificationResult(
                false,
                verifiedThroughSequence,
                new AuditVerificationResult.FirstFailure(recordId, sequence, violationType));
    }

    private AuditVerificationResult.RedactionFailure verifyRedactions(
            List<com.vkonatala.auditlog.domain.append.AuditRecord> records) {
        for (var record : records) {
            var fieldRows = repository.findFieldCommitments(record.recordId());
            var redactions = repository.findRedactions(record.recordId());
            var expected = record.payload().deepCopy();
            String previous = record.contentHash();
            long sequence = 1;
            for (var field : fieldRows) {
                try {
                    String digest = commitments.commitment(field.path(),
                            JsonPointerPath.parse(field.path()).resolve(record.payload()), field.salt());
                    if (!digest.equals(field.digest())) {
                        return redactionFailure(record, "REDACTION_COMMITMENT_FAILURE");
                    }
                } catch (RuntimeException exception) {
                    return redactionFailure(record, "REDACTION_COMMITMENT_FAILURE");
                }
            }
            for (var redaction : redactions) {
                try {
                    var path = JsonPointerPath.parse(redaction.path());
                    var field = fieldRows.stream()
                            .filter(candidate -> candidate.commitmentId().equals(redaction.commitmentId())
                                    && candidate.path().equals(path.value()))
                            .findFirst().orElseThrow();
                    if (redaction.sequence() != sequence
                            || !previous.equals(redaction.previousRedactionHash())) {
                        return redactionFailure(record, "REDACTION_METADATA_FAILURE");
                    }
                    String expectedOperation = operationHash(redaction, field);
                    if (!expectedOperation.equals(redaction.operationHash())) {
                        return redactionFailure(record, "REDACTION_METADATA_FAILURE");
                    }
                    expected = projections.redact(expected, path,
                            commitments.marker(field.digest()));
                    if (!hashes.hash(expected).equals(redaction.presentationHash())) {
                        return redactionFailure(record, "REDACTION_PROJECTION_FAILURE");
                    }
                    previous = redaction.operationHash();
                    sequence++;
                } catch (RuntimeException exception) {
                    return redactionFailure(record, "REDACTION_METADATA_FAILURE");
                }
            }
            if (!hashes.hash(expected).equals(record.presentationHash())
                    || !expected.equals(record.presentationPayload())) {
                return redactionFailure(record, "REDACTION_PROJECTION_FAILURE");
            }
        }
        return null;
    }

    private String operationHash(
            AuditRecordRepository.Redaction redaction,
            AuditRecordRepository.FieldCommitment field) {
        com.fasterxml.jackson.databind.node.ObjectNode input = objectMapper.createObjectNode();
        input.put("version", 1);
        input.put("redactionId", redaction.redactionId().toString());
        input.put("recordId", redaction.recordId().toString());
        input.put("path", redaction.path());
        input.put("commitmentId", field.commitmentId().toString());
        input.put("reason", redaction.reason());
        input.put("requestedBy", redaction.requestedBy());
        input.put("createdAt", redaction.createdAt().toString());
        input.put("sequence", redaction.sequence());
        input.put("previousRedactionHash", redaction.previousRedactionHash());
        input.put("presentationHash", redaction.presentationHash());
        input.put("requestFingerprint", redaction.requestFingerprint());
        return hashes.hash(input);
    }

    private AuditVerificationResult.RedactionFailure redactionFailure(
            com.vkonatala.auditlog.domain.append.AuditRecord record, String type) {
        return new AuditVerificationResult.RedactionFailure(record.recordId().toString(),
                record.sequence(), type);
    }
}
