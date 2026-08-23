package com.vkonatala.auditlog.application.verify;

import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.domain.hash.AuditHash;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AuditChainVerifier {

    private static final String DEFAULT_CHAIN_ID = "default";

    private final AuditRecordRepository repository;
    private final AuditHashChain hashChain;

    public AuditChainVerifier(
            AuditRecordRepository repository,
            AuditHashChain hashChain) {
        this.repository = repository;
        this.hashChain = hashChain;
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
                expectedHash = hashChain.append(
                        new AuditEvent(
                                record.eventType(),
                                record.actorId(),
                                record.resourceType(),
                                record.resourceId(),
                                record.payload(),
                                record.occurredAt()),
                        record.previousHash());
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

        return new AuditVerificationResult(true, verifiedThroughSequence, null);
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
}
