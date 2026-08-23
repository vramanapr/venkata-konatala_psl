package com.vkonatala.auditlog.application.checkpoint;

import com.vkonatala.auditlog.application.verify.AuditChainVerifier;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class AuditCheckpointService {

    private static final String DEFAULT_CHAIN_ID = "default";

    private final AuditRecordRepository repository;
    private final AuditChainVerifier verifier;

    @Autowired
    public AuditCheckpointService(
            AuditRecordRepository repository,
            AuditChainVerifier verifier) {
        this.repository = repository;
        this.verifier = verifier;
    }

    @Transactional
    public Optional<AuditRecordRepository.Checkpoint> createCheckpoint() {
        var verification = verifier.verify();
        if (!verification.intact()) {
            throw new IllegalStateException("Cannot checkpoint an invalid audit chain");
        }
        if (verification.verifiedThroughSequence() == 0) {
            return Optional.empty();
        }

        var record = repository.findBySequence(
                DEFAULT_CHAIN_ID,
                verification.verifiedThroughSequence())
                .orElseThrow(() -> new IllegalStateException(
                        "Verified chain record is missing"));
        repository.insertCheckpoint(
                UUID.randomUUID(),
                DEFAULT_CHAIN_ID,
                record.sequence(),
                record.contentHash());
        return repository.findLatestCheckpoint(DEFAULT_CHAIN_ID);
    }
}
