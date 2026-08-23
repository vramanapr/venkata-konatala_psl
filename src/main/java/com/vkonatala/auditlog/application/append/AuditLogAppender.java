package com.vkonatala.auditlog.application.append;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vkonatala.auditlog.domain.hash.AuditEvent;
import com.vkonatala.auditlog.domain.hash.AuditHash;
import com.vkonatala.auditlog.domain.hash.AuditHashChain;
import com.vkonatala.auditlog.domain.append.AuditRecord;
import com.vkonatala.auditlog.domain.append.IdempotencyConflictException;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class AuditLogAppender {

    private static final String DEFAULT_CHAIN_ID = "default";
    private static final int PAYLOAD_SCHEMA_VERSION = 1;

    private final AuditRecordRepository repository;
    private final AuditHashChain hashChain;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Autowired
    public AuditLogAppender(
            AuditRecordRepository repository,
            AuditHashChain hashChain,
            ObjectMapper objectMapper) {
        this(repository, hashChain, objectMapper, Clock.systemUTC());
    }

    AuditLogAppender(
            AuditRecordRepository repository,
            AuditHashChain hashChain,
            ObjectMapper objectMapper,
            Clock clock) {
        this.repository = repository;
        this.hashChain = hashChain;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Transactional(timeout = 30)
    public AuditRecord append(AuditEvent event, String idempotencyKey) {
        return append(DEFAULT_CHAIN_ID, event, idempotencyKey);
    }

    @Transactional(timeout = 30)
    public AuditRecord append(String chainId, AuditEvent event, String idempotencyKey) {
        String requestFingerprint = fingerprint(event);

        repository.initializeChain(chainId, AuditHashChain.GENESIS_HASH);
        AuditRecordRepository.ChainHead chainHead = repository.lockChainHead(chainId);

        if (idempotencyKey != null) {
            var existing = repository.findIdempotency(idempotencyKey);
            if (existing.isPresent()) {
                if (!existing.get().requestFingerprint().equals(requestFingerprint)) {
                    throw new IdempotencyConflictException(idempotencyKey);
                }
                return repository.findById(existing.get().recordId())
                        .orElseThrow(() -> new IllegalStateException(
                                "Idempotency record references a missing audit record"));
            }
        }

        long sequence = chainHead.nextSequence();
        String previousHash = chainHead.lastHash();
        AuditHash auditHash = hashChain.append(event, previousHash);
        Instant recordedAt = clock.instant();
        AuditRecord record = new AuditRecord(
                UUID.randomUUID(),
                chainId,
                sequence,
                event.eventType(),
                event.actorId(),
                event.resourceType(),
                event.resourceId(),
                event.timestamp(),
                recordedAt,
                event.payload(),
                PAYLOAD_SCHEMA_VERSION,
                auditHash.contentHash(),
                auditHash.previousHash());

        repository.insert(record);
        if (idempotencyKey != null) {
            repository.insertIdempotency(idempotencyKey, requestFingerprint, record.recordId());
        }
        repository.updateChainHead(chainId, sequence + 1, record.recordId(), record.contentHash());
        return record;
    }

    private String fingerprint(AuditEvent event) {
        ObjectNode eventContent = objectMapper.createObjectNode();
        eventContent.put("eventType", event.eventType());
        eventContent.put("actorId", event.actorId());
        eventContent.put("resourceType", event.resourceType());
        eventContent.put("resourceId", event.resourceId());
        eventContent.put("timestamp", event.timestamp().toString());
        eventContent.set("payload", event.payload());
        return hashChain.hashEventContent(eventContent);
    }
}
