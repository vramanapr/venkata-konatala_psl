package com.vkonatala.auditlog.application.query;

import com.vkonatala.auditlog.domain.query.AuditQueryCriteria;
import com.vkonatala.auditlog.persistence.append.AuditRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditQueryService {

    private static final String DEFAULT_CHAIN_ID = "default";

    private final AuditRecordRepository repository;

    public AuditQueryService(AuditRecordRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public AuditQueryResult query(AuditQueryCriteria criteria) {
        var page = repository.findPage(DEFAULT_CHAIN_ID, criteria);
        return new AuditQueryResult(page.records(), page.nextSequence());
    }
}
