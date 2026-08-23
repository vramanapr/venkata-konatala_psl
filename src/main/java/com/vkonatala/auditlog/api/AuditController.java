package com.vkonatala.auditlog.api;

import com.vkonatala.auditlog.application.append.AuditLogAppender;
import com.vkonatala.auditlog.application.query.AuditQueryResult;
import com.vkonatala.auditlog.application.query.AuditQueryService;
import com.vkonatala.auditlog.application.verify.AuditChainVerifier;
import com.vkonatala.auditlog.application.verify.AuditVerificationResult;
import com.vkonatala.auditlog.domain.query.AuditQueryCriteria;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditLogAppender appender;
    private final AuditQueryService queryService;
    private final AuditChainVerifier verifier;

    public AuditController(
            AuditLogAppender appender,
            AuditQueryService queryService,
            AuditChainVerifier verifier) {
        this.appender = appender;
        this.queryService = queryService;
        this.verifier = verifier;
    }

    @PostMapping("/events")
    public ResponseEntity<AuditEventResponse> append(
            @Valid @org.springframework.web.bind.annotation.RequestBody AuditEventRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey) {
        AuditEventResponse response =
                AuditEventResponse.from(appender.append(request.toDomain(), idempotencyKey));
        return ResponseEntity
                .created(URI.create("/api/v1/audit/events/" + response.recordId()))
                .body(response);
    }

    @GetMapping("/events")
    public AuditEventPage query(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "0") long afterSequence,
            @RequestParam(defaultValue = "50") int limit) {
        AuditQueryResult result = queryService.query(new AuditQueryCriteria(
                actorId,
                resourceType,
                resourceId,
                eventType,
                from,
                to,
                afterSequence,
                limit));
        return new AuditEventPage(
                result.records().stream().map(AuditEventResponse::from).toList(),
                result.nextSequence());
    }

    @GetMapping("/verify")
    public AuditVerificationResult verify() {
        return verifier.verify();
    }

    public record AuditEventPage(
            List<AuditEventResponse> events,
            Long nextSequence) {
    }
}
