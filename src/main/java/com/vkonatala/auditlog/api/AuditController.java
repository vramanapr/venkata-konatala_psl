package com.vkonatala.auditlog.api;

import com.vkonatala.auditlog.application.append.AuditLogAppender;
import com.vkonatala.auditlog.application.export.AuditExportService;
import com.vkonatala.auditlog.application.query.AuditQueryResult;
import com.vkonatala.auditlog.application.query.AuditQueryService;
import com.vkonatala.auditlog.application.redaction.AuditRedactionService;
import com.vkonatala.auditlog.application.verify.AuditChainVerifier;
import com.vkonatala.auditlog.application.verify.AuditVerificationResult;
import com.vkonatala.auditlog.domain.query.AuditQueryCriteria;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import jakarta.servlet.http.HttpServletRequest;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditLogAppender appender;
    private final AuditQueryService queryService;
    private final AuditChainVerifier verifier;
    @org.springframework.beans.factory.annotation.Value("${audit.security.enabled:true}")
    private boolean securityEnabled;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AuditRedactionService redactionService;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AuditExportService exportService;

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
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        boolean authenticated = authentication != null && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getName());
        if (securityEnabled && !authenticated) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.UNAUTHORIZED, "Authentication is required");
        }
        String principal = !authenticated
                ? request.actorId() : authentication.getName();
        if (principal == null || principal.isBlank()) {
            throw new IllegalArgumentException("actorId is required when security is disabled");
        }
        String effectiveActor = request.effectiveActorId();
        if (effectiveActor == null || effectiveActor.isBlank()) {
            effectiveActor = principal;
        }
        boolean delegated = !principal.equals(effectiveActor);
        if (delegated && securityEnabled
                && !has(authentication, "audit:admin")
                && !has(authentication, "ROLE_AUDIT_ADMIN")) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.FORBIDDEN,
                    "Delegation requires audit:admin");
        }
        if (delegated && (request.delegationReason() == null
                || request.delegationReason().isBlank()
                || request.delegationEvidence() == null
                || request.delegationEvidence().isNull())) {
            throw new IllegalArgumentException(
                    "delegationReason and delegationEvidence are required for delegation");
        }
        ObjectNode context = JsonNodeFactory.instance.objectNode();
        context.put("method", httpRequest.getMethod());
        context.put("path", httpRequest.getRequestURI());
        String requestId = httpRequest.getHeader("X-Request-Id");
        if (requestId != null && !requestId.isBlank()) context.put("requestId", requestId);
        if (delegated) context.set("delegationEvidence", request.delegationEvidence());
        String reason = delegated ? request.delegationReason() : "audit write authorized";
        String policy = delegated ? "audit:admin" : "audit:write";
        AuditEventResponse response =
                AuditEventResponse.from(appender.append(
                        request.toDomain(principal, effectiveActor,
                                delegated ? principal : null, "ALLOWED", policy, reason, context),
                        idempotencyKey));
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

    @PostMapping("/events/{recordId}/redactions")
    public AuditRedactionResponse redact(
            @PathVariable UUID recordId,
            @Valid @org.springframework.web.bind.annotation.RequestBody AuditRedactionRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            Authentication authentication) {
        if (redactionService == null) {
            throw new IllegalStateException("Redaction service is unavailable");
        }
        return AuditRedactionResponse.from(
                redactionService.redact(recordId,
                        new com.vkonatala.auditlog.domain.redaction.RedactionCommand(
                                request.path(), request.reason(),
                                !isAuthenticated(authentication)
                                        ? (request.requestedBy() == null ? "system" : request.requestedBy())
                                        : authentication.getName()),
                        idempotencyKey));
    }

    @GetMapping("/verify")
    public AuditVerificationResult verify() {
        return verifier.verify();
    }

    @GetMapping(value = "/exports", produces = "application/zip")
    public ResponseEntity<byte[]> export(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId) {
        if (exportService == null) {
            throw new IllegalStateException("Export service is unavailable");
        }
        byte[] bundle = exportService.export(actorId, resourceId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit-export.zip\"")
                .contentType(MediaType.parseMediaType("application/zip"))
                .body(bundle);
    }

    public record AuditEventPage(
            List<AuditEventResponse> events,
            Long nextSequence) {
    }

    private boolean has(Authentication authentication, String authority) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority::equals);
    }

    private boolean isAuthenticated(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getName());
    }
}
