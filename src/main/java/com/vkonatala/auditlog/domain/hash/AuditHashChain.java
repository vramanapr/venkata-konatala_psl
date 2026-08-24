package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

import static java.time.temporal.ChronoField.NANO_OF_SECOND;

@Component
public class AuditHashChain {

    public static final String GENESIS_VALUE = "audit-chain-genesis:v1";
    public static final String GENESIS_HASH =
            "5a7cc3d90127e61bf2955576dc128ae67d0ce6a61344d03356c556f123b1de84";

    private static final int CANONICAL_SCHEMA_VERSION = 1;
    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
            new DateTimeFormatterBuilder()
                    .appendPattern("uuuu-MM-dd'T'HH:mm:ss")
                    .appendFraction(NANO_OF_SECOND, 9, 9, true)
                    .appendLiteral('Z')
                    .toFormatter()
                    .withZone(ZoneOffset.UTC);

    private final ObjectMapper objectMapper;
    private final Sha256HashService hashService;

    public AuditHashChain(ObjectMapper objectMapper, Sha256HashService hashService) {
        this.objectMapper = objectMapper;
        this.hashService = hashService;
    }

    public AuditHash createFirstRecord(AuditEvent event) {
        return append(event, GENESIS_HASH);
    }

    public AuditHash append(AuditEvent event, String previousHash) {
        requireHash(previousHash, "previousHash");

        ObjectNode hashInput = objectMapper.createObjectNode();
        hashInput.put("schemaVersion", CANONICAL_SCHEMA_VERSION);
        hashInput.put("eventType", event.eventType());
        hashInput.put("actorId", event.actorId());
        hashInput.put("resourceType", event.resourceType());
        hashInput.put("resourceId", event.resourceId());
        hashInput.put("timestamp", TIMESTAMP_FORMATTER.format(event.timestamp()));
        hashInput.set("payload", event.payload());
        ObjectNode authorization = hashInput.putObject("authorization");
        AuditAuthorizationEvidence evidence = event.authorization();
        authorization.put("principal", evidence.principal());
        authorization.put("effectiveActor", evidence.effectiveActor());
        if (evidence.delegatedBy() == null) authorization.putNull("delegatedBy");
        else authorization.put("delegatedBy", evidence.delegatedBy());
        authorization.put("authorizationOutcome", evidence.outcome());
        authorization.put("authorizationPolicy", evidence.policy());
        authorization.put("authorizationReason", evidence.reason());
        authorization.set("requestContext", evidence.requestContext());
        hashInput.put("previousHash", previousHash);

        return new AuditHash(hashService.hash(hashInput), previousHash);
    }

    public String hashEventContent(JsonNode eventContent) {
        return hashService.hash(eventContent);
    }

    private static void requireHash(String hash, String fieldName) {
        if (hash == null || !hash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(
                    fieldName + " must be a lowercase SHA-256 hexadecimal digest");
        }
    }
}
