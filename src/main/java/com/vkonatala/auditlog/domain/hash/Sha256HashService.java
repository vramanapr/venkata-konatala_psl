package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
public class Sha256HashService {

    private static final String ALGORITHM = "SHA-256";
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private final CanonicalJsonSerializer canonicalJsonSerializer;

    public Sha256HashService(CanonicalJsonSerializer canonicalJsonSerializer) {
        this.canonicalJsonSerializer = canonicalJsonSerializer;
    }

    public String hash(JsonNode node) {
        String canonicalJson = canonicalJsonSerializer.serialize(node);
        return hash(canonicalJson.getBytes(StandardCharsets.UTF_8));
    }

    public String hash(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            return HEX_FORMAT.formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(ALGORITHM + " is unavailable", exception);
        }
    }
}
