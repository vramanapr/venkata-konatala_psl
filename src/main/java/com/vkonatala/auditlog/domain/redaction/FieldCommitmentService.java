package com.vkonatala.auditlog.domain.redaction;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vkonatala.auditlog.domain.hash.Sha256HashService;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Component
public class FieldCommitmentService {

    public static final int FORMAT_VERSION = 1;
    public static final String ALGORITHM = "sha256";
    private static final int SALT_BYTES = 16;

    private final ObjectMapper objectMapper;
    private final Sha256HashService hashService;
    private final SecureRandom secureRandom = new SecureRandom();

    public FieldCommitmentService(ObjectMapper objectMapper, Sha256HashService hashService) {
        this.objectMapper = objectMapper;
        this.hashService = hashService;
    }

    public List<GeneratedCommitment> generate(UUID recordId, JsonNode payload) {
        List<GeneratedCommitment> commitments = new ArrayList<>();
        collect(payload, "", commitments);
        return commitments;
    }

    public String commitment(String path, JsonNode value, byte[] salt) {
        ObjectNode input = objectMapper.createObjectNode();
        input.put("formatVersion", FORMAT_VERSION);
        input.put("path", JsonPointerPath.parse(path).value());
        input.set("value", value);
        input.put("salt", HexFormat.of().formatHex(salt));
        return hashService.hash(input);
    }

    public String marker(String digest) {
        ObjectNode marker = objectMapper.createObjectNode();
        marker.put("redacted", true);
        marker.put("commitment", "v" + FORMAT_VERSION + ":" + ALGORITHM + ":" + digest);
        return marker.toString();
    }

    private void collect(JsonNode node, String path, List<GeneratedCommitment> output) {
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String childPath = path + "/" + entry.getKey().replace("~", "~0").replace("/", "~1");
                add(childPath, entry.getValue(), output);
                collect(entry.getValue(), childPath, output);
            });
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                String childPath = path + "/" + i;
                add(childPath, node.get(i), output);
                collect(node.get(i), childPath, output);
            }
        }
    }

    private void add(String path, JsonNode value, List<GeneratedCommitment> output) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        output.add(new GeneratedCommitment(
                JsonPointerPath.parse(path).value(), value.deepCopy(), salt,
                commitment(path, value, salt)));
    }

    public record GeneratedCommitment(
            String path,
            JsonNode value,
            byte[] salt,
            String digest) {
        public GeneratedCommitment {
            salt = salt.clone();
            value = value.deepCopy();
        }
    }
}
