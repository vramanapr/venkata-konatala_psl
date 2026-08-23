package com.vkonatala.auditlog.domain.redaction;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RedactionProjectionService {

    private final ObjectMapper objectMapper;

    public RedactionProjectionService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public JsonNode redact(JsonNode source, JsonPointerPath path, String markerJson) {
        JsonNode result = source.deepCopy();
        JsonNode marker;
        try {
            marker = objectMapper.readTree(markerJson);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to create redaction marker", exception);
        }
        replace(result, path.tokens(), 0, marker);
        return result;
    }

    private void replace(JsonNode current, List<String> tokens, int depth, JsonNode replacement) {
        String token = tokens.get(depth);
        boolean last = depth == tokens.size() - 1;
        if (current.isObject()) {
            ObjectNode object = (ObjectNode) current;
            if (!object.has(token)) throw new IllegalArgumentException("path does not exist");
            if (last) object.set(token, replacement);
            else replace(object.get(token), tokens, depth + 1, replacement);
        } else if (current.isArray() && token.matches("0|[1-9][0-9]*")) {
            int index;
            try {
                index = Integer.parseInt(token);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("path array index is invalid", exception);
            }
            ArrayNode array = (ArrayNode) current;
            if (index >= array.size()) throw new IllegalArgumentException("path does not exist");
            if (last) array.set(index, replacement);
            else replace(array.get(index), tokens, depth + 1, replacement);
        } else {
            throw new IllegalArgumentException("path does not exist");
        }
    }
}
