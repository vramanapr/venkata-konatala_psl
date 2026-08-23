package com.vkonatala.auditlog.domain.redaction;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/** RFC 6901 JSON Pointer with one canonical representation. */
public record JsonPointerPath(String value, List<String> tokens) {

    public JsonPointerPath {
        if (value == null || !value.startsWith("/") || value.length() == 1 && tokens.isEmpty()) {
            throw new IllegalArgumentException("path must be a non-root JSON Pointer");
        }
        tokens = List.copyOf(tokens);
    }

    public static JsonPointerPath parse(String raw) {
        if (raw == null || raw.isEmpty() || !raw.startsWith("/") || raw.equals("/")) {
            throw new IllegalArgumentException("path must be a JSON Pointer beginning with '/'");
        }
        String[] encoded = raw.substring(1).split("/", -1);
        List<String> tokens = new ArrayList<>(encoded.length);
        for (String part : encoded) {
            StringBuilder decoded = new StringBuilder();
            for (int i = 0; i < part.length(); i++) {
                char character = part.charAt(i);
                if (character == '~') {
                    if (++i >= part.length()) {
                        throw new IllegalArgumentException("path contains an invalid escape");
                    }
                    char escaped = part.charAt(i);
                    if (escaped == '0') decoded.append('~');
                    else if (escaped == '1') decoded.append('/');
                    else throw new IllegalArgumentException("path contains an invalid escape");
                } else {
                    decoded.append(character);
                }
            }
            tokens.add(decoded.toString());
        }
        if (tokens.isEmpty()) {
            throw new IllegalArgumentException("root redaction is not supported");
        }
        return new JsonPointerPath("/" + tokens.stream()
                .map(JsonPointerPath::escape)
                .reduce((left, right) -> left + "/" + right).orElseThrow(), tokens);
    }

    public JsonNode resolve(JsonNode root) {
        JsonNode current = root;
        for (String token : tokens) {
            if (current == null) return null;
            if (current.isObject()) {
                current = current.get(token);
            } else if (current.isArray() && token.matches("0|[1-9][0-9]*")) {
                int index;
                try {
                    index = Integer.parseInt(token);
                } catch (NumberFormatException exception) {
                    return null;
                }
                current = index < current.size() ? current.get(index) : null;
            } else {
                return null;
            }
        }
        return current;
    }

    private static String escape(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }
}
