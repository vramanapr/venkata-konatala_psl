package com.vkonatala.auditlog.domain.hash;

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Serializes JSON into the deterministic representation used as hash input.
 *
 * <p>Rules: object keys are sorted by Unicode code point order, insignificant
 * whitespace is omitted, numbers use normalized decimal notation, strings use
 * JSON escaping, and UTF-8 is applied by the hashing service.</p>
 */
@Component
public class CanonicalJsonSerializer {

    private static final Comparator<String> CODE_POINT_ORDER =
            (left, right) -> {
                int[] leftCodePoints = left.codePoints().toArray();
                int[] rightCodePoints = right.codePoints().toArray();
                int length = Math.min(leftCodePoints.length, rightCodePoints.length);
                for (int index = 0; index < length; index++) {
                    int comparison = Integer.compare(leftCodePoints[index], rightCodePoints[index]);
                    if (comparison != 0) {
                        return comparison;
                    }
                }
                return Integer.compare(leftCodePoints.length, rightCodePoints.length);
            };

    public String serialize(JsonNode node) {
        if (node == null) {
            throw new IllegalArgumentException("JSON node must not be null");
        }

        StringBuilder output = new StringBuilder();
        appendNode(node, output);
        return output.toString();
    }

    private void appendNode(JsonNode node, StringBuilder output) {
        if (node.isObject()) {
            appendObject(node, output);
        } else if (node.isArray()) {
            appendArray(node, output);
        } else if (node.isTextual()) {
            appendString(node.textValue(), output);
        } else if (node.isNumber()) {
            appendNumber(node, output);
        } else if (node.isBoolean() || node.isNull()) {
            output.append(node);
        } else {
            throw new IllegalArgumentException(
                    "Unsupported JSON node type: " + node.getNodeType());
        }
    }

    private void appendObject(JsonNode node, StringBuilder output) {
        List<String> fieldNames = new ArrayList<>();
        node.fieldNames().forEachRemaining(fieldNames::add);
        fieldNames.sort(CODE_POINT_ORDER);

        output.append('{');
        for (int index = 0; index < fieldNames.size(); index++) {
            if (index > 0) {
                output.append(',');
            }
            String fieldName = fieldNames.get(index);
            appendString(fieldName, output);
            output.append(':');
            appendNode(node.get(fieldName), output);
        }
        output.append('}');
    }

    private void appendArray(JsonNode node, StringBuilder output) {
        output.append('[');
        for (int index = 0; index < node.size(); index++) {
            if (index > 0) {
                output.append(',');
            }
            appendNode(node.get(index), output);
        }
        output.append(']');
    }

    private void appendString(String value, StringBuilder output) {
        output.append('"');
        output.append(JsonStringEncoder.getInstance().quoteAsString(value));
        output.append('"');
    }

    private void appendNumber(JsonNode node, StringBuilder output) {
        if (node.isFloatingPointNumber()
                && !Double.isFinite(node.doubleValue())) {
            throw new IllegalArgumentException("Non-finite JSON numbers are not supported");
        }

        BigDecimal decimalValue = node.decimalValue();
        if (decimalValue.signum() == 0) {
            output.append('0');
        } else {
            output.append(decimalValue.stripTrailingZeros().toPlainString());
        }
    }
}
