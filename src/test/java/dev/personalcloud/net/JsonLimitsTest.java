package dev.personalcloud.net;

import java.util.Map;

/** Bounds tests for the dependency-free JSON parser. */
public final class JsonLimitsTest {
    public static void main(String[] args) throws Exception {
        check("ok".equals(Json.object("{\"value\":\"ok\"}").get("value")),
                "ordinary JSON objects must still parse");

        String nested = "[".repeat(200) + "0" + "]".repeat(200);
        expectFailure(() -> Json.parse(nested), "excessive JSON nesting must be rejected without exhausting the stack");

        String oversized = "0" + " ".repeat(Json.MAX_INPUT_CHARS);
        expectFailure(() -> Json.parse(oversized), "oversized JSON documents must be rejected before parsing");

        expectFailure(() -> Json.parse("{\"value\":1} trailing"), "trailing content must be rejected");
        expectFailure(() -> Json.parse("{\"value\":"), "truncated JSON must be rejected");

        Map<String, Object> roundTrip = Json.object(Json.stringify(Map.of("nested", Map.of("value", 42))));
        check(roundTrip.get("nested") instanceof Map<?, ?> nestedMap
                        && nestedMap.get("value") instanceof Number number
                        && number.longValue() == 42,
                "the writer and reader must remain compatible for ordinary documents");

        System.out.println("PASS: JSON parsing bounds input size, nesting depth and trailing content.");
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException expected) {
            // Expected: hostile or malformed input fails closed.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
