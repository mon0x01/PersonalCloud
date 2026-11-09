package dev.personalcloud.android.core;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON reader/writer for the small node protocol; no external JSON dependency. */
public final class Json {
    private Json() {}

    public static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out) {
        if (value == null) { out.append("null"); return; }
        if (value instanceof String text) { quote(text, out); return; }
        if (value instanceof Number || value instanceof Boolean) { out.append(value); return; }
        if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) out.append(',');
                first = false;
                quote(String.valueOf(entry.getKey()), out);
                out.append(':');
                write(entry.getValue(), out);
            }
            out.append('}');
            return;
        }
        if (value instanceof Iterable<?> iterable) {
            out.append('[');
            boolean first = true;
            for (Object item : iterable) {
                if (!first) out.append(',');
                first = false;
                write(item, out);
            }
            out.append(']');
            return;
        }
        if (value.getClass().isArray()) {
            out.append('[');
            for (int i = 0; i < Array.getLength(value); i++) {
                if (i > 0) out.append(',');
                write(Array.get(value, i), out);
            }
            out.append(']');
            return;
        }
        quote(String.valueOf(value), out);
    }

    private static void quote(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        out.append('"');
    }

    public static Object parse(String input) {
        Parser parser = new Parser(input);
        Object value = parser.value();
        parser.space();
        if (!parser.end()) throw new IllegalArgumentException("Unexpected content after JSON value.");
        return value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(String input) {
        Object value = parse(input);
        if (!(value instanceof Map<?, ?>)) throw new IllegalArgumentException("Expected a JSON object.");
        return (Map<String, Object>) value;
    }

    private static final class Parser {
        private final String text;
        private int index;
        Parser(String text) { this.text = text == null ? "" : text; }
        boolean end() { return index >= text.length(); }
        void space() { while (!end() && Character.isWhitespace(text.charAt(index))) index++; }

        Object value() {
            space();
            if (end()) throw error("Expected a value");
            return switch (text.charAt(index)) {
                case '{' -> objectValue();
                case '[' -> arrayValue();
                case '"' -> stringValue();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> numberValue();
            };
        }

        private Map<String, Object> objectValue() {
            index++;
            Map<String, Object> map = new LinkedHashMap<>();
            space();
            if (take('}')) return map;
            while (true) {
                space();
                if (end() || text.charAt(index) != '"') throw error("Expected object key");
                String key = stringValue();
                space();
                if (!take(':')) throw error("Expected ':'");
                map.put(key, value());
                space();
                if (take('}')) return map;
                if (!take(',')) throw error("Expected ',' or '}'");
            }
        }

        private List<Object> arrayValue() {
            index++;
            List<Object> list = new ArrayList<>();
            space();
            if (take(']')) return list;
            while (true) {
                list.add(value());
                space();
                if (take(']')) return list;
                if (!take(',')) throw error("Expected ',' or ']'");
            }
        }

        private String stringValue() {
            if (!take('"')) throw error("Expected string");
            StringBuilder out = new StringBuilder();
            while (!end()) {
                char c = text.charAt(index++);
                if (c == '"') return out.toString();
                if (c != '\\') { out.append(c); continue; }
                if (end()) throw error("Incomplete escape");
                char escaped = text.charAt(index++);
                switch (escaped) {
                    case '"', '\\', '/' -> out.append(escaped);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (index + 4 > text.length()) throw error("Incomplete unicode escape");
                        out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
                        index += 4;
                    }
                    default -> throw error("Invalid escape");
                }
            }
            throw error("Unclosed string");
        }

        private Object numberValue() {
            int start = index;
            if (!end() && text.charAt(index) == '-') index++;
            while (!end() && Character.isDigit(text.charAt(index))) index++;
            boolean decimal = false;
            if (!end() && text.charAt(index) == '.') {
                decimal = true; index++;
                while (!end() && Character.isDigit(text.charAt(index))) index++;
            }
            if (!end() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
                decimal = true; index++;
                if (!end() && (text.charAt(index) == '+' || text.charAt(index) == '-')) index++;
                while (!end() && Character.isDigit(text.charAt(index))) index++;
            }
            if (start == index) throw error("Invalid number");
            String number = text.substring(start, index);
            try {
                // Keep integral JSON numbers as Long. A conditional expression with
                // double/long operands would promote every integer to double and
                // break canonical signatures over parsed request bodies.
                if (decimal) return Double.parseDouble(number);
                return Long.parseLong(number);
            } catch (NumberFormatException ex) { throw error("Invalid number"); }
        }

        private Object literal(String expected, Object result) {
            if (!text.startsWith(expected, index)) throw error("Invalid token");
            index += expected.length();
            return result;
        }

        private boolean take(char expected) {
            if (!end() && text.charAt(index) == expected) { index++; return true; }
            return false;
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at JSON offset " + index);
        }
    }
}
