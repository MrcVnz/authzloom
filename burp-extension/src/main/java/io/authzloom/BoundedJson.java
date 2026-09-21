package io.authzloom;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounded JSON reader for the Burp bridge. Rejects oversized, overly nested, or malformed payloads
 * without regex field extraction.
 */
final class BoundedJson {
    private final String src;
    private final int maxBytes;
    private final int maxDepth;
    private int i;

    BoundedJson(String src, int maxBytes, int maxDepth) {
        if (src == null) throw new IllegalArgumentException("empty");
        if (src.length() > maxBytes) throw new IllegalArgumentException("too large");
        this.src = src;
        this.maxBytes = maxBytes;
        this.maxDepth = maxDepth;
    }

    static Object parse(String src, int maxBytes) {
        return new BoundedJson(src, maxBytes, 8).parseValue(0);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(String src, int maxBytes) {
        Object value = parse(src, maxBytes);
        if (!(value instanceof Map)) throw new IllegalArgumentException("object required");
        return (Map<String, Object>) value;
    }

    static String text(Map<String, Object> obj, String key) {
        Object value = obj.get(key);
        if (!(value instanceof String)) throw new IllegalArgumentException();
        return (String) value;
    }

    static int integer(Map<String, Object> obj, String key) {
        Object value = obj.get(key);
        if (value instanceof Number) return ((Number) value).intValue();
        if (value instanceof String) return Integer.parseInt((String) value);
        throw new IllegalArgumentException();
    }

    static boolean bool(Map<String, Object> obj, String key) {
        Object value = obj.get(key);
        if (value instanceof Boolean) return (Boolean) value;
        if (value instanceof String) return Boolean.parseBoolean((String) value);
        throw new IllegalArgumentException();
    }

    private Object parseValue(int depth) {
        if (depth > maxDepth) throw new IllegalArgumentException("too deep");
        skip();
        if (i >= src.length()) throw new IllegalArgumentException("truncated");
        char c = src.charAt(i);
        if (c == '{') return parseObject(depth + 1);
        if (c == '[') return parseArray(depth + 1);
        if (c == '"') return parseString();
        if (c == 't' || c == 'f') return parseLiteral();
        if (c == 'n') { parseNull(); return null; }
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
        throw new IllegalArgumentException("invalid");
    }

    private Map<String, Object> parseObject(int depth) {
        expect('{');
        Map<String, Object> out = new LinkedHashMap<>();
        skip();
        if (peek('}')) { i++; return out; }
        while (true) {
            skip();
            String key = parseString();
            skip();
            expect(':');
            Object value = parseValue(depth);
            if (out.containsKey(key)) throw new IllegalArgumentException("duplicate");
            out.put(key, value);
            skip();
            if (peek('}')) { i++; return out; }
            expect(',');
        }
    }

    private List<Object> parseArray(int depth) {
        expect('[');
        List<Object> out = new ArrayList<>();
        skip();
        if (peek(']')) { i++; return out; }
        while (true) {
            out.add(parseValue(depth));
            skip();
            if (peek(']')) { i++; return out; }
            expect(',');
        }
    }

    private String parseString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (i < src.length()) {
            char c = src.charAt(i++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (i >= src.length()) throw new IllegalArgumentException("truncated");
                char e = src.charAt(i++);
                switch (e) {
                    case '"': case '\\': case '/': sb.append(e); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 4 > src.length()) throw new IllegalArgumentException("truncated");
                        int cp = Integer.parseInt(src.substring(i, i + 4), 16);
                        sb.append((char) cp);
                        i += 4;
                        break;
                    default: throw new IllegalArgumentException("escape");
                }
            } else if (c < 0x20) {
                throw new IllegalArgumentException("control");
            } else {
                sb.append(c);
            }
            if (sb.length() > maxBytes) throw new IllegalArgumentException("too large");
        }
        throw new IllegalArgumentException("truncated");
    }

    private Object parseNumber() {
        int start = i;
        if (peek('-')) i++;
        if (peek('0')) i++;
        else {
            if (i >= src.length() || src.charAt(i) < '1' || src.charAt(i) > '9') throw new IllegalArgumentException("number");
            while (i < src.length() && src.charAt(i) >= '0' && src.charAt(i) <= '9') i++;
        }
        if (peek('.')) {
            i++;
            if (i >= src.length() || src.charAt(i) < '0' || src.charAt(i) > '9') throw new IllegalArgumentException("number");
            while (i < src.length() && src.charAt(i) >= '0' && src.charAt(i) <= '9') i++;
        }
        if (peek('e') || peek('E')) {
            i++;
            if (peek('+') || peek('-')) i++;
            if (i >= src.length() || src.charAt(i) < '0' || src.charAt(i) > '9') throw new IllegalArgumentException("number");
            while (i < src.length() && src.charAt(i) >= '0' && src.charAt(i) <= '9') i++;
        }
        String raw = src.substring(start, i);
        if (raw.contains(".") || raw.contains("e") || raw.contains("E")) return Double.parseDouble(raw);
        long n = Long.parseLong(raw);
        if (n >= Integer.MIN_VALUE && n <= Integer.MAX_VALUE) return (int) n;
        return n;
    }

    private Boolean parseLiteral() {
        if (src.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
        if (src.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
        throw new IllegalArgumentException("literal");
    }

    private void parseNull() {
        if (!src.startsWith("null", i)) throw new IllegalArgumentException("null");
        i += 4;
    }

    private void skip() {
        while (i < src.length()) {
            char c = src.charAt(i);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') i++;
            else break;
        }
    }

    private boolean peek(char c) {
        return i < src.length() && src.charAt(i) == c;
    }

    private void expect(char c) {
        skip();
        if (!peek(c)) throw new IllegalArgumentException("expected");
        i++;
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
