package io.authzloom;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Rebuild a captured HTTP/1.1 request with an allowlisted overlay. Package-private for smoke tests. */
final class HttpOverlay {
    private HttpOverlay() {}

    static boolean stripHeader(String name) {
        String lowered = name.toLowerCase(Locale.ROOT);
        return lowered.equals("transfer-encoding")
                || lowered.equals("content-length")
                || lowered.equals("te")
                || lowered.equals("trailer");
    }

    static boolean overlayForbidden(String name) {
        String lowered = name.toLowerCase(Locale.ROOT);
        return lowered.equals("authorization")
                || lowered.equals("cookie")
                || lowered.equals("proxy-authorization")
                || lowered.equals("host")
                || stripHeader(name);
    }

    static byte[] apply(byte[] raw, Map<String, Object> overlay) {
        if (overlay == null) overlay = Map.of();
        int split = indexOfHeaderBreak(raw);
        if (split < 0) throw new IllegalArgumentException();
        String head = new String(raw, 0, split, StandardCharsets.ISO_8859_1);
        byte[] originalBody = java.util.Arrays.copyOfRange(raw, split + 4, raw.length);
        String[] lines = head.split("\r\n", -1);
        String[] req = lines[0].split(" ", 3);
        String method = overlay.get("method") instanceof String ? (String) overlay.get("method") : req[0];
        String path = overlay.get("path") instanceof String ? (String) overlay.get("path") : req[1];
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) continue;
            String name = lines[i].substring(0, colon).trim();
            String value = lines[i].substring(colon + 1).trim();
            if (stripHeader(name)) continue;
            putHeader(headers, name, value);
        }
        Object overlayHeaders = overlay.get("headers");
        if (overlayHeaders instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String name = String.valueOf(entry.getKey());
                if (overlayForbidden(name)) continue;
                putHeader(headers, name, String.valueOf(entry.getValue()));
            }
        }
        byte[] bodyBytes;
        if (overlay.get("body") instanceof String overlayBody) {
            bodyBytes = overlayBody.getBytes(StandardCharsets.UTF_8);
        } else {
            bodyBytes = originalBody;
        }
        putHeader(headers, "Content-Length", Integer.toString(bodyBytes.length));
        StringBuilder out = new StringBuilder();
        out.append(method).append(' ').append(path).append(' ').append(req.length > 2 ? req[2] : "HTTP/1.1").append("\r\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            out.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        out.append("\r\n");
        byte[] headBytes = out.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] combined = new byte[headBytes.length + bodyBytes.length];
        System.arraycopy(headBytes, 0, combined, 0, headBytes.length);
        System.arraycopy(bodyBytes, 0, combined, headBytes.length, bodyBytes.length);
        return combined;
    }

    static void putHeader(LinkedHashMap<String, String> headers, String name, String value) {
        String existing = null;
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                existing = key;
                break;
            }
        }
        if (existing != null) headers.remove(existing);
        headers.put(name, value);
    }

    static int indexOfHeaderBreak(byte[] raw) {
        for (int i = 0; i + 3 < raw.length; i++) {
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    static long contentLengthCount(String http) {
        int count = 0;
        for (String line : http.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("content-length")) count++;
        }
        return count;
    }
}
