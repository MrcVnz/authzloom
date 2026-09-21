package io.authzloom;

import java.nio.charset.StandardCharsets;
import java.util.Map;

final class BoundedJsonSmoke {
    public static void main(String[] args) {
        var obj = BoundedJson.object("{\"host\":\"127.0.0.1\",\"port\":80,\"secure\":false,\"request_b64\":\"YQ==\"}", 1024);
        if (!"127.0.0.1".equals(BoundedJson.text(obj, "host"))) throw new IllegalStateException("host");
        if (BoundedJson.integer(obj, "port") != 80) throw new IllegalStateException("port");
        if (BoundedJson.bool(obj, "secure")) throw new IllegalStateException("secure");
        if (!TokenCompare.constantTimeEquals("Bearer a", "Bearer a")) throw new IllegalStateException("eq");
        if (TokenCompare.constantTimeEquals("Bearer a", "Bearer b")) throw new IllegalStateException("neq");
        CaptureStore store = new CaptureStore();
        String handle = store.put("example.com", 443, true, "GET", "/", "GET / HTTP/1.1\r\n\r\n".getBytes());
        if (store.get(handle) == null) throw new IllegalStateException("store");
        try {
            BoundedJson.parse("{\"a\":", 1024);
            throw new IllegalStateException("should fail");
        } catch (IllegalArgumentException ignored) {
            // expected
        }
        overlayUtf8AndSingleContentLength();
        overlayStripsTransferEncoding();
        System.out.println("ok");
    }

    private static void overlayUtf8AndSingleContentLength() {
        byte[] captured = (
                "POST /x HTTP/1.1\r\nHost: example.com\r\ncontent-length: 4\r\nTransfer-Encoding: chunked\r\n\r\nold!\n"
        ).getBytes(StandardCharsets.ISO_8859_1);
        byte[] rebuilt = HttpOverlay.apply(captured, Map.of("body", "caf\u00e9 \u2615"));
        String http = new String(rebuilt, StandardCharsets.ISO_8859_1);
        if (http.toLowerCase().contains("transfer-encoding")) throw new IllegalStateException("te");
        if (HttpOverlay.contentLengthCount(http) != 1) throw new IllegalStateException("cl count");
        int split = http.indexOf("\r\n\r\n");
        byte[] body = java.util.Arrays.copyOfRange(rebuilt, split + 4, rebuilt.length);
        String text = new String(body, StandardCharsets.UTF_8);
        if (!text.equals("caf\u00e9 \u2615")) throw new IllegalStateException("utf8 body");
        if (!http.contains("Content-Length: " + body.length)) throw new IllegalStateException("cl value");
    }

    private static void overlayStripsTransferEncoding() {
        byte[] captured = "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] rebuilt = HttpOverlay.apply(captured, Map.of("path", "/notes/1"));
        String http = new String(rebuilt, StandardCharsets.US_ASCII);
        if (http.toLowerCase().contains("transfer-encoding")) throw new IllegalStateException("te remains");
        if (!http.startsWith("GET /notes/1 ")) throw new IllegalStateException("path");
    }
}
