package io.authzloom;

import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

final class CaptureStore {
    static final int MAX = 32;
    static final long TTL_MS = 3_600_000L;

    static final class Capture {
        final String id;
        final String host;
        final int port;
        final boolean secure;
        final String method;
        final String path;
        final byte[] raw;
        final long expiresAt;

        Capture(String id, String host, int port, boolean secure, String method, String path, byte[] raw, long expiresAt) {
            this.id = id;
            this.host = host;
            this.port = port;
            this.secure = secure;
            this.method = method;
            this.path = path;
            this.raw = raw;
            this.expiresAt = expiresAt;
        }
    }

    private final ConcurrentHashMap<String, Capture> items = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    synchronized String put(String host, int port, boolean secure, String method, String path, byte[] raw) {
        purge();
        if (items.size() >= MAX) {
            String oldest = null;
            long min = Long.MAX_VALUE;
            for (Capture capture : items.values()) {
                if (capture.expiresAt < min) {
                    min = capture.expiresAt;
                    oldest = capture.id;
                }
            }
            if (oldest != null) items.remove(oldest);
        }
        byte[] buf = new byte[12];
        random.nextBytes(buf);
        StringBuilder id = new StringBuilder("cap_");
        for (byte b : buf) id.append(String.format("%02x", b));
        Capture capture = new Capture(id.toString(), host, port, secure, method, path, raw, System.currentTimeMillis() + TTL_MS);
        items.put(capture.id, capture);
        return capture.id;
    }

    synchronized Capture get(String id) {
        purge();
        Capture capture = items.get(id);
        if (capture == null || capture.expiresAt <= System.currentTimeMillis()) return null;
        return capture;
    }

    private void purge() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Capture>> it = items.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().expiresAt <= now) it.remove();
        }
    }
}
