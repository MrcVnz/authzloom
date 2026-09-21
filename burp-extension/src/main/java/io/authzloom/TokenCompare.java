package io.authzloom;

import java.nio.charset.StandardCharsets;

final class TokenCompare {
    private TokenCompare() {}

    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        int diff = x.length ^ y.length;
        int len = Math.max(x.length, y.length);
        for (int i = 0; i < len; i++) {
            byte xb = i < x.length ? x[i] : 0;
            byte yb = i < y.length ? y[i] : 0;
            diff |= xb ^ yb;
        }
        return diff == 0;
    }
}
