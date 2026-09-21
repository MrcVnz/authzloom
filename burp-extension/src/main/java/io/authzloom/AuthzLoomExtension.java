package io.authzloom;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public final class AuthzLoomExtension implements BurpExtension, ContextMenuItemsProvider {
    private static final int MAX_BODY = 1_048_576;
    private MontoyaApi api;
    private String token;
    private final CaptureStore captures = new CaptureStore();

    private static void trace(String line) {
        String path = System.getenv("AUTHZLOOM_BRIDGE_TRACE");
        if (path == null || path.isBlank()) return;
        try {
            java.nio.file.Files.writeString(
                    java.nio.file.Path.of(path),
                    line + System.lineSeparator(),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException ignored) {
        }
    }

    @Override public void initialize(MontoyaApi api) {
        trace("initialize");
        this.api = api;
        this.token = System.getenv("AUTHZLOOM_TOKEN");
        api.extension().setName("AuthzLoom");
        if (token == null || token.isBlank()) {
            trace("token missing");
            api.logging().logToError("AUTHZLOOM_TOKEN is required; bridge is disabled");
            return;
        }
        api.userInterface().registerContextMenuItemsProvider(this);
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8892), 0);
            server.createContext("/health", this::health);
            server.createContext("/send", this::send);
            server.createContext("/replay", this::replay);
            server.setExecutor(Executors.newFixedThreadPool(4, runnable -> {
                Thread thread = new Thread(runnable, "authzloom-bridge");
                thread.setDaemon(true);
                return thread;
            }));
            server.start();
            trace("listening");
            api.logging().logToOutput("Montoya bridge listening on 127.0.0.1:8892");
        } catch (IOException e) {
            trace("bind failed");
            api.logging().logToError("Bridge start failed");
        }
    }

    @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem item = new JMenuItem("Send to AuthzLoom");
        item.setEnabled(!event.selectedRequestResponses().isEmpty());
        item.addActionListener(ignored -> event.selectedRequestResponses().forEach(this::ingest));
        return List.of(item);
    }

    private void health(HttpExchange exchange) throws IOException {
        respond(exchange, 200, "{\"ok\":true,\"service\":\"authzloom-burp\"}");
    }

    private void send(HttpExchange exchange) throws IOException {
        if (!authorized(exchange)) { respond(exchange, 401, "{\"error\":\"unauthorized\"}"); return; }
        try {
            Map<String, Object> body = readObject(exchange);
            String host = BoundedJson.text(body, "host");
            int port = BoundedJson.integer(body, "port");
            boolean secure = BoundedJson.bool(body, "secure");
            byte[] raw = decodeB64(BoundedJson.text(body, "request_b64"));
            HttpService service = HttpService.httpService(host, port, secure);
            HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(raw));
            writeSendResult(exchange, service, request);
        } catch (Exception e) {
            respond(exchange, 400, "{\"error\":\"invalid bridge request\"}");
        }
    }

    private void replay(HttpExchange exchange) throws IOException {
        if (!authorized(exchange)) { respond(exchange, 401, "{\"error\":\"unauthorized\"}"); return; }
        try {
            Map<String, Object> body = readObject(exchange);
            String handle = BoundedJson.text(body, "handle");
            CaptureStore.Capture capture = captures.get(handle);
            if (capture == null) { respond(exchange, 409, "{\"error\":\"CAPTURE_STALE\"}"); return; }
            if (body.containsKey("host")) {
                String host = String.valueOf(body.get("host"));
                if (!capture.host.equalsIgnoreCase(host)) {
                    respond(exchange, 409, "{\"error\":\"CAPTURE_STALE\"}");
                    return;
                }
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> overlay = body.get("overlay") instanceof Map ? (Map<String, Object>) body.get("overlay") : Map.of();
            byte[] raw = HttpOverlay.apply(capture.raw, overlay);
            HttpService service = HttpService.httpService(capture.host, capture.port, capture.secure);
            HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(raw));
            writeSendResult(exchange, service, request);
        } catch (Exception e) {
            respond(exchange, 400, "{\"error\":\"invalid bridge request\"}");
        }
    }

    private void writeSendResult(HttpExchange exchange, HttpService ignored, HttpRequest request) throws IOException {
        HttpRequestResponse result = api.http().sendRequest(request);
        if (!result.hasResponse() || result.response().statusCode() <= 0) {
            respond(exchange, 502, "{\"error\":\"no response\"}");
            return;
        }
        byte[] raw = result.response().toByteArray().getBytes();
        int original = raw.length;
        boolean truncated = original > MAX_BODY;
        if (truncated) {
            raw = java.util.Arrays.copyOf(raw, MAX_BODY);
        }
        String response64 = Base64.getEncoder().encodeToString(raw);
        respond(exchange, 200, "{\"status\":" + result.response().statusCode()
                + ",\"response_b64\":\"" + response64 + "\""
                + ",\"truncated\":" + truncated
                + ",\"original_length\":" + original + "}");
    }

    private void ingest(HttpRequestResponse rr) {
        try {
            byte[] raw = rr.request().toByteArray().getBytes();
            if (raw.length > MAX_BODY) {
                api.logging().logToError("AuthzLoom ingest rejected oversized request");
                return;
            }
            String url = rr.request().url();
            URI uri = URI.create(url);
            String method = rr.request().method();
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            String handle = captures.put(uri.getHost(), uri.getPort() > 0 ? uri.getPort() : (url.startsWith("https") ? 443 : 80),
                    url.startsWith("https"), method, path, raw);
            String payload = "{\"handle\":\"" + handle + "\",\"host\":\"" + escape(uri.getHost()) + "\",\"method\":\"" +
                    escape(method) + "\",\"path\":\"" + escape(path) + "\",\"byte_length\":" + raw.length + "}";
            HttpURLConnection connection = (HttpURLConnection) URI.create("http://127.0.0.1:8891/ingest").toURL().openConnection();
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(5000);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Authorization", "Bearer " + token);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));
            int status = connection.getResponseCode();
            if (status != 202) api.logging().logToError("AuthzLoom ingest returned " + status);
            connection.disconnect();
        } catch (Exception e) {
            api.logging().logToError("AuthzLoom ingest failed");
        }
    }

    private Map<String, Object> readObject(HttpExchange exchange) throws IOException {
        byte[] raw = exchange.getRequestBody().readNBytes(MAX_BODY + 1);
        if (raw.length > MAX_BODY) throw new IllegalArgumentException("too large");
        return BoundedJson.object(new String(raw, StandardCharsets.UTF_8), MAX_BODY);
    }

    private byte[] decodeB64(String value) {
        int approx = value.length() * 3 / 4;
        if (approx > MAX_BODY) throw new IllegalArgumentException("too large");
        byte[] decoded = Base64.getDecoder().decode(value);
        if (decoded.length > MAX_BODY) throw new IllegalArgumentException("too large");
        return decoded;
    }

    private boolean authorized(HttpExchange e) {
        return TokenCompare.constantTimeEquals("Bearer " + token, e.getRequestHeaders().getFirst("Authorization"));
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void respond(HttpExchange e, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        e.getResponseHeaders().set("Content-Type", "application/json");
        e.sendResponseHeaders(status, bytes.length);
        e.getResponseBody().write(bytes);
        e.close();
    }
}
