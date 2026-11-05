package dev.personalcloud.storage;

import dev.personalcloud.control.LocalControlClient;
import dev.personalcloud.net.Json;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** Verifies cached remote search metadata remains visible but never appears live after a member goes offline. */
public final class ReferenceFileSystemModelCacheTest {
    private static final String LOCAL_ID = "cache-local-node-01";
    private static final String REMOTE_ID = "cache-remote-node-01";

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-search-cache-test-");
        Path data = Files.createDirectory(workspace.resolve("data"));
        Path socket = data.resolve("control.sock");
        Map<String, Object> remoteResult = result(REMOTE_ID, "Remote laptop", "Research/Design Notes.md");
        Map<String, Object> localResult = result(LOCAL_ID, "Local desktop", "Documents/Current Notes.md");
        try {
            try (FakeControlServer first = new FakeControlServer(socket,
                    List.of(member(LOCAL_ID, "Local desktop", true), member(REMOTE_ID, "Remote laptop", true)),
                    List.of(remoteResult), List.of())) {
                LocalControlClient client = new LocalControlClient(socket);
                ReferenceFileSystemModel model = new ReferenceFileSystemModel(client);
                List<Map<String, Object>> initial = model.search("notes", 20);
                check(initial.size() == 1, "first search must return the live remote result");
                check(Boolean.FALSE.equals(initial.getFirst().get("stale")), "live result must not be marked stale");
                check("AVAILABLE".equals(initial.getFirst().get("availability")), "live result must be marked available");
            }

            try (FakeControlServer second = new FakeControlServer(socket,
                    List.of(member(LOCAL_ID, "Local desktop", true), member(REMOTE_ID, "Remote laptop", false)),
                    List.of(localResult), List.of(Map.of("nodeId", REMOTE_ID, "name", "Remote laptop", "status", "UNAVAILABLE")))) {
                ReferenceFileSystemModel model = new ReferenceFileSystemModel(new LocalControlClient(socket));
                List<Map<String, Object>> current = model.search("notes", 20);
                check(current.size() == 2, "offline remote result must be retained beside fresh local results: " + current);
                Map<String, Object> stale = current.stream()
                        .filter(row -> REMOTE_ID.equals(row.get("ownerNodeId"))).findFirst()
                        .orElseThrow(() -> new AssertionError("cached remote result disappeared after the member went offline"));
                check(Boolean.TRUE.equals(stale.get("stale")), "cached remote result must be marked stale");
                check("UNAVAILABLE".equals(stale.get("availability")), "cached remote result must be marked unavailable");
                check("CACHED".equals(stale.get("source")), "cached result source must be explicit");
                Map<String, Object> local = current.stream()
                        .filter(row -> LOCAL_ID.equals(row.get("ownerNodeId"))).findFirst()
                        .orElseThrow(() -> new AssertionError("fresh local result must remain available"));
                check(Boolean.FALSE.equals(local.get("stale")) && "AVAILABLE".equals(local.get("availability")),
                        "fresh local result must not inherit stale status");
                check(Files.isRegularFile(data.resolve("filesystem-catalogue-cache.json")),
                        "offline-aware search cache must persist across model instances");
                try {
                    check(Files.getPosixFilePermissions(data.resolve("filesystem-catalogue-cache.json"))
                                    .equals(PosixFilePermissions.fromString("rw-------")),
                            "search cache must be private to the current user");
                } catch (UnsupportedOperationException ignored) { }
            }
        } finally {
            deleteTree(workspace);
        }
        System.out.println("PASS: network search persists remote metadata and labels cached results stale/unavailable when their owner goes offline.");
    }

    private static Map<String, Object> result(String owner, String ownerName, String path) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("storageId", "reference-" + owner);
        row.put("storageName", "Documents");
        row.put("storageKind", "REFERENCE");
        row.put("path", path);
        row.put("name", Path.of(path).getFileName().toString());
        row.put("kind", "FILE");
        row.put("size", 42L);
        row.put("modified", "2026-11-04T10:00:00Z");
        row.put("ownerNodeId", owner);
        row.put("ownerNodeName", ownerName);
        row.put("source", owner.equals(LOCAL_ID) ? "LOCAL" : "REMOTE");
        return row;
    }

    private static Map<String, Object> member(String id, String name, boolean online) {
        return Map.of("nodeId", id, "nodeName", name, "status", "ACTIVE", "online", online);
    }

    private static final class FakeControlServer implements AutoCloseable {
        private final ServerSocketChannel server;
        private final AtomicBoolean running = new AtomicBoolean(true);
        private final Thread worker;
        private final List<Map<String, Object>> members;
        private final List<Map<String, Object>> results;
        private final List<Map<String, Object>> unavailable;

        FakeControlServer(Path socket, List<Map<String, Object>> members,
                          List<Map<String, Object>> results, List<Map<String, Object>> unavailable) throws Exception {
            this.members = List.copyOf(members);
            this.results = List.copyOf(results);
            this.unavailable = List.copyOf(unavailable);
            Files.deleteIfExists(socket);
            server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            server.bind(UnixDomainSocketAddress.of(socket));
            Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-------"));
            worker = Thread.ofPlatform().daemon().start(this::serve);
        }

        private void serve() {
            while (running.get()) {
                try (SocketChannel channel = server.accept()) {
                    BufferedReader input = new BufferedReader(Channels.newReader(channel, StandardCharsets.UTF_8));
                    BufferedWriter output = new BufferedWriter(Channels.newWriter(channel, StandardCharsets.UTF_8));
                    String line = input.readLine();
                    if (line == null) continue;
                    Map<String, Object> request = Json.object(line);
                    String command = String.valueOf(request.get("command"));
                    Map<String, Object> response;
                    if ("network.members".equals(command)) response = Map.of("ok", true, "members", members);
                    else if ("network.search".equals(command)) response = Map.of("ok", true,
                            "results", results, "unavailableDevices", unavailable);
                    else response = Map.of("ok", false, "error", "Unsupported test command: " + command);
                    output.write(Json.stringify(response));
                    output.write('\n');
                    output.flush();
                } catch (java.nio.channels.AsynchronousCloseException stopped) {
                    break;
                } catch (Exception failure) {
                    if (running.get()) throw new IllegalStateException("Fake local control server failed", failure);
                }
            }
        }

        @Override public void close() throws Exception {
            running.set(false);
            server.close();
            worker.join(2_000);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
}
