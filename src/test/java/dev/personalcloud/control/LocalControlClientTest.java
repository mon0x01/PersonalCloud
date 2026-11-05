package dev.personalcloud.control;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.storage.ReferenceFileSystemModel;
import dev.personalcloud.storage.ReadOnlyVirtualFilesystem;
import dev.personalcloud.storage.ReferenceStorageService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** End-to-end Java client/control/filesystem-model tests. No Python or external test framework. */
public final class LocalControlClientTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-local-control-test-");
        LocalControlServer server = null;
        FileService managedFiles = null;
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path managed = Files.createDirectory(workspace.resolve("managed"));
            Path reference = Files.createDirectory(workspace.resolve("Documents"));
            Path nested = Files.createDirectory(reference.resolve("Research"));
            byte[] payload = new byte[9 * 1024 * 1024 + 37];
            for (int index = 0; index < payload.length; index++) payload[index] = (byte) ((index * 31 + 7) & 0xff);
            Path original = nested.resolve("Large payload.bin");
            Files.write(original, payload);
            String originalDigest = sha256(payload);

            StateStore store = new StateStore(data);
            AppConfig config = new AppConfig("Test Laptop", "node-test-id", "127.0.0.1", 28787,
                    data, managed, null, null, 20L * 1024 * 1024 * 1024);
            managedFiles = new FileService(managed);
            PeerService peers = new PeerService(store, config);
            VersionService versions = new VersionService(data, managedFiles);
            GrantService grants = new GrantService(store, managedFiles, peers, versions, config.maxFileBytes());
            ReferenceStorageService storage = new ReferenceStorageService(store, data, managedFiles.root());
            server = new LocalControlServer(data, config.nodeId(), config.nodeName(), storage, config, peers, grants);
            server.start();
            LocalControlClient client = new LocalControlClient(server.socketPath());

            Map<String, Object> status = client.ping();
            check("node-test-id".equals(status.get("nodeId")), "status must expose the node ID");
            check("Test Laptop".equals(status.get("nodeName")), "status must expose the device name");
            check("personalcloud-control/1".equals(status.get("protocol")), "local protocol version must be stable");
            check(Files.getPosixFilePermissions(server.socketPath()).size() == 2, "local control socket must be owner-only (0600)");
            check(Files.getPosixFilePermissions(data).size() == 3, "control data directory must be owner-only (0700)");

            Map<String, Object> created = client.registerReference("Research Documents", reference);
            @SuppressWarnings("unchecked") Map<String, Object> rootMap = (Map<String, Object>) created.get("reference");
            String rootId = (String) rootMap.get("id");
            check(rootId != null && !rootId.isBlank(), "registration must return a reference ID");
            check(client.listReferences().size() == 1, "registered reference must be listed");
            check(Files.exists(original), "reference registration must not copy or move the original");
            check(countRegularFiles(managed) == 0, "reference registration must not populate managed storage");

            List<Map<String, Object>> directories = client.listEntries(rootId, "");
            check(directories.size() == 1 && "Research".equals(directories.get(0).get("name")), "browse must list the original directory");
            List<Map<String, Object>> files = client.listEntries(rootId, "Research");
            check(files.size() == 1 && "Large payload.bin".equals(files.get(0).get("name")), "browse must preserve file names with spaces");
            check(client.search("large payload", 20).size() == 1, "name/path search must find the referenced file");
            check(((Number) client.stat(rootId, "Research/Large payload.bin").get("size")).longValue() == payload.length,
                    "stat must return the original file size");
            Map<String, Object> located = client.locateReferenceFile(original);
            check(rootId.equals(located.get("referenceId")), "selected file must resolve to its containing reference root");
            check("Research/Large payload.bin".equals(located.get("relativePath")), "located file must return a portable root-relative path");
            check("Large payload.bin".equals(located.get("fileName")), "located file metadata must preserve the original filename");
            Path outside = workspace.resolve("outside.bin");
            Files.writeString(outside, "not in a reference");
            expectFailure(() -> client.locateReferenceFile(outside), "unregistered files must not be shareable by reference");
            Path symlink = workspace.resolve("linked-file.bin");
            Files.createSymbolicLink(symlink, original);
            expectFailure(() -> client.locateReferenceFile(symlink), "symbolic-link files must not be shareable by reference");
            Path aliasDirectory = workspace.resolve("Documents-alias");
            Files.createSymbolicLink(aliasDirectory, reference);
            expectFailure(() -> client.locateReferenceFile(aliasDirectory.resolve("Research/Large payload.bin")),
                    "paths traversing symbolic-link directories must not be shareable by reference");

            byte[] range = client.readRange(rootId, "Research/Large payload.bin", 101, 4097);
            check(Arrays.equals(range, Arrays.copyOfRange(payload, 101, 101 + range.length)), "random-access range must match the original bytes");
            check(client.readRange(rootId, "Research/Large payload.bin", payload.length + 10L, 128).length == 0,
                    "reading beyond EOF must return an empty result");

            ReferenceFileSystemModel model = new ReferenceFileSystemModel(client);
            ReadOnlyVirtualFilesystem nativeFilesystem = new ReadOnlyVirtualFilesystem(model);
            check(nativeFilesystem.list("/").equals(List.of("Devices")), "native filesystem root must expose Devices");
            check(ReadOnlyVirtualFilesystem.normalize("/Devices//Test Laptop/").equals("/Devices/Test Laptop"),
                    "native adapter must normalize repeated and trailing separators");
            expectFailure(() -> ReadOnlyVirtualFilesystem.normalize("/Devices/../outside"),
                    "native adapter must reject parent traversal");
            expectFailure(() -> ReadOnlyVirtualFilesystem.normalize("/Devices/..\\outside"),
                    "native adapter must reject backslash traversal");
            expectFailure(() -> nativeFilesystem.list("/Devices/Test Laptop/References/Research Documents/Research/Large payload.bin"),
                    "native adapter must not list a regular file as a directory");
            check(model.list("/Devices").equals(List.of("Test Laptop")), "filesystem must expose the local node");
            check(model.list("/Devices/Test Laptop").equals(List.of("References", "Distributed-Storage")), "node must expose Referenced and Distributed-Storage views");
            check(model.list("/Devices/Test Laptop/References").equals(List.of("Research Documents")), "filesystem must expose approved reference roots");
            String virtualFile = "/Devices/Test Laptop/References/Research Documents/Research/Large payload.bin";
            ReferenceFileSystemModel.Attributes attributes = model.attributes(virtualFile);
            check(!attributes.directory() && attributes.sizeBytes() == payload.length, "virtual file attributes must match the original");
            check(Arrays.equals(model.read(virtualFile, 200, 512), Arrays.copyOfRange(payload, 200, 712)),
                    "filesystem model must stream requested byte ranges");
            check(nativeFilesystem.openForRead(virtualFile).sizeBytes() == payload.length,
                    "native adapter must open existing files read-only with accurate metadata");
            check(Arrays.equals(nativeFilesystem.read(virtualFile, 333, 2048), Arrays.copyOfRange(payload, 333, 2381)),
                    "native adapter must return exact bounded random-access bytes");
            expectFailure(() -> nativeFilesystem.read(virtualFile, -1, 10), "native adapter must reject negative offsets");
            expectFailure(() -> nativeFilesystem.read(virtualFile, 0, ReadOnlyVirtualFilesystem.MAX_READ_BYTES + 1),
                    "native adapter must enforce bounded reads");
            expectFailure(() -> model.attributes("/Devices/Test Laptop/References/Research Documents/../data"),
                    "filesystem paths must reject traversal");
            expectFailure(() -> client.listEntries(rootId, "../data"), "local control must reject traversal");

            Path download = workspace.resolve("downloaded.bin");
            LocalControlClient.DownloadResult result = client.download(rootId, "Research/Large payload.bin", download);
            check(result.sizeBytes() == payload.length, "download must preserve the complete file size");
            check(result.sha256().equals(originalDigest), "download must report the original SHA-256");
            check(Arrays.equals(Files.readAllBytes(download), payload), "download must reconstruct the exact original file");
            expectFailure(() -> client.download(rootId, "Research/Large payload.bin", download), "download must not overwrite an existing destination");

            // Duplicate startup must not unlink or replace the original process's socket.
            LocalControlServer duplicate = new LocalControlServer(data, config.nodeId(), config.nodeName(), storage, config, peers, grants);
            try {
                try {
                    duplicate.start();
                    throw new AssertionError("A duplicate daemon must not acquire the same local control socket.");
                } catch (IllegalStateException expected) { }
            } finally {
                duplicate.close();
            }
            check(Files.exists(server.socketPath()), "failed duplicate startup must not remove the live socket");
            check("node-test-id".equals(client.ping().get("nodeId")), "original daemon must remain reachable after duplicate startup fails");

            Path applicationJar = Path.of(System.getProperty("java.class.path").split(java.util.regex.Pattern.quote(System.getProperty("path.separator")))[0]).toAbsolutePath();
            Process cli = new ProcessBuilder(javaBinary(), "-jar", applicationJar.toString(), "local",
                    "--socket", server.socketPath().toString(), "status").redirectErrorStream(true).start();
            byte[] cliOutput = cli.getInputStream().readAllBytes();
            int cliExit = cli.waitFor();
            check(cliExit == 0, "Java CLI status must exit successfully: " + new String(cliOutput));
            check(new String(cliOutput).contains("personalcloud-control/1"), "Java CLI status must print the local protocol");

            client.unregisterReference(rootId);
            check(client.listReferences().isEmpty(), "unregister must remove the reference metadata");
            check(Files.exists(original) && Arrays.equals(Files.readAllBytes(original), payload),
                    "unregister must never delete or alter the referenced original");
            check(server.socketPath().toString().length() < 100, "Unix socket path must remain below the portable path limit");
        } finally {
            if (server != null) server.close();
            if (managedFiles != null) managedFiles.close();
            deleteTree(workspace);
        }
        System.out.println("PASS: Java local-control client/CLI, owner-only socket, reference browse/search/stat, random-access reads, read-only filesystem model, multi-chunk download/SHA-256, traversal rejection, duplicate-start safety and zero-copy unregister.");
    }

    private static String javaBinary() { return Path.of(System.getProperty("java.home"), "bin", "java").toString(); }
    private static long countRegularFiles(Path root) throws Exception { try (var paths = Files.walk(root)) { return paths.filter(Files::isRegularFile).count(); } }
    private static String sha256(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static void expectFailure(ThrowingRunnable operation, String message) throws Exception {
        try { operation.run(); throw new AssertionError(message); }
        catch (IllegalArgumentException | SecurityException | java.io.IOException expected) { }
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> { try { Files.deleteIfExists(path); } catch (Exception ignored) { } });
        }
    }
    @FunctionalInterface private interface ThrowingRunnable { void run() throws Exception; }
}
