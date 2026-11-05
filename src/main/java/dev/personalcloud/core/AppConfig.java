package dev.personalcloud.core;

import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/** Runtime configuration for a single PersonalCloud node. No browser-admin account is required. */
public record AppConfig(
        String nodeName,
        String nodeId,
        String bindAddress,
        int port,
        Path dataDirectory,
        Path storageRoot,
        Path tlsKeystore,
        String tlsKeystorePassword,
        long maxFileBytes
) {
    public static AppConfig load() throws Exception {
        Path dataDir = Path.of(env("PERSONALCLOUD_DATA_DIR", "./data")).toAbsolutePath().normalize();
        Path storage = Path.of(env("PERSONALCLOUD_STORAGE_ROOT",
                Path.of(System.getProperty("user.home"), "PersonalCloud", "storage").toString()))
                .toAbsolutePath().normalize();
        Files.createDirectories(dataDir);
        Files.createDirectories(storage);
        Path realData = dataDir.toRealPath();
        Path realStorage = storage.toRealPath();
        if (realData.startsWith(realStorage) || realStorage.startsWith(realData)) {
            throw new IllegalArgumentException("PersonalCloud data and managed storage must be separate, non-overlapping directories.");
        }
        restrictDirectory(dataDir);

        String nodeId = SecretFiles.loadOrCreate(dataDir.resolve("node-id.txt"), () -> java.util.UUID.randomUUID().toString());
        String hostName;
        try { hostName = InetAddress.getLocalHost().getHostName(); }
        catch (Exception ignored) { hostName = "PersonalCloud-Device"; }

        String nodeName = env("PERSONALCLOUD_NAME", hostName);
        String bind = env("PERSONALCLOUD_BIND_ADDRESS", "127.0.0.1");
        String keyStoreValue = env("PERSONALCLOUD_TLS_KEYSTORE", "");
        String keyStorePassword = env("PERSONALCLOUD_TLS_KEYSTORE_PASSWORD", "");
        Path keyStore = keyStoreValue.isBlank() ? null : Path.of(keyStoreValue).toAbsolutePath().normalize();
        if (keyStore != null && (!Files.isRegularFile(keyStore) || keyStorePassword.isBlank())) {
            throw new IllegalArgumentException("TLS requires an existing PERSONALCLOUD_TLS_KEYSTORE and PERSONALCLOUD_TLS_KEYSTORE_PASSWORD.");
        }
        boolean loopback = InetAddress.getByName(bind).isLoopbackAddress();
        if (!loopback && keyStore == null) {
            throw new IllegalArgumentException("Non-loopback binding is blocked without TLS. Configure PERSONALCLOUD_TLS_KEYSTORE and PERSONALCLOUD_TLS_KEYSTORE_PASSWORD.");
        }
        long maxFileBytes = Long.parseLong(env("PERSONALCLOUD_MAX_FILE_BYTES", "21474836480"));
        if (maxFileBytes < 1 || maxFileBytes > 100L * 1024 * 1024 * 1024) {
            throw new IllegalArgumentException("PERSONALCLOUD_MAX_FILE_BYTES must be between 1 byte and 100 GiB.");
        }
        int port = Integer.parseInt(env("PERSONALCLOUD_PORT", "8787"));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("PERSONALCLOUD_PORT must be between 1 and 65535.");
        return new AppConfig(nodeName, nodeId, bind, port, dataDir, storage, keyStore, keyStorePassword, maxFileBytes);
    }

    private static void restrictDirectory(Path directory) throws Exception {
        try {
            Files.setPosixFilePermissions(directory, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        } catch (UnsupportedOperationException ignored) {
            // The runtime reports POSIX capability at the local-control boundary as well.
        }
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
