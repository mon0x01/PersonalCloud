package dev.personalcloud.core;

import java.net.InetAddress;
import java.nio.file.Path;

public record AppConfig(
        String nodeName,
        String nodeId,
        String adminPasswordHash,
        String firstRunPassword,
        String bindAddress,
        int port,
        Path dataDirectory,
        Path storageRoot,
        boolean adminPasswordGenerated,
        Path tlsKeystore,
        String tlsKeystorePassword,
        long maxUploadBytes
) {
    public static AppConfig load() throws Exception {
        Path dataDir = Path.of(env("PERSONALCLOUD_DATA_DIR", "./data")).toAbsolutePath().normalize();
        Path storage = Path.of(env("PERSONALCLOUD_STORAGE_ROOT",
                Path.of(System.getProperty("user.home"), "PersonalCloud", "storage").toString()))
                .toAbsolutePath().normalize();
        java.nio.file.Files.createDirectories(dataDir);
        java.nio.file.Files.createDirectories(storage);
        Path realDataDirectory = dataDir.toRealPath();
        Path realStorageRoot = storage.toRealPath();
        if (realDataDirectory.startsWith(realStorageRoot) || realStorageRoot.startsWith(realDataDirectory)) {
            throw new IllegalArgumentException("The data directory and file storage root must be separate, non-overlapping directories. Keeping them separate prevents state, credentials, and recovery snapshots from being indexed as user files.");
        }
        try {
            java.nio.file.Files.setPosixFilePermissions(dataDir, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        } catch (Exception ignored) { }

        String nodeId = SecretFiles.loadOrCreate(dataDir.resolve("node-id.txt"), () -> java.util.UUID.randomUUID().toString());
        Path passwordFile = dataDir.resolve("admin-password.txt");
        Path passwordHashFile = dataDir.resolve("admin-password.hash");
        boolean passwordGenerated = !java.nio.file.Files.exists(passwordFile) && !java.nio.file.Files.exists(passwordHashFile);
        String firstRunPassword = null;
        String passwordHash;
        if (java.nio.file.Files.exists(passwordHashFile)) {
            passwordHash = java.nio.file.Files.readString(passwordHashFile).trim();
            if (!passwordHash.startsWith("pbkdf2-sha256$")) throw new IllegalStateException("Administrator password hash is invalid.");
        } else {
            String initial = java.nio.file.Files.exists(passwordFile)
                    ? java.nio.file.Files.readString(passwordFile).trim() : SecretFiles.randomToken();
            if (initial.isBlank()) {
                initial = SecretFiles.randomToken();
                passwordGenerated = true;
            }
            passwordHash = PasswordHasher.hash(initial);
            java.nio.file.Files.writeString(passwordHashFile, passwordHash + System.lineSeparator());
            SecretFiles.restrict(passwordHashFile);
            java.nio.file.Files.deleteIfExists(passwordFile); // migrate and remove the legacy plaintext secret.
            if (passwordGenerated) firstRunPassword = initial;
        }
        String hostName;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (Exception ignored) {
            hostName = "PersonalCloud-Device";
        }
        String nodeName = env("PERSONALCLOUD_NAME", hostName);
        String bind = env("PERSONALCLOUD_BIND_ADDRESS", "127.0.0.1");
        String keystoreValue = env("PERSONALCLOUD_TLS_KEYSTORE", "");
        String keystorePassword = env("PERSONALCLOUD_TLS_KEYSTORE_PASSWORD", "");
        Path tlsKeystore = keystoreValue.isBlank() ? null : Path.of(keystoreValue).toAbsolutePath().normalize();
        if (tlsKeystore != null && (!java.nio.file.Files.isRegularFile(tlsKeystore) || keystorePassword.isBlank())) {
            throw new IllegalArgumentException("TLS requires an existing PERSONALCLOUD_TLS_KEYSTORE and PERSONALCLOUD_TLS_KEYSTORE_PASSWORD.");
        }
        boolean loopback = InetAddress.getByName(bind).isLoopbackAddress();
        if (!loopback && tlsKeystore == null) {
            throw new IllegalArgumentException("Non-loopback binding is blocked without TLS. Configure PERSONALCLOUD_TLS_KEYSTORE and PERSONALCLOUD_TLS_KEYSTORE_PASSWORD.");
        }
        long maxUploadBytes = Long.parseLong(env("PERSONALCLOUD_MAX_UPLOAD_BYTES", "2147483648"));
        if (maxUploadBytes < 1 || maxUploadBytes > 20L * 1024 * 1024 * 1024) {
            throw new IllegalArgumentException("PERSONALCLOUD_MAX_UPLOAD_BYTES must be between 1 byte and 20 GiB.");
        }
        int port = Integer.parseInt(env("PERSONALCLOUD_PORT", "8787"));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("PERSONALCLOUD_PORT must be between 1 and 65535");
        return new AppConfig(nodeName, nodeId, passwordHash, firstRunPassword, bind, port, dataDir, storage, passwordGenerated, tlsKeystore, keystorePassword, maxUploadBytes);
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
