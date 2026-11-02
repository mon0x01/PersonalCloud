package dev.personalcloud.core;

import java.net.InetAddress;
import java.nio.file.Path;

public record AppConfig(
        String nodeName,
        String nodeId,
        String adminPassword,
        String bindAddress,
        int port,
        Path dataDirectory,
        Path storageRoot,
        boolean adminPasswordGenerated
) {
    public static AppConfig load() throws Exception {
        Path dataDir = Path.of(env("PERSONALCLOUD_DATA_DIR", "./data")).toAbsolutePath().normalize();
        Path storage = Path.of(env("PERSONALCLOUD_STORAGE_ROOT",
                Path.of(System.getProperty("user.home"), "PersonalCloud", "storage").toString()))
                .toAbsolutePath().normalize();
        java.nio.file.Files.createDirectories(dataDir);
        java.nio.file.Files.createDirectories(storage);
        try {
            java.nio.file.Files.setPosixFilePermissions(dataDir, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        } catch (Exception ignored) { }

        String nodeId = SecretFiles.loadOrCreate(dataDir.resolve("node-id.txt"), () -> java.util.UUID.randomUUID().toString());
        Path passwordFile = dataDir.resolve("admin-password.txt");
        boolean passwordGenerated = !java.nio.file.Files.exists(passwordFile);
        String password = SecretFiles.loadOrCreate(passwordFile, SecretFiles::randomToken);
        String hostName;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (Exception ignored) {
            hostName = "PersonalCloud-Device";
        }
        String nodeName = env("PERSONALCLOUD_NAME", hostName);
        String bind = env("PERSONALCLOUD_BIND_ADDRESS", "127.0.0.1");
        int port = Integer.parseInt(env("PERSONALCLOUD_PORT", "8787"));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("PERSONALCLOUD_PORT must be between 1 and 65535");
        return new AppConfig(nodeName, nodeId, password, bind, port, dataDir, storage, passwordGenerated);
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
