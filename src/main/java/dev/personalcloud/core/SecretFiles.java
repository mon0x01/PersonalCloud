package dev.personalcloud.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import java.util.function.Supplier;

public final class SecretFiles {
    private static final SecureRandom RANDOM = new SecureRandom();
    private SecretFiles() {}

    public static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String randomCode() {
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        return java.util.HexFormat.of().withUpperCase().formatHex(bytes);
    }

    public static String loadOrCreate(Path file, Supplier<String> generator) throws Exception {
        if (Files.exists(file)) {
            String value = Files.readString(file, StandardCharsets.UTF_8).trim();
            if (!value.isEmpty()) return value;
        }
        String value = generator.get();
        Files.createDirectories(file.getParent());
        Files.writeString(file, value + System.lineSeparator(), StandardCharsets.UTF_8);
        restrict(file);
        return value;
    }

    public static void restrict(Path path) {
        try {
            Files.setPosixFilePermissions(path, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        } catch (Exception ignored) {
            // POSIX permissions are not available on every operating system.
        }
    }
}
