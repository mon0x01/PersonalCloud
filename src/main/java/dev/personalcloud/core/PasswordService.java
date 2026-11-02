package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Owns admin password verification and safe password rotation. */
public final class PasswordService {
    private final Path hashFile;
    private volatile String hash;

    public PasswordService(AppConfig config) throws Exception {
        this.hashFile = config.dataDirectory().resolve("admin-password.hash");
        this.hash = config.adminPasswordHash();
    }

    public boolean verify(String password) { return PasswordHasher.verify(password, hash); }

    public synchronized void change(String current, String replacement) throws Exception {
        if (!verify(current)) throw new SecurityException("Current administrator password is incorrect.");
        if (replacement == null || replacement.length() < 14 || replacement.length() > 1024) {
            throw new IllegalArgumentException("New password must contain between 14 and 1024 characters.");
        }
        if (replacement.equals(current)) throw new IllegalArgumentException("New password must differ from the current password.");
        String next = PasswordHasher.hash(replacement);
        Path temp = hashFile.resolveSibling(hashFile.getFileName() + ".tmp");
        Files.writeString(temp, next + System.lineSeparator());
        SecretFiles.restrict(temp);
        try {
            Files.move(temp, hashFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException error) {
            Files.move(temp, hashFile, StandardCopyOption.REPLACE_EXISTING);
        }
        SecretFiles.restrict(hashFile);
        hash = next;
    }
}
