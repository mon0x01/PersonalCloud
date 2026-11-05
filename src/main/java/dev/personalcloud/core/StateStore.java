package dev.personalcloud.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Atomic properties-backed state store. Reads and mutations refresh under an OS file lock,
 * so multiple node processes cannot silently overwrite each other's state snapshots.
 */
public final class StateStore {
    private static final ConcurrentHashMap<Path, ReentrantLock> JVM_LOCKS = new ConcurrentHashMap<>();

    private final Path file;
    private final Path backup;
    private final Path lockFile;
    private final ReentrantLock jvmLock;
    private final Properties data = new Properties();

    public StateStore(Path dataDirectory) throws Exception {
        Path suppliedDirectory = dataDirectory.toAbsolutePath().normalize();
        Files.createDirectories(suppliedDirectory);
        if (Files.isSymbolicLink(suppliedDirectory) || !Files.isDirectory(suppliedDirectory, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("PersonalCloud state directory must be a real directory, not a symbolic link.");
        }
        Path canonicalDirectory = suppliedDirectory.toRealPath();
        this.file = canonicalDirectory.resolve("state.properties");
        this.backup = file.resolveSibling("state.properties.bak");
        this.lockFile = file.resolveSibling("state.properties.lock");
        this.jvmLock = JVM_LOCKS.computeIfAbsent(lockFile, ignored -> new ReentrantLock(true));
        withFileLock(() -> { loadLatest(); return null; });
        SecretFiles.restrict(file);
        SecretFiles.restrict(backup);
        SecretFiles.restrict(lockFile);
    }

    public synchronized String get(String key) {
        return readLocked(() -> data.getProperty(key));
    }

    public synchronized void put(String key, String value) throws Exception {
        mutateAndSave(() -> data.setProperty(key, value));
    }

    public synchronized void remove(String key) throws Exception {
        mutateAndSave(() -> data.remove(key));
    }

    public synchronized void putRecord(String prefix, String id, Map<String, String> fields) throws Exception {
        mutateAndSave(() -> {
            removeRecordProperties(prefix, id);
            for (Map.Entry<String, String> entry : fields.entrySet()) {
                data.setProperty(prefix + "." + id + "." + entry.getKey(), entry.getValue() == null ? "" : entry.getValue());
            }
        });
    }

    public synchronized Map<String, String> getRecord(String prefix, String id) {
        return readLocked(() -> {
            String start = prefix + "." + id + ".";
            Map<String, String> result = new LinkedHashMap<>();
            for (String key : data.stringPropertyNames()) {
                if (key.startsWith(start)) result.put(key.substring(start.length()), data.getProperty(key));
            }
            return result.isEmpty() ? null : result;
        });
    }

    public synchronized List<Map<String, String>> records(String prefix) {
        return readLocked(() -> {
            String start = prefix + ".";
            Map<String, Map<String, String>> grouped = new LinkedHashMap<>();
            for (String key : data.stringPropertyNames()) {
                if (!key.startsWith(start)) continue;
                String remainder = key.substring(start.length());
                int dot = remainder.indexOf('.');
                if (dot < 1) continue;
                String id = remainder.substring(0, dot);
                String field = remainder.substring(dot + 1);
                grouped.computeIfAbsent(id, ignored -> new LinkedHashMap<>()).put(field, data.getProperty(key));
            }
            List<Map<String, String>> result = new ArrayList<>();
            for (Map.Entry<String, Map<String, String>> entry : grouped.entrySet()) {
                Map<String, String> row = new LinkedHashMap<>(entry.getValue());
                row.put("_id", entry.getKey());
                result.add(row);
            }
            return List.copyOf(result);
        });
    }

    public synchronized void removeRecord(String prefix, String id) throws Exception {
        mutateAndSave(() -> removeRecordProperties(prefix, id));
    }

    private void mutateAndSave(Runnable mutation) throws Exception {
        withFileLock(() -> {
            loadLatest();
            Properties previous = copy(data);
            mutation.run();
            try {
                save();
            } catch (Exception persistenceFailure) {
                data.clear();
                data.putAll(previous);
                throw persistenceFailure;
            }
            return null;
        });
    }

    private <T> T readLocked(CheckedSupplier<T> action) {
        try {
            return withFileLock(() -> {
                loadLatest();
                return action.get();
            });
        } catch (Exception failure) {
            throw new IllegalStateException("Unable to read PersonalCloud state safely.", failure);
        }
    }

    private <T> T withFileLock(CheckedSupplier<T> action) throws Exception {
        jvmLock.lockInterruptibly();
        try {
            rejectSymbolicLink(lockFile, "state lock");
            try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                 FileLock ignored = channel.lock()) {
                SecretFiles.restrict(lockFile);
                return action.get();
            }
        } finally {
            jvmLock.unlock();
        }
    }

    private void loadLatest() throws Exception {
        ensureRegularIfPresent(file, "state file");
        ensureRegularIfPresent(backup, "state backup");
        data.clear();
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            try (InputStream input = Files.newInputStream(file)) {
                data.load(input);
                return;
            } catch (Exception primaryFailure) {
                if (!Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IllegalStateException("State file is corrupt and no recovery backup exists: " + file, primaryFailure);
                }
                data.clear();
                try (InputStream input = Files.newInputStream(backup)) { data.load(input); }
                restorePrimaryFromBackup();
                return;
            }
        }
        if (Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
            try (InputStream input = Files.newInputStream(backup)) { data.load(input); }
            restorePrimaryFromBackup();
        }
    }

    private void restorePrimaryFromBackup() throws Exception {
        Path temporary = file.resolveSibling(file.getFileName() + ".recover-" + UUID.randomUUID());
        try {
            Files.copy(backup, temporary);
            SecretFiles.restrict(temporary);
            moveReplace(temporary, file);
            forceParentDirectory();
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void removeRecordProperties(String prefix, String id) {
        String start = prefix + "." + id + ".";
        data.stringPropertyNames().stream().filter(key -> key.startsWith(start)).toList().forEach(data::remove);
    }

    private void save() throws Exception {
        ensureRegularIfPresent(file, "state file");
        ensureRegularIfPresent(backup, "state backup");
        Path temporary = file.resolveSibling(file.getFileName() + ".tmp-" + UUID.randomUUID());
        try {
            try (OutputStream output = Files.newOutputStream(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                data.store(output, "PersonalCloud local state. Keep this file private.");
                output.flush();
            }
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) { channel.force(true); }
            SecretFiles.restrict(temporary);
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                Path backupTemp = backup.resolveSibling(backup.getFileName() + ".tmp-" + UUID.randomUUID());
                try {
                    Files.copy(file, backupTemp);
                    try (FileChannel channel = FileChannel.open(backupTemp, StandardOpenOption.WRITE)) { channel.force(true); }
                    SecretFiles.restrict(backupTemp);
                    moveReplace(backupTemp, backup);
                } finally { Files.deleteIfExists(backupTemp); }
            }
            moveReplace(temporary, file);
            forceParentDirectory();
            SecretFiles.restrict(file);
            SecretFiles.restrict(backup);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void moveReplace(Path source, Path target) throws Exception {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unavailable) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void forceParentDirectory() {
        Path parent = file.getParent();
        if (parent == null) return;
        try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) { directory.force(true); }
        catch (Exception unsupported) { /* Directory fsync is platform/provider dependent. */ }
    }

    private static void rejectSymbolicLink(Path path, String label) {
        if (Files.isSymbolicLink(path)) throw new SecurityException("PersonalCloud " + label + " cannot be a symbolic link.");
    }

    private static void ensureRegularIfPresent(Path path, String label) {
        rejectSymbolicLink(path, label);
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("PersonalCloud " + label + " must be a regular file.");
        }
    }

    private static Properties copy(Properties source) {
        Properties result = new Properties();
        result.putAll(source);
        return result;
    }

    @FunctionalInterface private interface CheckedSupplier<T> { T get() throws Exception; }
}
