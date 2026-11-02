package dev.personalcloud.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/** Small atomic properties-backed store for the MVP. It can be migrated to SQLite later. */
public final class StateStore {
    private final Path file;
    private final Properties data = new Properties();

    public StateStore(Path dataDirectory) throws Exception {
        this.file = dataDirectory.resolve("state.properties");
        Path backup = file.resolveSibling("state.properties.bak");
        if (Files.exists(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                data.load(in);
            } catch (Exception primaryFailure) {
                if (!Files.exists(backup)) throw new IllegalStateException("State file is corrupt and no recovery backup exists: " + file, primaryFailure);
                data.clear();
                try (InputStream in = Files.newInputStream(backup)) { data.load(in); }
                Files.copy(backup, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } else if (Files.exists(backup)) {
            try (InputStream in = Files.newInputStream(backup)) { data.load(in); }
            Files.copy(backup, file, StandardCopyOption.REPLACE_EXISTING);
        }
        SecretFiles.restrict(file);
        SecretFiles.restrict(backup);
    }

    public synchronized String get(String key) { return data.getProperty(key); }

    public synchronized void put(String key, String value) throws Exception {
        data.setProperty(key, value);
        save();
    }

    public synchronized void remove(String key) throws Exception {
        data.remove(key);
        save();
    }

    public synchronized void putRecord(String prefix, String id, Map<String, String> fields) throws Exception {
        removeRecordProperties(prefix, id);
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            data.setProperty(prefix + "." + id + "." + entry.getKey(), entry.getValue() == null ? "" : entry.getValue());
        }
        save();
    }

    public synchronized Map<String, String> getRecord(String prefix, String id) {
        String start = prefix + "." + id + ".";
        Map<String, String> result = new LinkedHashMap<>();
        for (String key : data.stringPropertyNames()) {
            if (key.startsWith(start)) result.put(key.substring(start.length()), data.getProperty(key));
        }
        return result.isEmpty() ? null : result;
    }

    public synchronized List<Map<String, String>> records(String prefix) {
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
        return result;
    }

    public synchronized void removeRecord(String prefix, String id) throws Exception {
        removeRecordProperties(prefix, id);
        save();
    }

    private void removeRecordProperties(String prefix, String id) {
        String start = prefix + "." + id + ".";
        data.stringPropertyNames().stream().filter(key -> key.startsWith(start)).toList().forEach(data::remove);
    }

    private void save() throws Exception {
        Path temp = file.resolveSibling(file.getFileName() + ".tmp");
        try (OutputStream out = Files.newOutputStream(temp)) {
            data.store(out, "PersonalCloud local state. Keep this file private.");
            out.flush();
        }
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(temp, java.nio.file.StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        SecretFiles.restrict(temp);
        if (Files.exists(file)) {
            Path backup = file.resolveSibling("state.properties.bak");
            Files.copy(file, backup, StandardCopyOption.REPLACE_EXISTING);
            SecretFiles.restrict(backup);
        }
        try {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception atomicMoveUnavailable) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
        SecretFiles.restrict(file);
    }
}
