package dev.personalcloud.storage;

import java.util.LinkedHashMap;
import java.util.Map;

/** Metadata for one entry in a referenced directory. No file content is loaded by this type. */
public record StorageEntry(
        String storageId,
        String storageName,
        String relativePath,
        String name,
        Kind kind,
        long sizeBytes,
        String modifiedAt
) {
    public enum Kind { FILE, DIRECTORY }

    public StorageEntry {
        if (storageId == null || storageId.isBlank()) throw new IllegalArgumentException("Storage ID is required.");
        if (storageName == null || storageName.isBlank()) throw new IllegalArgumentException("Storage name is required.");
        if (relativePath == null || relativePath.isBlank()) throw new IllegalArgumentException("Relative path is required.");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Entry name is required.");
        if (kind == null) throw new IllegalArgumentException("Entry kind is required.");
        if (sizeBytes < 0) throw new IllegalArgumentException("Entry size cannot be negative.");
        modifiedAt = modifiedAt == null ? "" : modifiedAt;
        if (kind == Kind.DIRECTORY && sizeBytes != 0) {
            throw new IllegalArgumentException("Directory entries must not advertise a file size.");
        }
    }

    public Map<String, Object> toMap() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("storageId", storageId);
        result.put("storageName", storageName);
        result.put("storageKind", "REFERENCE");
        result.put("path", relativePath);
        result.put("name", name);
        result.put("kind", kind.name());
        result.put("size", sizeBytes);
        result.put("modified", modifiedAt);
        return result;
    }
}
