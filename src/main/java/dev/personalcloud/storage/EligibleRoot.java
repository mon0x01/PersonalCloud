package dev.personalcloud.storage;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** One owner-authorized filesystem root exposed to active network members. */
public record EligibleRoot(String id, String name, Path path, Path realPath) {

    public EligibleRoot {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("Eligible root ID is required.");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Eligible root name is required.");
        if (path == null || realPath == null) throw new IllegalArgumentException("Eligible root paths are required.");
    }

    /** Wire representation. Absolute host paths are intentionally not disclosed to remote members. */
    public Map<String, Object> toRemoteMap() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rootId", id);
        result.put("name", name);
        return result;
    }

    /** Owner-local representation used by the owner-only control socket. */
    public Map<String, Object> toOwnerMap() {
        Map<String, Object> result = toRemoteMap();
        result.put("path", path.toString());
        return result;
    }
}
