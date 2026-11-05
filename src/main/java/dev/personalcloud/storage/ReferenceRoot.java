package dev.personalcloud.storage;

import java.util.LinkedHashMap;
import java.util.Map;

/** Public metadata for a user-approved directory. The physical path is deliberately not exposed. */
public record ReferenceRoot(
        String id,
        String name,
        Availability availability,
        String registeredAt
) {
    public enum Availability { AVAILABLE, MISSING, NOT_READABLE }

    public ReferenceRoot {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("Reference ID is required.");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Reference name is required.");
        if (availability == null) throw new IllegalArgumentException("Reference availability is required.");
        registeredAt = registeredAt == null ? "" : registeredAt;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("name", name);
        result.put("kind", "REFERENCE");
        result.put("availability", availability.name());
        result.put("registeredAt", registeredAt);
        return result;
    }
}
