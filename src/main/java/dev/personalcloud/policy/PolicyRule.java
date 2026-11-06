package dev.personalcloud.policy;

import java.util.LinkedHashMap;
import java.util.Map;

/** Immutable policy rule for one root-relative path. */
public record PolicyRule(String id, String rootId, String path, PolicyMode mode,
                         String updatedAt, long epoch) {

    public PolicyRule {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("Policy rule ID is required.");
        if (rootId == null || rootId.isBlank()) throw new IllegalArgumentException("Policy root ID is required.");
        if (path == null) throw new IllegalArgumentException("Policy path is required.");
        if (mode == null) throw new IllegalArgumentException("Policy mode is required.");
        updatedAt = updatedAt == null ? "" : updatedAt;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("policyId", id);
        result.put("rootId", rootId);
        result.put("path", path);
        result.put("mode", mode.name());
        result.put("updatedAt", updatedAt);
        result.put("epoch", epoch);
        return result;
    }
}
