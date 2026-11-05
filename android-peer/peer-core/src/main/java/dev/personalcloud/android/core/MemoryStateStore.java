package dev.personalcloud.android.core;

import java.util.LinkedHashMap;
import java.util.Map;

public final class MemoryStateStore implements StateStore {
    private Map<String, Object> state = new LinkedHashMap<String, Object>();
    private final Map<String, Map<String, Object>> domains = new LinkedHashMap<String, Map<String, Object>>();
    public synchronized Map<String, Object> load() { return deepCopy(state); }
    public synchronized void save(Map<String, Object> value) { state = deepCopy(value); }
    public synchronized Map<String, Object> loadDomain(String domain) { return deepCopy(domains.getOrDefault(validateDomain(domain), new LinkedHashMap<String, Object>())); }
    public synchronized void saveDomain(String domain, Map<String, Object> value) { domains.put(validateDomain(domain), deepCopy(value)); }
    private static String validateDomain(String value) { if (value == null || !value.matches("[a-z0-9_-]{1,48}")) throw new IllegalArgumentException("Invalid state domain."); return value; }
    @SuppressWarnings("unchecked") private static Map<String, Object> deepCopy(Map<String, Object> source) {
        return (Map<String, Object>) Json.parse(Json.stringify(source));
    }
}
