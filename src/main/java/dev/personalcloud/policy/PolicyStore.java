package dev.personalcloud.policy;

import dev.personalcloud.core.StateStore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Persistent, owner-controlled policy rules keyed by eligible root and relative path. */
public final class PolicyStore {
    private static final String RECORD_PREFIX = "policy";
    private static final String EPOCH_KEY = "policy.epoch";

    private final StateStore store;

    public PolicyStore(StateStore store) {
        this.store = store;
    }

    public synchronized Map<String, Object> set(String rootId, String path, PolicyMode mode) throws Exception {
        String normalizedRoot = requireRoot(rootId);
        String normalizedPath = normalize(path);
        if (mode == null) throw new IllegalArgumentException("A policy mode is required.");
        long epoch = nextEpoch();
        PolicyRule rule = new PolicyRule(ruleId(normalizedRoot, normalizedPath), normalizedRoot,
                normalizedPath, mode, Instant.now().toString(), epoch);
        store.putRecord(RECORD_PREFIX, rule.id(), fields(rule));
        return rule.toMap();
    }

    public synchronized boolean remove(String rootId, String path) throws Exception {
        String normalizedRoot = requireRoot(rootId);
        String normalizedPath = normalize(path);
        PolicyRule existing = null;
        for (PolicyRule rule : listRules()) {
            if (rule.rootId().equals(normalizedRoot) && rule.path().equals(normalizedPath)) {
                existing = rule;
                break;
            }
        }
        if (existing == null) return false;
        nextEpoch();
        store.removeRecord(RECORD_PREFIX, existing.id());
        return true;
    }

    public synchronized List<PolicyRule> listRules() {
        List<PolicyRule> result = new ArrayList<>();
        for (Map<String, String> row : store.records(RECORD_PREFIX)) {
            try {
                result.add(new PolicyRule(
                        row.get("_id"),
                        row.getOrDefault("rootId", ""),
                        row.getOrDefault("path", ""),
                        PolicyMode.valueOf(row.getOrDefault("mode", "NORMAL")),
                        row.getOrDefault("updatedAt", ""),
                        parseLong(row.get("epoch"))));
            } catch (RuntimeException invalid) {
                // Ignore malformed policy records; a damaged rule must not grant access.
            }
        }
        result.sort(Comparator.comparing(PolicyRule::rootId).thenComparing(PolicyRule::path));
        return List.copyOf(result);
    }

    /** Returns the most specific rule matching the path, or null when no rule applies. */
    public synchronized PolicyRule ruleFor(String rootId, String path) {
        String normalizedRoot = requireRoot(rootId);
        String normalizedPath = normalize(path);
        PolicyRule best = null;
        for (PolicyRule rule : listRules()) {
            if (!rule.rootId().equals(normalizedRoot)) continue;
            boolean matches = rule.path().isEmpty()
                    || normalizedPath.equals(rule.path())
                    || normalizedPath.startsWith(rule.path() + "/");
            if (matches && (best == null || rule.path().length() > best.path().length())) best = rule;
        }
        return best;
    }

    public synchronized long epoch() {
        String value = store.get(EPOCH_KEY);
        return parseLong(value);
    }

    private long nextEpoch() throws Exception {
        long next = Math.max(epoch(), 0L) + 1L;
        store.put(EPOCH_KEY, Long.toString(next));
        return next;
    }

    private static Map<String, String> fields(PolicyRule rule) {
        return Map.of(
                "rootId", rule.rootId(),
                "path", rule.path(),
                "mode", rule.mode().name(),
                "updatedAt", rule.updatedAt(),
                "epoch", Long.toString(rule.epoch()));
    }

    private static String ruleId(String rootId, String path) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((rootId + "\0" + path).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 32);
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 is unavailable.", impossible);
        }
    }

    private static String requireRoot(String rootId) {
        if (rootId == null || rootId.isBlank()) throw new IllegalArgumentException("An eligible root ID is required.");
        return rootId.strip();
    }

    /** Normalizes a root-relative path and rejects unsafe segments. */
    public static String normalize(String path) {
        String value = path == null ? "" : path.replace('\\', '/').strip();
        while (value.startsWith("/")) value = value.substring(1);
        while (value.endsWith("/") && !value.isEmpty()) value = value.substring(0, value.length() - 1);
        if (value.isEmpty()) return "";
        for (String segment : value.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("Policy path contains an unsafe segment.");
            }
        }
        return value;
    }

    private static long parseLong(String value) {
        if (value == null || value.isBlank()) return 0L;
        try {
            return Long.parseLong(value.strip());
        } catch (NumberFormatException invalid) {
            return 0L;
        }
    }
}
