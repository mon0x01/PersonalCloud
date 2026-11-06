package dev.personalcloud.policy;

import dev.personalcloud.core.StateStore;

import java.util.List;
import java.util.Map;

/**
 * Single source-side authorization decision point for filesystem operations.
 *
 * <p>Callers must only pass roots that are eligible for network access. The
 * policy layer applies owner exceptions on top of that default. Until the
 * eligible-root registry is wired in, the default for any evaluated path is
 * {@link PolicyDecision#ALLOW}, matching the product's broad-access default.</p>
 */
public final class FilesystemPolicyService {
    private final PolicyStore store;

    public FilesystemPolicyService(StateStore state) {
        this.store = new PolicyStore(state);
    }

    public Map<String, Object> set(String rootId, String path, PolicyMode mode) throws Exception {
        return store.set(rootId, path, mode);
    }

    public boolean remove(String rootId, String path) throws Exception {
        return store.remove(rootId, path);
    }

    public List<Map<String, Object>> list() {
        return store.listRules().stream().map(PolicyRule::toMap).toList();
    }

    public long epoch() {
        return store.epoch();
    }

    public PolicyDecision evaluate(String rootId, String path, PolicyOperation operation) {
        if (operation == null) throw new IllegalArgumentException("A policy operation is required.");
        PolicyRule rule = store.ruleFor(rootId, path);
        if (rule == null) return PolicyDecision.ALLOW;
        return switch (rule.mode()) {
            case PRIVATE -> PolicyDecision.DENY;
            case PROTECTED -> operation.destructive() ? PolicyDecision.REQUIRE_APPROVAL : PolicyDecision.ALLOW;
            case NORMAL -> PolicyDecision.ALLOW;
        };
    }

    /** True when a path may appear in remote listings, search results, or catalogues. */
    public boolean isVisible(String rootId, String path) {
        PolicyRule rule = store.ruleFor(rootId, path);
        return rule == null || rule.mode() != PolicyMode.PRIVATE;
    }
}
