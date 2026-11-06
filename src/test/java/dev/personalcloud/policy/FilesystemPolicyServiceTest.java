package dev.personalcloud.policy;

import dev.personalcloud.core.StateStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** Source-side policy evaluation and persistence tests. */
public final class FilesystemPolicyServiceTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-policy-test-");
        try {
            Path data = Files.createDirectory(base.resolve("data"));
            StateStore store = new StateStore(data);
            FilesystemPolicyService policy = new FilesystemPolicyService(store);

            check(policy.evaluate("root-a", "Documents/report.txt", PolicyOperation.READ) == PolicyDecision.ALLOW,
                    "unconfigured paths must use broad default access");
            check(policy.evaluate("root-a", "Documents/report.txt", PolicyOperation.DELETE) == PolicyDecision.ALLOW,
                    "unconfigured destructive operations must be allowed by default");
            check(policy.isVisible("root-a", "Documents/report.txt"), "unconfigured paths must be visible");
            check(policy.epoch() == 0L, "a fresh policy store must start at epoch zero");

            policy.set("root-a", "/Projects/", PolicyMode.PROTECTED);
            check(policy.evaluate("root-a", "Projects", PolicyOperation.READ) == PolicyDecision.ALLOW,
                    "protected paths must remain readable");
            check(policy.evaluate("root-a", "Projects/plan.txt", PolicyOperation.READ) == PolicyDecision.ALLOW,
                    "protected directory rules must apply recursively for reads");
            check(policy.evaluate("root-a", "Projects/plan.txt", PolicyOperation.CREATE) == PolicyDecision.ALLOW,
                    "creating a new name on a protected path must not require approval");
            check(policy.evaluate("root-a", "Projects/plan.txt", PolicyOperation.DELETE) == PolicyDecision.REQUIRE_APPROVAL,
                    "deleting on a protected path must require approval");
            check(policy.evaluate("root-a", "Projects/plan.txt", PolicyOperation.MOVE) == PolicyDecision.REQUIRE_APPROVAL,
                    "moving on a protected path must require approval");
            check(policy.isVisible("root-a", "Projects/plan.txt"), "protected paths must remain visible");

            policy.set("root-a", "Projects/secret", PolicyMode.PRIVATE);
            check(policy.evaluate("root-a", "Projects/secret/keys.txt", PolicyOperation.READ) == PolicyDecision.DENY,
                    "private paths must deny reads at the source");
            check(policy.evaluate("root-a", "Projects/secret/keys.txt", PolicyOperation.LIST) == PolicyDecision.DENY,
                    "private paths must deny listing");
            check(!policy.isVisible("root-a", "Projects/secret"), "private paths must be hidden from catalogues");
            check(!policy.isVisible("root-a", "Projects/secret/keys.txt"), "private rules must hide descendants");
            check(policy.evaluate("root-a", "Projects/other.txt", PolicyOperation.DELETE) == PolicyDecision.REQUIRE_APPROVAL,
                    "a more specific private rule must not weaken its protected parent");

            policy.set("root-a", "", PolicyMode.PRIVATE);
            check(policy.evaluate("root-a", "Anything.txt", PolicyOperation.READ) == PolicyDecision.DENY,
                    "a root-level private rule must deny the whole root");
            check(policy.evaluate("root-b", "Anything.txt", PolicyOperation.READ) == PolicyDecision.ALLOW,
                    "policy rules must be scoped to their eligible root");

            long epochBeforeRemove = policy.epoch();
            check(policy.remove("root-a", "Projects"), "removing an existing rule must report success");
            check(policy.epoch() > epochBeforeRemove, "removing a rule must advance the policy epoch");
            check(!policy.remove("root-a", "Projects"), "removing a missing rule must report no change");
            check(policy.evaluate("root-a", "Projects/plan.txt", PolicyOperation.DELETE) == PolicyDecision.DENY,
                    "removing the child rule must fall back to the private root rule");
            check(policy.evaluate("root-a", "Anything.txt", PolicyOperation.READ) == PolicyDecision.DENY,
                    "removing a child rule must keep the root private rule");

            check(policy.remove("root-a", ""), "removing the root rule must succeed");
            check(policy.evaluate("root-a", "Anything.txt", PolicyOperation.READ) == PolicyDecision.ALLOW,
                    "removing the root rule must restore broad default access");

            policy.set("root-a", "Shared/../escape", PolicyMode.PRIVATE);
            throw new AssertionError("unsafe path segments must be rejected.");
        } catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains("unsafe"), "unsafe policy paths must be rejected with a clear message");
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }

        Path persistedBase = Files.createTempDirectory("personalcloud-policy-persistence-");
        try {
            Path data = Files.createDirectory(persistedBase.resolve("data"));
            FilesystemPolicyService first = new FilesystemPolicyService(new StateStore(data));
            first.set("root-a", "Private", PolicyMode.PRIVATE);
            long epoch = first.epoch();
            List<Map<String, Object>> rules = first.list();
            check(rules.size() == 1, "policy rules must be listed");

            FilesystemPolicyService reopened = new FilesystemPolicyService(new StateStore(data));
            check(reopened.epoch() == epoch, "policy epoch must survive restart");
            check(reopened.list().size() == 1, "policy rules must survive restart");
            check(reopened.evaluate("root-a", "Private/file.txt", PolicyOperation.READ) == PolicyDecision.DENY,
                    "persisted private rules must remain enforced after restart");
            check(reopened.evaluate("root-a", "Public/file.txt", PolicyOperation.READ) == PolicyDecision.ALLOW,
                    "persisted rules must not broaden to unrelated paths");
        } finally {
            try (var paths = Files.walk(persistedBase)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }

        System.out.println("PASS: source-side policy defaults, precedence, hiding, persistence and unsafe-path rejection.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
