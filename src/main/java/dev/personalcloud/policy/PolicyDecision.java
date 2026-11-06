package dev.personalcloud.policy;

/** Result of a source-side policy evaluation. */
public enum PolicyDecision {
    ALLOW,
    DENY,
    REQUIRE_APPROVAL
}
