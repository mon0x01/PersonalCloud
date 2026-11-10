package dev.personalcloud.transfer;

import dev.personalcloud.core.StateStore;
import dev.personalcloud.net.Json;
import dev.personalcloud.network.DeviceIdentity;
import dev.personalcloud.network.NetworkMembershipService;
import dev.personalcloud.storage.EligibleStorageService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Signed, single-use tickets for three-peer coordinated transfers.
 *
 * <p>The coordinating device (Z) signs a ticket that binds the source device,
 * destination device, resource paths, operation, version, size, digest,
 * expiry, request identity and optional owner approvals. Source and
 * destination verify the issuer's active membership key independently and
 * persist a durable claim before doing any work. A ticket can be retried with
 * the same transfer identity, but a different transfer identity is rejected.</p>
 */
public final class TransferTicketService {
    public static final String TICKET_VERSION = "personalcloud-coordinated-ticket/1";
    public static final long DEFAULT_TTL_SECONDS = 600;
    public static final long MAX_TTL_SECONDS = 3600;
    private static final long CLOCK_SKEW_SECONDS = 120;
    private static final String CLAIM_PREFIX = "coordinatedTicketClaim";
    private static final int MAX_CLAIMS = 5000;
    private static final long CLAIM_RETENTION_SECONDS = MAX_TTL_SECONDS * 2L;

    private final StateStore state;
    private final NetworkMembershipService membership;

    public TransferTicketService(StateStore state, NetworkMembershipService membership) {
        this.state = state;
        this.membership = membership;
    }

    /** Builds the canonical, unsigned ticket body in a stable field order. */
    public static Map<String, Object> build(String ticketId, String requestId, String transferId,
                                            String issuerNodeId, String sourceNodeId, String destinationNodeId,
                                            String sourceRootId, String sourcePath,
                                            String destinationRootId, String destinationPath,
                                            String operation, boolean overwrite, long size, String sha256,
                                            String version, String sourceApprovalId,
                                            String destinationApprovalId, long ttlSeconds) {
        Instant issued = Instant.now();
        long ttl = ttlSeconds <= 0 ? DEFAULT_TTL_SECONDS : Math.min(ttlSeconds, MAX_TTL_SECONDS);
        Map<String, Object> ticket = new LinkedHashMap<>();
        ticket.put("ticketVersion", TICKET_VERSION);
        ticket.put("ticketId", canonicalUuid(ticketId, "Ticket ID"));
        ticket.put("requestId", canonicalUuid(requestId, "Request ID"));
        ticket.put("transferId", canonicalUuid(transferId, "Transfer ID"));
        ticket.put("issuerNodeId", requireText(issuerNodeId, "Issuer node ID"));
        ticket.put("sourceNodeId", requireText(sourceNodeId, "Source node ID"));
        ticket.put("destinationNodeId", requireText(destinationNodeId, "Destination node ID"));
        ticket.put("sourceRootId", requireText(sourceRootId, "Source root ID"));
        ticket.put("sourcePath", EligibleStorageService.normalizeRelative(sourcePath));
        ticket.put("destinationRootId", requireText(destinationRootId, "Destination root ID"));
        ticket.put("destinationPath", EligibleStorageService.normalizeRelative(destinationPath));
        ticket.put("operation", normalizeOperation(operation));
        ticket.put("overwrite", overwrite);
        ticket.put("size", size);
        ticket.put("sha256", normalizeHash(sha256));
        ticket.put("version", requireText(version, "Source version"));
        ticket.put("sourceApprovalId", sourceApprovalId == null ? "" : sourceApprovalId);
        ticket.put("destinationApprovalId", destinationApprovalId == null ? "" : destinationApprovalId);
        ticket.put("issuedAt", issued.toString());
        ticket.put("expiresAt", issued.plusSeconds(ttl).toString());
        return ticket;
    }

    /** Signs the canonical ticket body with this device's membership identity. */
    public String sign(Map<String, Object> ticket) throws Exception {
        validateStructure(ticket);
        return Base64.getEncoder().encodeToString(membership.identity().sign(canonicalBytes(ticket)));
    }

    /**
     * Verifies the ticket signature against the active issuer member key and
     * checks all structural, expiry and role bindings. Returns the parsed
     * ticket body unchanged.
     */
    public Map<String, Object> verify(Map<String, Object> ticket, String signature) throws Exception {
        validateStructure(ticket);
        String issuer = text(ticket, "issuerNodeId");
        PublicKey issuerKey = membership.activeMemberPublicKey(issuer);
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(signature == null ? "" : signature);
        } catch (IllegalArgumentException invalid) {
            throw new SecurityException("The coordinated transfer ticket signature is not valid base64.");
        }
        if (decoded.length == 0 || decoded.length > 512
                || !DeviceIdentity.verify(issuerKey, canonicalBytes(ticket), decoded)) {
            throw new SecurityException("The coordinated transfer ticket signature is invalid.");
        }
        Instant now = Instant.now();
        Instant issuedAt = Instant.parse(text(ticket, "issuedAt"));
        Instant expiresAt = Instant.parse(text(ticket, "expiresAt"));
        if (issuedAt.isAfter(now.plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new SecurityException("The coordinated transfer ticket was issued in the future.");
        }
        if (!expiresAt.isAfter(issuedAt) || expiresAt.isAfter(issuedAt.plusSeconds(MAX_TTL_SECONDS))) {
            throw new SecurityException("The coordinated transfer ticket has an invalid lifetime.");
        }
        if (!now.isBefore(expiresAt)) {
            throw new SecurityException("The coordinated transfer ticket has expired.");
        }
        if (Duration.between(issuedAt, now).toSeconds() > MAX_TTL_SECONDS + CLOCK_SKEW_SECONDS) {
            throw new SecurityException("The coordinated transfer ticket is too old.");
        }
        return ticket;
    }

    /**
     * Durably binds a ticket to one transfer identity for one role. The same
     * ticket and transfer may be retried; any different binding is rejected.
     */
    public synchronized void claim(Map<String, Object> ticket, String role, String transferId,
                                   String requestId) throws Exception {
        String ticketId = text(ticket, "ticketId");
        String normalizedRole = requireText(role, "Ticket claim role").toUpperCase(Locale.ROOT);
        String normalizedTransfer = canonicalUuid(transferId, "Transfer ID");
        String normalizedRequest = canonicalUuid(requestId, "Request ID");
        String digest = ticketDigest(ticket);
        Map<String, String> existing = state.getRecord(CLAIM_PREFIX, ticketId);
        if (existing != null) {
            boolean matches = normalizedRole.equals(existing.get("role"))
                    && normalizedTransfer.equals(existing.get("transferId"))
                    && normalizedRequest.equals(existing.get("requestId"))
                    && digest.equals(existing.get("ticketSha256"));
            if (!matches) {
                throw new SecurityException("This coordinated transfer ticket was already claimed by a different operation.");
            }
            return;
        }
        Map<String, String> row = new LinkedHashMap<>();
        row.put("ticketId", ticketId);
        row.put("role", normalizedRole);
        row.put("transferId", normalizedTransfer);
        row.put("requestId", normalizedRequest);
        row.put("issuerNodeId", text(ticket, "issuerNodeId"));
        row.put("ticketSha256", digest);
        row.put("claimedAt", Instant.now().toString());
        pruneClaims();
        state.putRecord(CLAIM_PREFIX, ticketId, row);
    }

    /** Keeps durable ticket claims bounded; expired tickets can no longer be replayed. */
    private void pruneClaims() throws Exception {
        List<Map<String, String>> claims = state.records(CLAIM_PREFIX);
        if (claims.isEmpty()) return;
        Instant cutoff = Instant.now().minusSeconds(CLAIM_RETENTION_SECONDS);
        List<Map<String, String>> removable = new java.util.ArrayList<>();
        for (Map<String, String> claim : claims) {
            try {
                if (Instant.parse(claim.getOrDefault("claimedAt", "")).isBefore(cutoff)) removable.add(claim);
            } catch (Exception ignored) {
                removable.add(claim);
            }
        }
        int excess = claims.size() - removable.size() - MAX_CLAIMS;
        if (excess > 0) {
            claims.stream()
                    .filter(claim -> !removable.contains(claim))
                    .sorted(java.util.Comparator.comparing(claim -> claim.getOrDefault("claimedAt", "")))
                    .limit(excess)
                    .forEach(removable::add);
        }
        for (Map<String, String> claim : removable) state.removeRecord(CLAIM_PREFIX, claim.get("_id"));
    }

    public synchronized Map<String, String> claimRecord(String ticketId) {
        return state.getRecord(CLAIM_PREFIX, ticketId);
    }

    public static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("Ticket field '" + key + "' is required.");
        }
        return text;
    }

    public static long number(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException("Ticket field '" + key + "' must be a number.");
        }
        return number.longValue();
    }

    public static boolean bool(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof Boolean bool)) {
            throw new IllegalArgumentException("Ticket field '" + key + "' must be a boolean.");
        }
        return bool;
    }

    public static String operation(Map<String, Object> ticket) {
        return normalizeOperation(text(ticket, "operation"));
    }

    public static String normalizeOperation(String operation) {
        String value = requireText(operation, "Operation").toUpperCase(Locale.ROOT);
        if (!value.equals("COPY") && !value.equals("MOVE")) {
            throw new IllegalArgumentException("Coordinated transfer operation must be COPY or MOVE.");
        }
        return value;
    }

    private static void validateStructure(Map<String, Object> ticket) {
        if (ticket == null) throw new IllegalArgumentException("A coordinated transfer ticket is required.");
        if (!TICKET_VERSION.equals(ticket.get("ticketVersion"))) {
            throw new IllegalArgumentException("Unsupported coordinated transfer ticket version.");
        }
        canonicalUuid(text(ticket, "ticketId"), "Ticket ID");
        canonicalUuid(text(ticket, "requestId"), "Request ID");
        canonicalUuid(text(ticket, "transferId"), "Transfer ID");
        String issuer = text(ticket, "issuerNodeId");
        String source = text(ticket, "sourceNodeId");
        String destination = text(ticket, "destinationNodeId");
        if (issuer.equals(source) || issuer.equals(destination) || source.equals(destination)) {
            throw new SecurityException("A coordinated transfer requires three distinct devices.");
        }
        text(ticket, "sourceRootId");
        text(ticket, "destinationRootId");
        EligibleStorageService.normalizeRelative(text(ticket, "sourcePath"));
        String destinationPath = EligibleStorageService.normalizeRelative(text(ticket, "destinationPath"));
        if (destinationPath.isEmpty()) throw new IllegalArgumentException("A coordinated destination path is required.");
        normalizeOperation(text(ticket, "operation"));
        bool(ticket, "overwrite");
        long size = number(ticket, "size");
        if (size < 0) throw new IllegalArgumentException("Coordinated transfer size cannot be negative.");
        normalizeHash(text(ticket, "sha256"));
        text(ticket, "version");
        // Optional approvals must be text when present.
        Object sourceApproval = ticket.get("sourceApprovalId");
        Object destinationApproval = ticket.get("destinationApprovalId");
        if (sourceApproval != null && !(sourceApproval instanceof String)) {
            throw new IllegalArgumentException("Ticket field 'sourceApprovalId' must be text.");
        }
        if (destinationApproval != null && !(destinationApproval instanceof String)) {
            throw new IllegalArgumentException("Ticket field 'destinationApprovalId' must be text.");
        }
    }

    private static byte[] canonicalBytes(Map<String, Object> ticket) {
        return Json.stringify(ticket).getBytes(StandardCharsets.UTF_8);
    }

    private static String ticketDigest(Map<String, Object> ticket) throws Exception {
        return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(canonicalBytes(ticket)));
    }

    private static String canonicalUuid(String value, String label) {
        try {
            String canonical = UUID.fromString(requireText(value, label)).toString();
            if (!canonical.equalsIgnoreCase(value)) throw new IllegalArgumentException(label + " must be a canonical UUID.");
            return canonical;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException(label + " must be a canonical UUID.", invalid);
        }
    }

    private static String normalizeHash(String value) {
        String hash = requireText(value, "SHA-256 digest").toLowerCase(Locale.ROOT);
        if (!hash.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("A SHA-256 digest is required.");
        return hash;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required.");
        return value;
    }
}
