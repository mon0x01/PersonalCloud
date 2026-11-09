package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.net.Json;
import dev.personalcloud.storage.EligibleStorageService;
import dev.personalcloud.transfer.TransferTicketService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Three-peer coordinated transfer service.
 *
 * <p>The coordinating node (Z) fetches source metadata, signs a ticket, asks
 * the source node (X) to execute it, and receives metadata-only progress. The
 * source streams chunks directly to the destination (Y). Z never opens the
 * source file and never receives file bytes.</p>
 */
public final class CoordinatedTransferService {
    private static final String REQUEST_PREFIX = "coordinatedRequest";
    private static final String JOB_PREFIX = "coordinatedJob";

    private final AppConfig config;
    private final NetworkMembershipService membership;
    private final EligibleStorageService filesystem;
    private final TransferTicketService tickets;
    private final NetworkPeerClient client;
    private final StateStore state;

    public CoordinatedTransferService(AppConfig config, NetworkMembershipService membership,
                                      EligibleStorageService filesystem, TransferTicketService tickets,
                                      NetworkPeerClient client, StateStore state) {
        this.config = config;
        this.membership = membership;
        this.filesystem = filesystem;
        this.tickets = tickets;
        this.client = client;
        this.state = state;
    }

    /** Read-only plan for a coordinated transfer: source metadata and destination requirements. */
    public Map<String, Object> plan(String sourceNodeId, String sourceRootId, String sourcePath,
                                    String destinationNodeId, String destinationRootId,
                                    String destinationPath) throws Exception {
        requireDistinctEndpoints(sourceNodeId, destinationNodeId);
        String sourceUrl = membership.activeMemberEndpoint(sourceNodeId);
        String destinationUrl = membership.activeMemberEndpoint(destinationNodeId);
        Map<String, Object> source = client.coordinatedMetadata(sourceUrl, "source", sourceRootId,
                sourcePath, membership);
        Map<String, Object> destination = client.coordinatedMetadata(destinationUrl, "destination",
                destinationRootId, destinationPath, membership);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sourceNodeId", sourceNodeId);
        result.put("destinationNodeId", destinationNodeId);
        result.put("source", source);
        result.put("destination", destination);
        return result;
    }

    /** Builds and signs a ticket without executing it. Useful for explicit two-phase control. */
    public Prepared prepare(String sourceNodeId, String sourceRootId, String sourcePath,
                            String destinationNodeId, String destinationRootId, String destinationPath,
                            String operation, boolean overwrite, String sourceApprovalId,
                            String destinationApprovalId, long ttlSeconds) throws Exception {
        requireDistinctEndpoints(sourceNodeId, destinationNodeId);
        String normalizedOperation = TransferTicketService.normalizeOperation(operation);
        Map<String, Object> plan = plan(sourceNodeId, sourceRootId, sourcePath,
                destinationNodeId, destinationRootId, destinationPath);
        @SuppressWarnings("unchecked") Map<String, Object> source = (Map<String, Object>) plan.get("source");
        long size = number(source.get("size"));
        String sha256 = TransferTicketService.text(source, "sha256");
        String version = TransferTicketService.text(source, "version");
        String ticketId = UUID.randomUUID().toString();
        String requestId = UUID.randomUUID().toString();
        String transferId = UUID.randomUUID().toString();
        Map<String, Object> ticket = TransferTicketService.build(ticketId, requestId, transferId,
                config.nodeId(), sourceNodeId, destinationNodeId,
                sourceRootId, sourcePath, destinationRootId, destinationPath,
                normalizedOperation, overwrite, size, sha256, version,
                sourceApprovalId, destinationApprovalId, ttlSeconds);
        String signature = tickets.sign(ticket);
        Map<String, String> row = new LinkedHashMap<>();
        row.put("requestId", requestId);
        row.put("ticketId", ticketId);
        row.put("transferId", transferId);
        row.put("sourceNodeId", sourceNodeId);
        row.put("destinationNodeId", destinationNodeId);
        row.put("operation", normalizedOperation);
        row.put("overwrite", Boolean.toString(overwrite));
        row.put("state", "PREPARED");
        row.put("ticket", Json.stringify(ticket));
        row.put("ticketSignature", signature);
        row.put("createdAt", Instant.now().toString());
        row.put("updatedAt", row.get("createdAt"));
        state.putRecord(REQUEST_PREFIX, requestId, row);
        return new Prepared(requestId, ticketId, transferId, ticket, signature);
    }

    /** Prepares and immediately executes a coordinated transfer, returning the source's metadata-only result. */
    public Map<String, Object> coordinate(String sourceNodeId, String sourceRootId, String sourcePath,
                                          String destinationNodeId, String destinationRootId,
                                          String destinationPath, String operation, boolean overwrite,
                                          String sourceApprovalId, String destinationApprovalId,
                                          long ttlSeconds) throws Exception {
        Prepared prepared = prepare(sourceNodeId, sourceRootId, sourcePath,
                destinationNodeId, destinationRootId, destinationPath, operation, overwrite,
                sourceApprovalId, destinationApprovalId, ttlSeconds);
        return execute(prepared);
    }

    /** Re-invokes a durable coordination request. Terminal results are returned unchanged. */
    public Map<String, Object> retry(String requestId) throws Exception {
        Map<String, String> row = state.getRecord(REQUEST_PREFIX, canonicalUuid(requestId, "Request ID"));
        if (row == null) throw new IllegalArgumentException("Coordinated transfer request was not found.");
        Map<String, Object> result = parseResult(row.get("result"));
        if (isTerminal(String.valueOf(row.get("state"))) && result != null) return result;
        Map<String, Object> ticket = Json.object(row.get("ticket"));
        Prepared prepared = new Prepared(row.get("requestId"), row.get("ticketId"), row.get("transferId"),
                ticket, row.get("ticketSignature"));
        return execute(prepared);
    }

    public Map<String, Object> status(String requestId) throws Exception {
        Map<String, String> row = state.getRecord(REQUEST_PREFIX, canonicalUuid(requestId, "Request ID"));
        if (row == null) throw new IllegalArgumentException("Coordinated transfer request was not found.");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requestId", row.get("requestId"));
        result.put("ticketId", row.get("ticketId"));
        result.put("transferId", row.get("transferId"));
        result.put("sourceNodeId", row.get("sourceNodeId"));
        result.put("destinationNodeId", row.get("destinationNodeId"));
        result.put("operation", row.get("operation"));
        result.put("overwrite", Boolean.parseBoolean(row.get("overwrite")));
        result.put("state", row.get("state"));
        result.put("createdAt", row.get("createdAt"));
        result.put("updatedAt", row.get("updatedAt"));
        if (row.get("error") != null && !row.get("error").isBlank()) result.put("error", row.get("error"));
        Map<String, Object> stored = parseResult(row.get("result"));
        if (stored != null) result.put("result", stored);
        try {
            String sourceUrl = membership.activeMemberEndpoint(row.get("sourceNodeId"));
            result.put("sourceStatus", client.coordinatedStatus(sourceUrl, row.get("requestId"), membership));
        } catch (Exception unavailable) {
            result.put("sourceStatusUnavailable", safeMessage(unavailable));
        }
        return result;
    }

    public List<Map<String, Object>> list() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : state.records(REQUEST_PREFIX)) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("requestId", row.get("requestId"));
            item.put("ticketId", row.get("ticketId"));
            item.put("transferId", row.get("transferId"));
            item.put("sourceNodeId", row.get("sourceNodeId"));
            item.put("destinationNodeId", row.get("destinationNodeId"));
            item.put("operation", row.get("operation"));
            item.put("state", row.get("state"));
            item.put("createdAt", row.get("createdAt"));
            item.put("updatedAt", row.get("updatedAt"));
            result.add(item);
        }
        result.sort((left, right) -> String.valueOf(right.get("createdAt"))
                .compareTo(String.valueOf(left.get("createdAt"))));
        return List.copyOf(result);
    }

    /**
     * Source-side execution. The authenticated requester must be the ticket
     * issuer. The source authorizes its own resource, creates the destination
     * session, streams chunks directly to the destination, revalidates the
     * source and only then deletes it for a MOVE.
     */
    public Map<String, Object> executeSource(Map<String, Object> ticket, String signature,
                                             String requesterId) throws Exception {
        tickets.verify(ticket, signature);
        String issuer = TransferTicketService.text(ticket, "issuerNodeId");
        if (!issuer.equals(requesterId)) {
            throw new SecurityException("The coordinated ticket was issued by a different network member.");
        }
        String sourceNodeId = TransferTicketService.text(ticket, "sourceNodeId");
        if (!sourceNodeId.equals(config.nodeId())) {
            throw new SecurityException("The coordinated ticket is not bound to this source device.");
        }
        String destinationNodeId = TransferTicketService.text(ticket, "destinationNodeId");
        if (!membership.isActiveMember(destinationNodeId)) {
            throw new SecurityException("The coordinated destination is not an active network member.");
        }
        String ticketId = TransferTicketService.text(ticket, "ticketId");
        String requestId = TransferTicketService.text(ticket, "requestId");
        String transferId = TransferTicketService.text(ticket, "transferId");
        String operation = TransferTicketService.operation(ticket);
        tickets.claim(ticket, "SOURCE", transferId, requestId);

        Map<String, String> existingJob = state.getRecord(JOB_PREFIX, requestId);
        if (existingJob != null) {
            if (!ticketId.equals(existingJob.get("ticketId"))
                    || !transferId.equals(existingJob.get("transferId"))
                    || !issuer.equals(existingJob.get("issuerNodeId"))) {
                throw new SecurityException("The coordinated request identity is already bound to a different ticket.");
            }
            String existingState = existingJob.getOrDefault("state", "");
            if (existingState.equals("COPIED") || existingState.equals("MOVED")) {
                return resultFromJob(existingJob);
            }
            if (operation.equals("MOVE")
                    && (existingState.equals("DELETING") || existingState.equals("COPIED_NOT_MOVED"))) {
                return finishSourceDeletion(ticket, existingJob);
            }
        }

        String sourceRootId = TransferTicketService.text(ticket, "sourceRootId");
        String sourcePath = TransferTicketService.text(ticket, "sourcePath");
        long size = TransferTicketService.number(ticket, "size");
        String sha256 = TransferTicketService.text(ticket, "sha256");
        String version = TransferTicketService.text(ticket, "version");
        String sourceApprovalId = optional(ticket.get("sourceApprovalId"));
        EligibleStorageService.CoordinatedSource authorized;
        try {
            authorized = filesystem.authorizeCoordinatedSource(issuer, sourceRootId, sourcePath, operation,
                    sourceApprovalId, ticketId, size, sha256, version);
        } catch (Exception failure) {
            persistJob(requestId, ticket, issuer, "FAILED", null, safeMessage(failure));
            throw failure;
        }
        persistJob(requestId, ticket, issuer, "TRANSFERRING", null, "");
        String destinationUrl = membership.activeMemberEndpoint(destinationNodeId);
        try {
            client.createCoordinatedTransfer(destinationUrl, transferId, ticket, signature, membership);
            Map<String, Object> receipt = client.resumeManagedFile(destinationUrl, transferId,
                    authorized.path(), membership, config.maxFileBytes());
            filesystem.verifyCoordinatedSourceUnchanged(issuer, sourceRootId, sourcePath, operation,
                    ticketId, size, sha256, version);
            if (operation.equals("COPY")) {
                Map<String, Object> result = result(ticket, "COPIED", receipt, true, false, "");
                persistJob(requestId, ticket, issuer, "COPIED", result, "");
                return result;
            }
            // Persist the deletion intent with the verified receipt before touching
            // the source. A crash after deletion can then be reconciled idempotently.
            Map<String, Object> pending = result(ticket, "DELETING", receipt, true, false, "");
            persistJob(requestId, ticket, issuer, "DELETING", pending, "");
            return finishSourceDeletion(ticket, state.getRecord(JOB_PREFIX, requestId));
        } catch (Exception failure) {
            persistJob(requestId, ticket, issuer, "RETRYABLE", null, safeMessage(failure));
            throw failure;
        }
    }

    /** Metadata-only source job status for the coordinator. */
    public Map<String, Object> sourceStatus(String requesterId, String requestId) throws Exception {
        Map<String, String> job = state.getRecord(JOB_PREFIX, canonicalUuid(requestId, "Request ID"));
        if (job == null) throw new IllegalArgumentException("Coordinated source job was not found.");
        if (!requesterId.equals(job.get("issuerNodeId"))) {
            throw new SecurityException("The coordinated job belongs to a different coordinating member.");
        }
        Map<String, Object> result = resultFromJob(job);
        if (!isTerminal(job.getOrDefault("state", ""))) {
            try {
                String destinationUrl = membership.activeMemberEndpoint(job.get("destinationNodeId"));
                result.put("destinationProgress", client.transferStatus(destinationUrl,
                        job.get("transferId"), membership));
            } catch (Exception unavailable) {
                result.put("destinationProgressUnavailable", safeMessage(unavailable));
            }
        }
        return result;
    }

    private Map<String, Object> finishSourceDeletion(Map<String, Object> ticket, Map<String, String> job)
            throws Exception {
        String issuer = TransferTicketService.text(ticket, "issuerNodeId");
        String ticketId = TransferTicketService.text(ticket, "ticketId");
        String sourceRootId = TransferTicketService.text(ticket, "sourceRootId");
        String sourcePath = TransferTicketService.text(ticket, "sourcePath");
        long size = TransferTicketService.number(ticket, "size");
        String sha256 = TransferTicketService.text(ticket, "sha256");
        String version = TransferTicketService.text(ticket, "version");
        Map<String, Object> receipt = parseResult(job.get("result"));
        Map<String, Object> committed = receipt == null ? Map.of() : receipt;
        Object nestedReceipt = committed.get("receipt");
        if (nestedReceipt instanceof Map<?, ?> map) {
            @SuppressWarnings("unchecked") Map<String, Object> copy = (Map<String, Object>) map;
            committed = copy;
        }
        try {
            filesystem.deleteCoordinatedSource(issuer, sourceRootId, sourcePath, ticketId, size, sha256, version);
            Map<String, Object> result = result(ticket, "MOVED", committed, false, true, "");
            persistJob(job.get("requestId"), ticket, issuer, "MOVED", result, "");
            return result;
        } catch (Exception failure) {
            Map<String, Object> result = result(ticket, "COPIED_NOT_MOVED", committed, true, false,
                    safeMessage(failure));
            persistJob(job.get("requestId"), ticket, issuer, "COPIED_NOT_MOVED", result, safeMessage(failure));
            return result;
        }
    }

    private Map<String, Object> execute(Prepared prepared) throws Exception {
        Map<String, String> row = state.getRecord(REQUEST_PREFIX, prepared.requestId());
        if (row == null) throw new IllegalStateException("The prepared coordination request disappeared.");
        String sourceUrl = membership.activeMemberEndpoint(row.get("sourceNodeId"));
        try {
            Map<String, Object> result = client.executeCoordinatedTransfer(sourceUrl,
                    prepared.ticket(), prepared.signature(), membership);
            String stateValue = String.valueOf(result.getOrDefault("state", "RETRYABLE"));
            Map<String, String> update = new LinkedHashMap<>(row);
            update.put("state", stateValue);
            update.put("result", Json.stringify(result));
            update.put("error", String.valueOf(result.getOrDefault("error", "")));
            update.put("updatedAt", Instant.now().toString());
            state.putRecord(REQUEST_PREFIX, prepared.requestId(), update);
            return result;
        } catch (Exception failure) {
            Map<String, String> update = new LinkedHashMap<>(row);
            update.put("state", "RETRYABLE");
            update.put("error", safeMessage(failure));
            update.put("updatedAt", Instant.now().toString());
            state.putRecord(REQUEST_PREFIX, prepared.requestId(), update);
            throw failure;
        }
    }

    private void persistJob(String requestId, Map<String, Object> ticket, String issuer, String stateValue,
                            Map<String, Object> result, String error) throws Exception {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("requestId", requestId);
        row.put("ticketId", TransferTicketService.text(ticket, "ticketId"));
        row.put("transferId", TransferTicketService.text(ticket, "transferId"));
        row.put("issuerNodeId", issuer);
        row.put("sourceNodeId", TransferTicketService.text(ticket, "sourceNodeId"));
        row.put("destinationNodeId", TransferTicketService.text(ticket, "destinationNodeId"));
        row.put("operation", TransferTicketService.operation(ticket));
        row.put("state", stateValue);
        if (result != null) row.put("result", Json.stringify(result));
        row.put("error", error == null ? "" : error);
        Map<String, String> existing = state.getRecord(JOB_PREFIX, requestId);
        row.put("createdAt", existing == null ? Instant.now().toString() : existing.get("createdAt"));
        row.put("updatedAt", Instant.now().toString());
        state.putRecord(JOB_PREFIX, requestId, row);
    }

    private static Map<String, Object> resultFromJob(Map<String, String> job) {
        Map<String, Object> stored = parseResult(job.get("result"));
        if (stored != null) return stored;
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requestId", job.get("requestId"));
        result.put("ticketId", job.get("ticketId"));
        result.put("transferId", job.get("transferId"));
        result.put("operation", job.get("operation"));
        result.put("state", job.get("state"));
        if (job.get("error") != null && !job.get("error").isBlank()) result.put("error", job.get("error"));
        return result;
    }

    private static Map<String, Object> result(Map<String, Object> ticket, String stateValue,
                                              Map<String, Object> receipt, boolean sourceRetained,
                                              boolean sourceDeleted, String error) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requestId", TransferTicketService.text(ticket, "requestId"));
        result.put("ticketId", TransferTicketService.text(ticket, "ticketId"));
        result.put("transferId", TransferTicketService.text(ticket, "transferId"));
        result.put("operation", TransferTicketService.operation(ticket));
        result.put("state", stateValue);
        result.put("sourceRetained", sourceRetained);
        result.put("sourceDeleted", sourceDeleted);
        result.put("receipt", receipt);
        if (error != null && !error.isBlank()) result.put("error", error);
        return result;
    }

    private void requireDistinctEndpoints(String sourceNodeId, String destinationNodeId) {
        String source = requireText(sourceNodeId, "Source node ID");
        String destination = requireText(destinationNodeId, "Destination node ID");
        if (source.equals(destination)) throw new IllegalArgumentException("Source and destination devices must differ.");
        if (!membership.isActiveMember(source)) throw new SecurityException("The source device is not an active network member.");
        if (!membership.isActiveMember(destination)) throw new SecurityException("The destination device is not an active network member.");
    }

    private static boolean isTerminal(String value) {
        return value.equals("COPIED") || value.equals("MOVED") || value.equals("COPIED_NOT_MOVED");
    }

    private static Map<String, Object> parseResult(String json) {
        if (json == null || json.isBlank()) return null;
        try { return Json.object(json); }
        catch (RuntimeException invalid) { return null; }
    }

    private static String optional(Object value) {
        return value instanceof String text ? text : "";
    }

    private static long number(Object value) {
        if (!(value instanceof Number number)) throw new IllegalArgumentException("Source metadata did not report a numeric size.");
        return number.longValue();
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

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required.");
        return value;
    }

    private static String safeMessage(Throwable failure) {
        String message = failure.getMessage();
        return message == null || message.isBlank() ? failure.getClass().getSimpleName() : message;
    }

    public record Prepared(String requestId, String ticketId, String transferId,
                           Map<String, Object> ticket, String signature) { }
}
