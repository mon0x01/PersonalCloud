package dev.personalcloud.control;

import dev.personalcloud.net.Json;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Java client for PersonalCloud's owner-only Unix-domain control protocol. */
public final class LocalControlClient {
    private static final int MAX_RESPONSE_LINE = 1024 * 1024;
    private static final int MAX_READ_BYTES = 8 * 1024 * 1024;
    private static final int DOWNLOAD_CHUNK_BYTES = 4 * 1024 * 1024;

    private final Path socketPath;

    public LocalControlClient(Path socketPath) {
        if (socketPath == null) throw new IllegalArgumentException("A local control socket path is required.");
        this.socketPath = socketPath.toAbsolutePath().normalize();
    }

    public Path socketPath() { return socketPath; }

    public Map<String, Object> ping() throws IOException {
        return request("ping");
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listReferences() throws IOException {
        Object rows = request("references.list").get("references");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid references list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid reference entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> registerReference(String name, Path directory) throws IOException {
        Map<String, Object> fields = fields("name", requireText(name, "Reference name"),
                "path", directory.toAbsolutePath().normalize().toString());
        return request("references.register", fields);
    }

    public Map<String, Object> unregisterReference(String referenceId) throws IOException {
        return request("references.unregister", fields("referenceId", requireText(referenceId, "Reference ID")));
    }

    public Map<String, Object> locateReferenceFile(Path file) throws IOException {
        Map<String, Object> response = request("references.locate", fields(
                "path", file.toAbsolutePath().normalize().toString()));
        Object located = response.get("file");
        if (!(located instanceof Map<?, ?> map)) throw new IOException("The control server returned invalid reference-file metadata.");
        @SuppressWarnings("unchecked") Map<String, Object> result = (Map<String, Object>) map;
        return result;
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listEntries(String referenceId, String relativeDirectory) throws IOException {
        Map<String, Object> response = request("storage.list", fields(
                "referenceId", requireText(referenceId, "Reference ID"),
                "path", relativeDirectory == null ? "" : relativeDirectory));
        Object rows = response.get("entries");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid directory listing.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid directory entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> search(String query, int limit) throws IOException {
        Map<String, Object> response = request("storage.search", fields("query", requireText(query, "Search query"), "limit", limit));
        Object rows = response.get("results");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid search result.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid search entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> stat(String referenceId, String relativePath) throws IOException {
        return request("storage.stat", fields("referenceId", requireText(referenceId, "Reference ID"),
                "path", requireText(relativePath, "Relative file path")));
    }

    public Map<String, Object> networkStatus() throws IOException { return request("network.status"); }

    public Map<String, Object> networkBootstrap(String networkName, String accountName, char[] password) throws IOException {
        return request("network.bootstrap", fields("networkName", requireText(networkName, "Network name"),
                "accountName", requireText(accountName, "Account name"), "password", new String(password)));
    }

    public Map<String, Object> networkJoin(String baseUrl, String accountName, char[] password) throws IOException {
        return networkJoin(baseUrl, accountName, password, false);
    }

    public Map<String, Object> networkJoin(String baseUrl, String accountName, char[] password,
                                           boolean filesystemConsent) throws IOException {
        return request("network.join", fields("baseUrl", requireText(baseUrl, "Network peer URL"),
                "accountName", accountName == null ? "" : accountName, "password", new String(password),
                "filesystemConsent", Boolean.toString(filesystemConsent)));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> networkRequests() throws IOException {
        Object rows = request("network.requests").get("requests");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid enrollment request list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    public Map<String, Object> networkApprove(String requestId) throws IOException {
        return request("network.approve", fields("requestId", requireText(requestId, "Enrollment request ID")));
    }

    public Map<String, Object> networkReject(String requestId, String reason) throws IOException {
        return request("network.reject", fields("requestId", requireText(requestId, "Enrollment request ID"),
                "reason", reason == null ? "" : reason));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> networkMembers() throws IOException {
        Object rows = request("network.members").get("members");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid network member list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listReferenceGrants() throws IOException {
        Object rows = request("reference-grants.list").get("grants");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid reference-grant list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    public Map<String, Object> createReferenceGrant(String memberId, String referenceId, String path, String permission) throws IOException {
        return request("reference-grants.create", fields("memberId", requireText(memberId, "Member ID"),
                "referenceId", requireText(referenceId, "Reference ID"), "path", path == null ? "" : path,
                "permission", requireText(permission, "Permission")));
    }

    public Map<String, Object> revokeReferenceGrant(String grantId) throws IOException {
        return request("reference-grants.revoke", fields("grantId", requireText(grantId, "Reference grant ID")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listReferenceSnapshots() throws IOException {
        Object rows = request("reference-snapshots.list").get("snapshots");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid reference-snapshot list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    public Map<String, Object> restoreReferenceSnapshot(String snapshotId) throws IOException {
        return request("reference-snapshots.restore", fields("snapshotId", requireText(snapshotId, "Snapshot ID")));
    }

    public Map<String, Object> networkSetEndpoint(String nodeId, String endpoint) throws IOException {
        return request("network.set-endpoint", fields(
                "nodeId", requireText(nodeId, "Network member node ID"),
                "endpoint", requireText(endpoint, "HTTPS endpoint")));
    }

    public Map<String, Object> networkSync() throws IOException { return request("network.sync"); }

    public List<Map<String, Object>> networkSearch(String query, int limit) throws IOException {
        return networkSearchWithStatus(query, limit).results();
    }

    /** Includes which members could not be searched, allowing callers to label cached metadata as stale. */
    @SuppressWarnings("unchecked")
    public NetworkSearchResult networkSearchWithStatus(String query, int limit) throws IOException {
        int boundedLimit = Math.max(1, Math.min(100, limit));
        Map<String, Object> response = request("network.search", fields(
                "query", requireText(query, "Search query"), "limit", boundedLimit));
        Object rows = response.get("results");
        Object unavailableRows = response.get("unavailableDevices");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid network search result.");
        if (!(unavailableRows instanceof List<?> unavailable)) throw new IOException("The control server returned invalid network search availability metadata.");
        List<Map<String, Object>> results = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid network search entry.");
            results.add((Map<String, Object>) map);
        }
        List<Map<String, Object>> unavailableDevices = new ArrayList<>();
        for (Object item : unavailable) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned invalid unavailable-device metadata.");
            unavailableDevices.add((Map<String, Object>) map);
        }
        return new NetworkSearchResult(List.copyOf(results), List.copyOf(unavailableDevices));
    }

    public record NetworkSearchResult(List<Map<String, Object>> results,
                                      List<Map<String, Object>> unavailableDevices) { }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listRemoteNetworkReferences(String memberId) throws IOException {
        Object rows = request("remote.references.list", fields("memberId", requireText(memberId, "Member ID"))).get("references");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid remote reference list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> browseRemoteNetworkReference(String memberId, String grantId, String path) throws IOException {
        Object rows = request("remote.reference.browse", fields("memberId", requireText(memberId, "Member ID"),
                "grantId", requireText(grantId, "Reference grant ID"), "path", path == null ? "" : path)).get("entries");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid remote directory listing.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    public Map<String, Object> statRemoteNetworkReference(String memberId, String grantId, String path) throws IOException {
        return request("remote.reference.stat", fields("memberId", requireText(memberId, "Member ID"),
                "grantId", requireText(grantId, "Reference grant ID"), "path", path == null ? "" : path));
    }

    public DownloadResult downloadRemoteNetworkReference(String memberId, String grantId, String path, Path destination) throws IOException {
        Map<String, Object> response = request("remote.reference.download", fields("memberId", requireText(memberId, "Member ID"),
                "grantId", requireText(grantId, "Reference grant ID"), "path", path == null ? "" : path,
                "destination", destination.toAbsolutePath().normalize().toString()));
        return new DownloadResult(Path.of(string(response, "path")), number(response, "size"), string(response, "sha256"));
    }

    public Map<String, Object> deleteRemoteNetworkReference(String memberId, String grantId, String path) throws IOException {
        return request("remote.reference.delete", fields("memberId", requireText(memberId, "Member ID"),
                "grantId", requireText(grantId, "Reference grant ID"), "path", path == null ? "" : path));
    }

    public Map<String, Object> placeManagedFile(String memberId, Path source, String destinationRelativePath) throws IOException {
        return request("managed.place", fields("memberId", requireText(memberId, "Destination member ID"),
                "sourcePath", source.toAbsolutePath().normalize().toString(),
                "destinationPath", requireText(destinationRelativePath, "Managed destination path")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listOutboundTransfers() throws IOException {
        Object rows = request("managed.transfers.list").get("transfers");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid outbound transfer list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    public Map<String, Object> outboundTransferStatus(String jobId) throws IOException {
        return request("managed.transfers.status", fields("jobId", requireText(jobId, "Transfer job ID")));
    }

    public Map<String, Object> resumeOutboundTransfer(String jobId) throws IOException {
        return request("managed.transfers.resume", fields("jobId", requireText(jobId, "Transfer job ID")));
    }

    public Map<String, Object> abortOutboundTransfer(String jobId) throws IOException {
        return request("managed.transfers.abort", fields("jobId", requireText(jobId, "Transfer job ID")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listLocalManagedFiles() throws IOException {
        Object rows = request("managed.local.list").get("files");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid local managed-file list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listRemoteManagedFiles(String memberId) throws IOException {
        Object rows = request("managed.remote.list", fields("memberId", requireText(memberId, "Member ID"))).get("files");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid remote managed-file list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    public DownloadResult downloadRemoteManagedFile(String memberId, String fileId, Path destination) throws IOException {
        Map<String, Object> response = request("managed.remote.download", fields("memberId", requireText(memberId, "Member ID"),
                "fileId", requireText(fileId, "Managed file ID"), "destination", destination.toAbsolutePath().normalize().toString()));
        return new DownloadResult(Path.of(string(response, "path")), number(response, "size"), string(response, "sha256"));
    }

    public Map<String, Object> deleteRemoteManagedFile(String memberId, String fileId) throws IOException {
        return request("managed.remote.delete", fields("memberId", requireText(memberId, "Member ID"),
                "fileId", requireText(fileId, "Managed file ID")));
    }

    public Map<String, Object> networkRevoke(String nodeId) throws IOException {
        return request("network.revoke", fields("nodeId", requireText(nodeId, "Node ID")));
    }

    public Map<String, Object> createInvitation() throws IOException {
        return request("invites.create");
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listPeers() throws IOException {
        Object rows = request("peers.list").get("peers");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid peer list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid peer entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> addPeer(String baseUrl, String invitationCode) throws IOException {
        return request("peers.add", fields("baseUrl", requireText(baseUrl, "Peer URL"),
                "code", requireText(invitationCode, "Invitation code")));
    }

    public Map<String, Object> removePeer(String peerId, String direction) throws IOException {
        return request("peers.remove", fields("peerId", requireText(peerId, "Peer ID"),
                "direction", requireText(direction, "Peer direction")));
    }

    public Map<String, Object> createGrant(String peerId, String relativePath, String permission) throws IOException {
        return request("grants.create", fields("peerId", requireText(peerId, "Peer ID"),
                "path", requireText(relativePath, "Storage path"), "permission", requireText(permission, "Permission")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listGrants() throws IOException {
        Object rows = request("grants.list").get("grants");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid grant list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid grant entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> revokeGrant(String grantId) throws IOException {
        return request("grants.revoke", fields("grantId", requireText(grantId, "Grant ID")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listPolicies() throws IOException {
        Object rows = request("policy.list").get("rules");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid policy list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid policy entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> setPolicy(String rootId, String path, String mode) throws IOException {
        return request("policy.set", fields("rootId", requireText(rootId, "Eligible root ID"),
                "path", path == null ? "" : path, "mode", requireText(mode, "Policy mode")));
    }

    public Map<String, Object> removePolicy(String rootId, String path) throws IOException {
        return request("policy.remove", fields("rootId", requireText(rootId, "Eligible root ID"),
                "path", path == null ? "" : path));
    }

    public Map<String, Object> policyEpoch() throws IOException { return request("policy.epoch"); }

    public Map<String, Object> requestProtectionApproval(String memberId, String rootId, String path,
                                                          String operation, long ttlSeconds) throws IOException {
        return request("policy.approvals.request", fields("memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"), "path", path == null ? "" : path,
                "operation", requireText(operation, "Policy operation"), "ttlSeconds", ttlSeconds));
    }

    public Map<String, Object> approveProtection(String approvalId) throws IOException {
        return request("policy.approvals.approve", fields("approvalId", requireText(approvalId, "Approval ID")));
    }

    public Map<String, Object> denyProtection(String approvalId) throws IOException {
        return request("policy.approvals.deny", fields("approvalId", requireText(approvalId, "Approval ID")));
    }

    public Map<String, Object> protectionStatus(String approvalId) throws IOException {
        return request("policy.approvals.status", fields("approvalId", requireText(approvalId, "Approval ID")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listProtectionApprovals() throws IOException {
        Object rows = request("policy.approvals.list").get("approvals");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid approval list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid approval entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> filesystemStatus() throws IOException { return request("filesystem.status"); }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> filesystemRoots() throws IOException {
        Object rows = request("filesystem.roots").get("roots");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid eligible-root list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid eligible-root entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> grantFilesystemConsent() throws IOException { return request("filesystem.consent"); }

    public Map<String, Object> revokeFilesystemConsent() throws IOException { return request("filesystem.revoke-consent"); }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listFilesystemBudgets() throws IOException {
        Object rows = request("filesystem.budgets").get("budgets");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid filesystem budget list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid filesystem budget entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> filesystemBudget(String memberId) throws IOException {
        return asMap(request("filesystem.budget",
                fields("memberId", requireText(memberId, "Member ID"))).get("budget"));
    }

    public Map<String, Object> setFilesystemBudget(String memberId, long writeBytesPerDay,
                                                   long deleteEntriesPerDay) throws IOException {
        if (writeBytesPerDay < 0 || deleteEntriesPerDay < 0) {
            throw new IllegalArgumentException("Filesystem budget limits cannot be negative.");
        }
        return asMap(request("filesystem.budget-set", fields(
                "memberId", requireText(memberId, "Member ID"),
                "writeBytesPerDay", writeBytesPerDay,
                "deleteEntriesPerDay", deleteEntriesPerDay)).get("budget"));
    }

    public Map<String, Object> clearFilesystemBudget(String memberId) throws IOException {
        return asMap(request("filesystem.budget-clear",
                fields("memberId", requireText(memberId, "Member ID"))).get("budget"));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listAuditEvents(int limit) throws IOException {
        Object rows = request("audit.list", fields("limit", Math.max(1, Math.min(limit, 200)))).get("events");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid audit event list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid audit event.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listRemoteShares(String peerId) throws IOException {
        Object rows = request("remote.shares.list", fields("peerId", requireText(peerId, "Peer ID"))).get("shares");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid remote share list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid remote share entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    public Map<String, Object> deleteRemoteShare(String peerId, String shareId) throws IOException {
        return request("remote.share.delete", fields("peerId", requireText(peerId, "Peer ID"),
                "shareId", requireText(shareId, "Share ID")));
    }

    public DownloadResult downloadRemoteShare(String peerId, String shareId, Path destination) throws IOException {
        Map<String, Object> response = request("remote.share.download", fields("peerId", requireText(peerId, "Peer ID"),
                "shareId", requireText(shareId, "Share ID"), "destination", destination.toAbsolutePath().normalize().toString()));
        return new DownloadResult(Path.of(string(response, "path")), number(response, "size"), string(response, "sha256"));
    }

    /** Reads at most 8 MiB from a referenced file. Empty reads at or past EOF are valid. */
    public byte[] readRange(String referenceId, String relativePath, long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        Map<String, Object> request = fields("command", "storage.read", "referenceId", requireText(referenceId, "Reference ID"),
                "path", requireText(relativePath, "Relative file path"), "offset", offset, "length", length);
        try (SocketChannel channel = connect()) {
            InputStream input = Channels.newInputStream(channel);
            OutputStream output = Channels.newOutputStream(channel);
            writeRequest(output, request);
            Map<String, Object> header = readResponse(input);
            long fileSize = number(header, "size");
            long responseOffset = number(header, "offset");
            long responseLength = number(header, "length");
            if (fileSize < 0 || responseOffset != offset || responseLength < 0 || responseLength > length || responseLength > MAX_READ_BYTES) {
                throw new IOException("The control server returned an invalid file range header.");
            }
            if (offset >= fileSize && responseLength != 0) throw new IOException("The control server returned bytes beyond end of file.");
            byte[] bytes = input.readNBytes(Math.toIntExact(responseLength));
            if (bytes.length != responseLength) throw new IOException("The control connection ended before the requested file range was received.");
            return bytes;
        }
    }

    /** Reads a bounded range from managed bytes physically owned by this node. */
    public byte[] readLocalManagedRange(String fileId, long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        Map<String, Object> request = fields("command", "managed.local.read", "fileId", requireText(fileId, "Managed file ID"),
                "offset", offset, "length", length);
        try (SocketChannel channel = connect()) {
            InputStream input = Channels.newInputStream(channel);
            OutputStream output = Channels.newOutputStream(channel);
            writeRequest(output, request);
            Map<String, Object> header = readResponse(input);
            long fileSize = number(header, "size");
            long responseOffset = number(header, "offset");
            long responseLength = number(header, "length");
            long expectedLength = offset >= fileSize ? 0 : Math.min((long) length, fileSize - offset);
            if (fileSize < 0 || responseOffset != offset || responseLength != expectedLength || responseLength < 0 || responseLength > MAX_READ_BYTES) {
                throw new IOException("The control server returned an invalid managed-file range header.");
            }
            byte[] bytes = input.readNBytes(Math.toIntExact(responseLength));
            if (bytes.length != responseLength) throw new IOException("The control connection ended before the managed-file range was received.");
            return bytes;
        }
    }

    /** Reads a bounded range from another network member through the owner-only local control socket. */
    public byte[] readRemoteRange(String memberId, String storageKind, String grantOrFileId,
                                  String relativePath, long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        String kind = requireText(storageKind, "Remote storage kind").toUpperCase(java.util.Locale.ROOT);
        Map<String, Object> request = fields("command", "storage.remote.read",
                "memberId", requireText(memberId, "Member ID"), "storageKind", kind,
                "offset", offset, "length", length);
        if ("REFERENCE".equals(kind)) {
            request.put("grantId", requireText(grantOrFileId, "Reference grant ID"));
            request.put("path", relativePath == null ? "" : relativePath);
        } else if ("MANAGED".equals(kind)) {
            request.put("fileId", requireText(grantOrFileId, "Managed file ID"));
        } else throw new IllegalArgumentException("Remote storage kind must be REFERENCE or MANAGED.");
        try (SocketChannel channel = connect()) {
            InputStream input = Channels.newInputStream(channel);
            OutputStream output = Channels.newOutputStream(channel);
            writeRequest(output, request);
            Map<String, Object> header = readResponse(input);
            long fileSize = number(header, "size");
            long responseOffset = number(header, "offset");
            long responseLength = number(header, "length");
            long expectedLength = offset >= fileSize ? 0 : Math.min((long) length, fileSize - offset);
            if (fileSize < 0 || responseOffset != offset || responseLength != expectedLength
                    || responseLength < 0 || responseLength > MAX_READ_BYTES) {
                throw new IOException("The control server returned an invalid remote file range header.");
            }
            byte[] bytes = input.readNBytes(Math.toIntExact(responseLength));
            if (bytes.length != responseLength) throw new IOException("The control connection ended before the remote file range was received.");
            return bytes;
        }
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listRemoteFilesystemRoots(String memberId) throws IOException {
        Object rows = request("filesystem.remote.roots",
                fields("memberId", requireText(memberId, "Member ID"))).get("roots");
        return rows(rows, "remote eligible-root list");
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> browseRemoteFilesystem(String memberId, String rootId, String relativePath)
            throws IOException {
        Object rows = request("filesystem.remote.browse", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", relativePath == null ? "" : relativePath)).get("entries");
        return rows(rows, "remote eligible-storage directory");
    }

    public Map<String, Object> statRemoteFilesystem(String memberId, String rootId, String relativePath)
            throws IOException {
        return request("filesystem.remote.stat", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", relativePath == null ? "" : relativePath));
    }

    /** Reads a bounded range from a remote eligible-storage file through the owner-only control socket. */
    public byte[] readRemoteFilesystemRange(String memberId, String rootId, String relativePath,
                                            long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) {
            throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        }
        Map<String, Object> request = fields("command", "filesystem.remote.read",
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", relativePath == null ? "" : relativePath,
                "offset", offset, "length", length);
        try (SocketChannel channel = connect()) {
            InputStream input = Channels.newInputStream(channel);
            OutputStream output = Channels.newOutputStream(channel);
            writeRequest(output, request);
            Map<String, Object> header = readResponse(input);
            long fileSize = number(header, "size");
            long responseOffset = number(header, "offset");
            long responseLength = number(header, "length");
            long expectedLength = offset >= fileSize ? 0 : Math.min((long) length, fileSize - offset);
            if (fileSize < 0 || responseOffset != offset || responseLength != expectedLength
                    || responseLength < 0 || responseLength > MAX_READ_BYTES) {
                throw new IOException("The control server returned an invalid remote filesystem range header.");
            }
            byte[] bytes = input.readNBytes(Math.toIntExact(responseLength));
            if (bytes.length != responseLength) {
                throw new IOException("The control connection ended before the remote filesystem range was received.");
            }
            return bytes;
        }
    }

    /** Downloads a remote eligible-storage file atomically into a new local destination. */
    public Map<String, Object> downloadRemoteFilesystemFile(String memberId, String rootId, String relativePath,
                                                             Path destination) throws IOException {
        return request("filesystem.remote.download", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", relativePath == null ? "" : relativePath,
                "destination", requireText(destination.toAbsolutePath().normalize().toString(), "Destination")));
    }

    /** Uploads a completed local staging file; the remote owner performs final authorization. */
    public Map<String, Object> uploadRemoteFilesystemFile(String memberId, String rootId, String relativePath,
                                                           Path source, boolean overwrite, String approvalId)
            throws IOException {
        return request("filesystem.remote.write", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", relativePath == null ? "" : relativePath,
                "source", requireText(source.toAbsolutePath().normalize().toString(), "Staging source"),
                "overwrite", overwrite,
                "approvalId", approvalId == null ? "" : approvalId));
    }

    public Map<String, Object> createRemoteFilesystemDirectory(String memberId, String rootId, String relativePath)
            throws IOException {
        return request("filesystem.remote.mkdir", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", requireText(relativePath, "Directory path")));
    }

    public Map<String, Object> moveRemoteFilesystemEntry(String memberId, String rootId, String from, String to,
                                                          boolean overwrite, String approvalId,
                                                          String destinationApprovalId) throws IOException {
        return request("filesystem.remote.move", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "from", requireText(from, "Source path"),
                "to", requireText(to, "Destination path"),
                "overwrite", overwrite,
                "approvalId", approvalId == null ? "" : approvalId,
                "destinationApprovalId", destinationApprovalId == null ? "" : destinationApprovalId));
    }

    public Map<String, Object> deleteRemoteFilesystemEntry(String memberId, String rootId, String relativePath,
                                                            boolean recursive, String approvalId) throws IOException {
        return request("filesystem.remote.delete", fields(
                "memberId", requireText(memberId, "Member ID"),
                "rootId", requireText(rootId, "Eligible root ID"),
                "path", relativePath == null ? "" : relativePath,
                "recursive", recursive,
                "approvalId", approvalId == null ? "" : approvalId));
    }

    public Map<String, Object> planCoordinatedTransfer(String sourceNodeId, String sourceRootId, String sourcePath,
                                                        String destinationNodeId, String destinationRootId,
                                                        String destinationPath) throws IOException {
        return request("coordinated.plan", fields(
                "sourceNodeId", requireText(sourceNodeId, "Source node ID"),
                "sourceRootId", requireText(sourceRootId, "Source root ID"),
                "sourcePath", sourcePath == null ? "" : sourcePath,
                "destinationNodeId", requireText(destinationNodeId, "Destination node ID"),
                "destinationRootId", requireText(destinationRootId, "Destination root ID"),
                "destinationPath", requireText(destinationPath, "Destination path")));
    }

    public Map<String, Object> prepareCoordinatedTransfer(String sourceNodeId, String sourceRootId,
                                                           String sourcePath, String destinationNodeId,
                                                           String destinationRootId, String destinationPath,
                                                           String operation, boolean overwrite,
                                                           String sourceApprovalId, String destinationApprovalId,
                                                           long ttlSeconds) throws IOException {
        return request("coordinated.prepare", fields(
                "sourceNodeId", requireText(sourceNodeId, "Source node ID"),
                "sourceRootId", requireText(sourceRootId, "Source root ID"),
                "sourcePath", sourcePath == null ? "" : sourcePath,
                "destinationNodeId", requireText(destinationNodeId, "Destination node ID"),
                "destinationRootId", requireText(destinationRootId, "Destination root ID"),
                "destinationPath", requireText(destinationPath, "Destination path"),
                "operation", requireText(operation, "Operation"),
                "overwrite", overwrite,
                "sourceApprovalId", sourceApprovalId == null ? "" : sourceApprovalId,
                "destinationApprovalId", destinationApprovalId == null ? "" : destinationApprovalId,
                "ttlSeconds", ttlSeconds));
    }

    public Map<String, Object> coordinateTransfer(String sourceNodeId, String sourceRootId, String sourcePath,
                                                   String destinationNodeId, String destinationRootId,
                                                   String destinationPath, String operation, boolean overwrite,
                                                   String sourceApprovalId, String destinationApprovalId,
                                                   long ttlSeconds) throws IOException {
        return request("coordinated.transfer", fields(
                "sourceNodeId", requireText(sourceNodeId, "Source node ID"),
                "sourceRootId", requireText(sourceRootId, "Source root ID"),
                "sourcePath", sourcePath == null ? "" : sourcePath,
                "destinationNodeId", requireText(destinationNodeId, "Destination node ID"),
                "destinationRootId", requireText(destinationRootId, "Destination root ID"),
                "destinationPath", requireText(destinationPath, "Destination path"),
                "operation", requireText(operation, "Operation"),
                "overwrite", overwrite,
                "sourceApprovalId", sourceApprovalId == null ? "" : sourceApprovalId,
                "destinationApprovalId", destinationApprovalId == null ? "" : destinationApprovalId,
                "ttlSeconds", ttlSeconds));
    }

    public Map<String, Object> coordinatedTransferStatus(String requestId) throws IOException {
        return request("coordinated.status", fields("requestId", requireText(requestId, "Request ID")));
    }

    public Map<String, Object> retryCoordinatedTransfer(String requestId) throws IOException {
        return request("coordinated.retry", fields("requestId", requireText(requestId, "Request ID")));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listCoordinatedTransfers() throws IOException {
        Object rows = request("coordinated.list").get("requests");
        if (!(rows instanceof List<?> list)) throw new IOException("The control server returned an invalid coordinated transfer list.");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) result.add((Map<String, Object>) map);
        return List.copyOf(result);
    }

    /** Downloads atomically to a new destination and verifies the source size/mtime did not change. */
    public DownloadResult download(String referenceId, String relativePath, Path destination) throws Exception {
        Path requested = destination.toAbsolutePath().normalize();
        Path requestedParent = requested.getParent();
        if (requestedParent == null || requested.getFileName() == null) throw new IllegalArgumentException("A destination file inside a parent directory is required.");
        Files.createDirectories(requestedParent);
        Path parent = requestedParent.toRealPath();
        Path target = parent.resolve(requested.getFileName().toString());
        if (Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Destination already exists; refusing to overwrite it.");

        Map<String, Object> before = stat(referenceId, relativePath);
        long expectedSize = number(before, "size");
        String expectedModified = string(before, "modified");
        Path temporary = parent.resolve("." + target.getFileName() + ".pc-part-" + UUID.randomUUID());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        boolean committed = false;
        try {
            try (OutputStream output = Files.newOutputStream(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                long offset = 0;
                while (offset < expectedSize) {
                    int length = (int) Math.min(DOWNLOAD_CHUNK_BYTES, expectedSize - offset);
                    byte[] chunk = readRange(referenceId, relativePath, offset, length);
                    if (chunk.length != length) throw new IOException("The source file changed or ended during download.");
                    output.write(chunk);
                    digest.update(chunk);
                    offset += chunk.length;
                }
            }
            Map<String, Object> after = stat(referenceId, relativePath);
            if (number(after, "size") != expectedSize || !expectedModified.equals(string(after, "modified"))) {
                throw new IOException("The source file changed during download; the partial result was discarded.");
            }
            if (Files.size(temporary) != expectedSize) throw new IOException("Downloaded file size verification failed.");
            // ATOMIC_MOVE may replace an existing target depending on the filesystem provider.
            Files.move(temporary, target);
            committed = true;
            return new DownloadResult(target, expectedSize, HexFormat.of().formatHex(digest.digest()));
        } finally {
            if (!committed) Files.deleteIfExists(temporary);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows(Object value, String label) throws IOException {
        if (!(value instanceof List<?> list)) throw new IOException("The control server returned an invalid " + label + ".");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IOException("The control server returned an invalid " + label + " entry.");
            result.add((Map<String, Object>) map);
        }
        return List.copyOf(result);
    }

    private Map<String, Object> request(String command) throws IOException { return request(command, Map.of()); }

    private Map<String, Object> request(String command, Map<String, ?> fields) throws IOException {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("command", command);
        request.putAll(fields);
        try (SocketChannel channel = connect()) {
            InputStream input = Channels.newInputStream(channel);
            OutputStream output = Channels.newOutputStream(channel);
            writeRequest(output, request);
            return readResponse(input);
        }
    }

    private SocketChannel connect() throws IOException {
        if (!Files.exists(socketPath)) throw new IOException("PersonalCloud local control socket not found: " + socketPath);
        SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX);
        try {
            channel.connect(UnixDomainSocketAddress.of(socketPath));
            return channel;
        } catch (IOException failure) {
            channel.close();
            throw new IOException("Cannot connect to PersonalCloud local control socket: " + socketPath, failure);
        }
    }

    private static void writeRequest(OutputStream output, Map<String, ?> request) throws IOException {
        output.write(Json.stringify(request).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.write('\n');
        output.flush();
    }

    private static Map<String, Object> readResponse(InputStream input) throws IOException {
        String line = readLine(input, MAX_RESPONSE_LINE);
        if (line == null || line.isBlank()) throw new IOException("The PersonalCloud control server closed without a response.");
        Map<String, Object> response;
        try { response = Json.object(line); }
        catch (RuntimeException invalid) { throw new IOException("The PersonalCloud control server returned invalid JSON.", invalid); }
        if (!Boolean.TRUE.equals(response.get("ok"))) {
            Object error = response.get("error");
            throw new IOException(error instanceof String text ? text : "The PersonalCloud control request failed: " + Json.stringify(response));
        }
        return response;
    }

    private static String readLine(InputStream input, int maximumBytes) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1) {
            if (value == '\n') break;
            if (value != '\r') bytes.write(value);
            if (bytes.size() > maximumBytes) throw new IOException("The PersonalCloud control response is too large.");
        }
        if (value == -1 && bytes.size() == 0) return null;
        return bytes.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static Map<String, Object> fields(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < pairs.length; index += 2) result.put((String) pairs[index], pairs[index + 1]);
        return result;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required.");
        return value;
    }

    private static long number(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof Number number)) throw new IOException("The control server omitted numeric field '" + key + "'.");
        return number.longValue();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) throws IOException {
        if (!(value instanceof Map<?, ?> map)) throw new IOException("The control server omitted an object field.");
        return (Map<String, Object>) map;
    }

    private static String string(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof String text)) throw new IOException("The control server omitted text field '" + key + "'.");
        return text;
    }

    public record DownloadResult(Path path, long sizeBytes, String sha256) { }
}
