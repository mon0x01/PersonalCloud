package dev.personalcloud.control;

import dev.personalcloud.net.Json;
import dev.personalcloud.net.RemotePeerClient;
import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.storage.ReferenceRoot;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.storage.StorageEntry;
import dev.personalcloud.core.SecretFiles;
import dev.personalcloud.network.NetworkMembershipService;
import dev.personalcloud.network.NetworkEnrollmentClient;
import dev.personalcloud.network.DeviceCatalogueService;
import dev.personalcloud.network.NetworkPeerClient;
import dev.personalcloud.network.OutboundTransferQueue;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceVersionService;
import dev.personalcloud.storage.ManagedStorageService;
import dev.personalcloud.network.NetworkPeerClient;
import dev.personalcloud.network.OutboundTransferQueue;
import dev.personalcloud.core.StateStore;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owner-only Unix-domain control socket for native OS adapters. Access is restricted by the
 * socket's 0600 permissions and the 0700 application data directory; it is never network-bound.
 * Protocol: one UTF-8 JSON request line, one UTF-8 JSON response line, and for storage.read only,
 * exactly response.length raw bytes following the response line.
 */
public final class LocalControlServer implements AutoCloseable {
    private static final int MAX_REQUEST_BYTES = 32 * 1024;
    private static final long MAX_READ_BYTES = 8L * 1024 * 1024;

    private final Path socketPath;
    private final String nodeId;
    private final String nodeName;
    private final ReferenceStorageService references;
    private final AppConfig config;
    private final PeerService peers;
    private final GrantService grants;
    private final NetworkMembershipService membership;
    private final DeviceCatalogueService catalogue;
    private final ReferenceGrantService referenceGrants;
    private final ReferenceVersionService referenceVersions;
    private final ManagedStorageService managedStorage;
    private final OutboundTransferQueue outboundTransfers;
    private final java.util.concurrent.ScheduledExecutorService transferRetryScheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread thread = new Thread(r, "personalcloud-transfer-retry");
                thread.setDaemon(true);
                return thread;
            });
    private final RemotePeerClient remote = new RemotePeerClient();
    private FileChannel lockChannel;
    private FileLock processLock;
    private final AtomicBoolean running = new AtomicBoolean();
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private ServerSocketChannel server;
    private Thread acceptThread;
    private boolean ownsSocket;

    public LocalControlServer(Path dataDirectory, String nodeId, String nodeName,
                              ReferenceStorageService references, AppConfig config,
                              PeerService peers, GrantService grants, NetworkMembershipService membership, DeviceCatalogueService catalogue,
                              ReferenceGrantService referenceGrants, ReferenceVersionService referenceVersions,
                              ManagedStorageService managedStorage) {
        this.socketPath = dataDirectory.toAbsolutePath().normalize().resolve("control.sock");
        this.nodeId = nodeId;
        this.nodeName = nodeName;
        this.references = references;
        this.config = config;
        this.peers = peers;
        this.grants = grants;
        this.membership = membership;
        this.catalogue = catalogue;
        this.referenceGrants = referenceGrants;
        this.referenceVersions = referenceVersions;
        this.managedStorage = managedStorage;
        try {
            this.outboundTransfers = new OutboundTransferQueue(new StateStore(config.dataDirectory()), membership,
                    this::requireMemberEndpoint, config.maxFileBytes());
        } catch (Exception failure) {
            throw new IllegalStateException("Unable to initialize the durable outbound transfer queue.", failure);
        }
    }

    public LocalControlServer(Path dataDirectory, String nodeId, String nodeName,
                              ReferenceStorageService references, AppConfig config,
                              PeerService peers, GrantService grants) throws Exception {
        this(dataDirectory, nodeId, nodeName, references, config, peers, grants,
                legacyDependencies(dataDirectory, config, references));
    }

    private LocalControlServer(Path dataDirectory, String nodeId, String nodeName,
                               ReferenceStorageService references, AppConfig config, PeerService peers,
                               GrantService grants, LegacyDependencies dependencies) {
        this(dataDirectory, nodeId, nodeName, references, config, peers, grants,
                dependencies.membership(), dependencies.catalogue(), dependencies.referenceGrants(), dependencies.referenceVersions(), dependencies.managedStorage());
    }

    private static LegacyDependencies legacyDependencies(Path dataDirectory, AppConfig config,
                                                         ReferenceStorageService references) throws Exception {
        dev.personalcloud.core.StateStore store = new dev.personalcloud.core.StateStore(config.dataDirectory());
        NetworkMembershipService membership = new NetworkMembershipService(store, config);
        DeviceCatalogueService catalogue = new DeviceCatalogueService(config, membership);
        return new LegacyDependencies(membership, catalogue,
                new ReferenceGrantService(store, references, membership),
                new ReferenceVersionService(config.dataDirectory(), references), new ManagedStorageService(store, config));
    }

    private record LegacyDependencies(NetworkMembershipService membership, DeviceCatalogueService catalogue,
                                      ReferenceGrantService referenceGrants, ReferenceVersionService referenceVersions,
                                      ManagedStorageService managedStorage) { }

    public synchronized void start() throws Exception {
        if (running.get()) return;
        Files.createDirectories(socketPath.getParent());
        restrictPrivateDirectory(socketPath.getParent());
        if (socketPath.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length >= 108) {
            throw new IllegalStateException("The configured data directory is too long for a Linux Unix-domain socket path. Choose a shorter PERSONALCLOUD_DATA_DIR.");
        }
        Path lockPath = socketPath.resolveSibling("control.lock");
        lockChannel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        SecretFiles.restrict(lockPath);
        try { processLock = lockChannel.tryLock(); }
        catch (java.nio.channels.OverlappingFileLockException alreadyInProcess) { processLock = null; }
        if (processLock == null) throw new IllegalStateException("Another PersonalCloud process is already using this data directory.");
        removeStaleSocket();
        server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(socketPath));
        ownsSocket = true;
        try {
            Files.setPosixFilePermissions(socketPath, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException unavailable) {
            close();
            throw new IllegalStateException("PersonalCloud local control requires owner-only Unix socket permissions on this platform.");
        }
        running.set(true);
        transferRetryScheduler.scheduleWithFixedDelay(() -> {
            if (!running.get()) return;
            try { outboundTransfers.retryDue(); }
            catch (Exception failure) { System.err.println("PersonalCloud transfer retry pass failed: " + safeMessage(failure)); }
        }, 30, 30, java.util.concurrent.TimeUnit.SECONDS);
        acceptThread = Thread.ofPlatform().name("personalcloud-control-accept").daemon(true).start(this::acceptLoop);
    }

    public Path socketPath() { return socketPath; }

    private static void restrictPrivateDirectory(Path directory) throws Exception {
        try {
            Files.setPosixFilePermissions(directory, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        } catch (UnsupportedOperationException unsupported) {
            throw new IllegalStateException("The local control socket requires POSIX owner-only directory permissions.", unsupported);
        }
    }

    private void removeStaleSocket() throws Exception {
        if (!Files.exists(socketPath)) return;
        if (Files.isSymbolicLink(socketPath)) {
            throw new IllegalStateException("Refusing to replace a symbolic link at " + socketPath);
        }
        try {
            if (!Files.readAttributes(socketPath, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isOther()) {
                throw new IllegalStateException("Refusing to replace a non-socket file at " + socketPath);
            }
        } catch (java.nio.file.NoSuchFileException disappeared) {
            return;
        }
        try (SocketChannel probe = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            probe.connect(UnixDomainSocketAddress.of(socketPath));
            throw new IllegalStateException("Another PersonalCloud process is already listening on " + socketPath);
        } catch (java.net.ConnectException stale) {
            Files.deleteIfExists(socketPath);
        }
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                SocketChannel client = server.accept();
                workers.submit(() -> handle(client));
            } catch (java.nio.channels.AsynchronousCloseException stopped) {
                break;
            } catch (Exception failure) {
                if (running.get()) System.err.println("PersonalCloud local control accept failed: " + safeMessage(failure));
            }
        }
    }

    private void handle(SocketChannel channel) {
        try (channel;
             InputStream input = Channels.newInputStream(channel);
             OutputStream output = Channels.newOutputStream(channel)) {
            boolean[] responseStarted = {false};
            try {
                String line = readLine(input, MAX_REQUEST_BYTES);
                if (line == null || line.isBlank()) throw new IllegalArgumentException("A JSON request line is required.");
                Map<String, Object> request = Json.object(line);
                String command = string(request, "command");
                switch (command) {
                    case "ping" -> respond(output, responseStarted, Map.of("ok", true, "nodeId", nodeId,
                        "nodeName", nodeName, "protocol", "personalcloud-control/1"));
                    case "references.list" -> {
                        List<Map<String, Object>> roots = references.listRoots().stream().map(ReferenceRoot::toMap).toList();
                        respond(output, responseStarted, Map.of("ok", true, "references", roots));
                    }
                    case "references.register" -> {
                        String name = string(request, "name");
                        String path = string(request, "path");
                        ReferenceRoot root = references.register(name, Path.of(path));
                        respond(output, responseStarted, Map.of("ok", true, "reference", root.toMap()));
                    }
                    case "references.locate" -> {
                        Map<String, Object> located = references.locateFile(Path.of(string(request, "path")));
                        respond(output, responseStarted, Map.of("ok", true, "file", located));
                    }
                    case "references.unregister" -> {
                        String id = string(request, "referenceId");
                        references.unregister(id);
                        respond(output, responseStarted, Map.of("ok", true, "referenceId", id));
                    }
                    case "storage.list" -> {
                        String id = string(request, "referenceId");
                        String path = optionalString(request, "path", "");
                        List<Map<String, Object>> entries = references.listEntries(id, path).stream().map(StorageEntry::toMap).toList();
                        respond(output, responseStarted, Map.of("ok", true, "entries", entries));
                    }
                    case "storage.search" -> {
                        String query = string(request, "query");
                        int limit = integer(request, "limit", 50);
                        List<Map<String, Object>> entries = references.search(query, limit).stream().map(StorageEntry::toMap).toList();
                        respond(output, responseStarted, Map.of("ok", true, "results", entries));
                    }
                    case "storage.stat" -> {
                        String id = string(request, "referenceId");
                        String path = string(request, "path");
                        Map<String, Object> metadata = references.inspect(id, path);
                        metadata.put("ok", true);
                        respond(output, responseStarted, metadata);
                    }
                    case "storage.read" -> streamRead(request, output, responseStarted);
                    case "storage.remote.read" -> streamRemoteRead(request, output, responseStarted);
                    case "managed.local.read" -> streamLocalManagedRead(request, output, responseStarted);
                    case "invites.create" -> { Map<String, Object> invitation = new LinkedHashMap<>(peers.createInvitation()); invitation.put("ok", true); respond(output, responseStarted, invitation); }
                    case "peers.list" -> respond(output, responseStarted, Map.of("ok", true, "peers", peers.listPeers()));
                    case "peers.add" -> {
                        String baseUrl = string(request, "baseUrl");
                        String code = string(request, "code");
                        Map<String, Object> remoteInfo = remote.pair(baseUrl, config.nodeId(), config.nodeName(), code);
                        String remoteId = String.valueOf(remoteInfo.get("nodeId"));
                        String remoteName = String.valueOf(remoteInfo.get("nodeName"));
                        String token = String.valueOf(remoteInfo.get("accessToken"));
                        if (remoteId.equals(config.nodeId()) || "null".equals(remoteId) || token.isBlank() || "null".equals(token)) {
                            throw new IllegalArgumentException("Remote node returned invalid pairing information.");
                        }
                        peers.saveOutgoingPeer(remoteId, remoteName, String.valueOf(remoteInfo.get("baseUrl")), token);
                        respond(output, responseStarted, Map.of("ok", true, "nodeId", remoteId, "nodeName", remoteName,
                                "direction", "OUTGOING", "baseUrl", String.valueOf(remoteInfo.get("baseUrl"))));
                    }
                    case "peers.remove" -> {
                        String peerId = string(request, "peerId");
                        String direction = string(request, "direction").toUpperCase(java.util.Locale.ROOT);
                        if ("INCOMING".equals(direction)) peers.removeTrustedPeer(peerId);
                        else if ("OUTGOING".equals(direction)) peers.removeOutgoingPeer(peerId);
                        else throw new IllegalArgumentException("Peer direction must be INCOMING or OUTGOING.");
                        respond(output, responseStarted, Map.of("ok", true, "peerId", peerId, "direction", direction));
                    }
                    case "network.status" -> respond(output, responseStarted, Map.of("ok", true, "network", membership.status()));
                    case "network.bootstrap" -> {
                        char[] password = string(request, "password").toCharArray();
                        try {
                            Map<String, Object> result = membership.bootstrap(string(request, "networkName"),
                                    string(request, "accountName"), password);
                            respond(output, responseStarted, Map.of("ok", true, "network", result));
                        } finally { java.util.Arrays.fill(password, '\0'); }
                    }
                    case "network.join" -> {
                        char[] password = string(request, "password").toCharArray();
                        try {
                            Map<String, Object> result = new NetworkEnrollmentClient().join(string(request, "baseUrl"),
                                    optionalString(request, "accountName", ""), password, config, membership.identity(), membership);
                            respond(output, responseStarted, Map.of("ok", true, "network", result));
                        } finally { java.util.Arrays.fill(password, '\0'); }
                    }
                    case "network.requests" -> respond(output, responseStarted, Map.of("ok", true, "requests", membership.pendingRequests()));
                    case "network.approve" -> respond(output, responseStarted, Map.of("ok", true,
                            "request", membership.approve(string(request, "requestId"))));
                    case "network.reject" -> respond(output, responseStarted, Map.of("ok", true,
                            "request", membership.reject(string(request, "requestId"), optionalString(request, "reason", ""))));
                    case "reference-grants.list" -> respond(output, responseStarted, Map.of("ok", true, "grants", referenceGrants.listAll()));
                    case "reference-grants.create" -> {
                        String path = optionalString(request, "path", "");
                        if (".".equals(path) || "-".equals(path)) path = "";
                        Map<String, Object> grant = referenceGrants.create(string(request, "memberId"),
                                string(request, "referenceId"), path, string(request, "permission"));
                        respond(output, responseStarted, Map.of("ok", true, "grant", grant));
                    }
                    case "reference-grants.revoke" -> {
                        String grantId = string(request, "grantId");
                        referenceGrants.revoke(grantId);
                        respond(output, responseStarted, Map.of("ok", true, "grantId", grantId));
                    }
                    case "reference-snapshots.list" -> respond(output, responseStarted, Map.of("ok", true, "snapshots", referenceVersions.list()));
                    case "reference-snapshots.restore" -> {
                        Map<String, Object> restored = new LinkedHashMap<>(referenceVersions.restore(string(request, "snapshotId")));
                        restored.put("ok", true);
                        respond(output, responseStarted, restored);
                    }
                    case "managed.local.list" -> respond(output, responseStarted, Map.of("ok", true, "files", managedStorage.listLocal()));
                    case "managed.place" -> {
                        Map<String, Object> placed = new LinkedHashMap<>(outboundTransfers.place(
                                string(request, "memberId"), string(request, "destinationPath"),
                                Path.of(string(request, "sourcePath"))));
                        placed.put("ok", true);
                        respond(output, responseStarted, placed);
                    }
                    case "managed.transfers.list" -> respond(output, responseStarted,
                            Map.of("ok", true, "transfers", outboundTransfers.list()));
                    case "managed.transfers.status" -> {
                        Map<String, Object> status = new LinkedHashMap<>(outboundTransfers.status(string(request, "jobId")));
                        status.put("ok", true);
                        respond(output, responseStarted, status);
                    }
                    case "managed.transfers.resume" -> {
                        Map<String, Object> status = new LinkedHashMap<>(outboundTransfers.resume(string(request, "jobId")));
                        status.put("ok", true);
                        respond(output, responseStarted, status);
                    }
                    case "managed.transfers.abort" -> {
                        Map<String, Object> status = new LinkedHashMap<>(outboundTransfers.abort(string(request, "jobId")));
                        status.put("ok", true);
                        respond(output, responseStarted, status);
                    }
                    case "managed.remote.list" -> {
                        String memberId = string(request, "memberId");
                        Map<String, Object> response = new NetworkPeerClient().listManagedFiles(requireMemberEndpoint(memberId), membership);
                        respond(output, responseStarted, Map.of("ok", true, "memberId", memberId,
                                "files", response.getOrDefault("files", List.of())));
                    }
                    case "managed.remote.download" -> {
                        String memberId = string(request, "memberId");
                        NetworkPeerClient.RemoteDownloadResult result = new NetworkPeerClient().downloadManagedFile(
                                requireMemberEndpoint(memberId), string(request, "fileId"), Path.of(string(request, "destination")),
                                membership, config.maxFileBytes());
                        respond(output, responseStarted, Map.of("ok", true, "path", result.path().toString(),
                                "size", result.sizeBytes(), "sha256", result.sha256()));
                    }
                    case "managed.remote.delete" -> {
                        String memberId = string(request, "memberId");
                        Map<String, Object> response = new NetworkPeerClient().deleteManagedFile(
                                requireMemberEndpoint(memberId), string(request, "fileId"), membership);
                        Map<String, Object> result = new LinkedHashMap<>(response);
                        result.put("ok", true);
                        respond(output, responseStarted, result);
                    }
                    case "network.members" -> respond(output, responseStarted, Map.of("ok", true, "members", membership.members()));
                    case "network.search" -> {
                        String query = string(request, "query");
                        int limit = (int) longValue(request, "limit", 50);
                        List<Map<String, Object>> results = new java.util.ArrayList<>();
                        for (StorageEntry entry : references.search(query, Math.min(100, Math.max(1, limit)))) {
                            Map<String, Object> item = new LinkedHashMap<>(entry.toMap());
                            item.put("ownerNodeId", config.nodeId());
                            item.put("ownerNodeName", config.nodeName());
                            item.put("source", "LOCAL");
                            results.add(item);
                        }
                        NetworkPeerClient networkClient = new NetworkPeerClient();
                        List<Map<String, Object>> unreachable = new java.util.ArrayList<>();
                        for (Map<String, Object> member : membership.members()) {
                            String memberId = String.valueOf(member.get("nodeId"));
                            if (memberId.equals(config.nodeId()) || !"ACTIVE".equals(String.valueOf(member.get("status")))) continue;
                            if (results.size() >= limit) break;
                            try {
                                String endpoint = String.valueOf(member.get("endpoint"));
                                Map<String, Object> response = networkClient.searchRemoteReferences(endpoint, query, limit - results.size(), membership);
                                Object rows = response.get("results");
                                if (rows instanceof List<?> list) for (Object value : list) {
                                    if (value instanceof Map<?, ?> map) {
                                        Map<String, Object> item = new LinkedHashMap<>();
                                        map.forEach((key, val) -> item.put(String.valueOf(key), val));
                                        item.put("ownerNodeId", memberId);
                                        item.put("ownerNodeName", String.valueOf(member.get("nodeName")));
                                        item.put("source", "REMOTE");
                                        results.add(item);
                                        if (results.size() >= limit) break;
                                    }
                                }
                            } catch (Exception unavailable) {
                                unreachable.add(Map.of("nodeId", memberId, "name", String.valueOf(member.get("nodeName")), "status", "UNAVAILABLE"));
                            }
                        }
                        respond(output, responseStarted, Map.of("ok", true, "results", results, "unavailableDevices", unreachable));
                    }
                    case "remote.references.list" -> {
                        String memberId = string(request, "memberId");
                        String endpoint = requireMemberEndpoint(memberId);
                        Map<String, Object> response = new NetworkPeerClient().listRemoteReferences(endpoint, membership);
                        respond(output, responseStarted, Map.of("ok", true, "memberId", memberId,
                                "references", response.getOrDefault("references", List.of())));
                    }
                    case "remote.reference.browse" -> {
                        String memberId = string(request, "memberId");
                        Map<String, Object> response = new NetworkPeerClient().browseRemoteReference(requireMemberEndpoint(memberId),
                                string(request, "grantId"), optionalString(request, "path", ""), membership);
                        respond(output, responseStarted, Map.of("ok", true, "entries", response.getOrDefault("entries", List.of())));
                    }
                    case "remote.reference.stat" -> {
                        String memberId = string(request, "memberId");
                        Map<String, Object> response = new NetworkPeerClient().statRemoteReference(requireMemberEndpoint(memberId),
                                string(request, "grantId"), optionalString(request, "path", ""), membership);
                        Map<String, Object> result = new LinkedHashMap<>(response);
                        result.put("ok", true);
                        respond(output, responseStarted, result);
                    }
                    case "remote.reference.download" -> {
                        String memberId = string(request, "memberId");
                        NetworkPeerClient.RemoteDownloadResult result = new NetworkPeerClient().downloadRemoteReference(
                                requireMemberEndpoint(memberId), string(request, "grantId"), optionalString(request, "path", ""),
                                Path.of(string(request, "destination")), membership, config.maxFileBytes());
                        respond(output, responseStarted, Map.of("ok", true, "path", result.path().toString(),
                                "size", result.sizeBytes(), "sha256", result.sha256()));
                    }
                    case "remote.reference.delete" -> {
                        String memberId = string(request, "memberId");
                        Map<String, Object> response = new NetworkPeerClient().deleteRemoteReference(requireMemberEndpoint(memberId),
                                string(request, "grantId"), optionalString(request, "path", ""), membership);
                        Map<String, Object> result = new LinkedHashMap<>(response);
                        result.put("ok", true);
                        respond(output, responseStarted, result);
                    }
                    case "network.set-endpoint" -> {
                        String nodeId = string(request, "nodeId");
                        String endpoint = string(request, "endpoint");
                        Map<String, Object> result =
                                new LinkedHashMap<>(membership.setMemberEndpoint(nodeId, endpoint));
                        result.put("ok", true);
                        respond(output, responseStarted, result);
                    }
                    case "network.sync" -> { catalogue.synchronizeOnce(); respond(output, responseStarted, Map.of("ok", true, "members", membership.members())); }
                    case "network.revoke" -> {
                        String memberId = string(request, "nodeId");
                        membership.revokeMember(memberId);
                        respond(output, responseStarted, Map.of("ok", true, "nodeId", memberId, "status", "REVOKED"));
                    }
                    case "grants.list" -> respond(output, responseStarted, Map.of("ok", true, "grants", grants.listAll()));
                    case "grants.create" -> {
                        String permission = normalizePermission(string(request, "permission"));
                        Map<String, Object> grant = grants.create(string(request, "peerId"), string(request, "path"), permission);
                        respond(output, responseStarted, Map.of("ok", true, "grant", toUserGrant(grant)));
                    }
                    case "grants.revoke" -> {
                        String grantId = string(request, "grantId");
                        grants.revoke(grantId);
                        respond(output, responseStarted, Map.of("ok", true, "grantId", grantId));
                    }
                    case "remote.shares.list" -> {
                        Map<String, String> peer = peers.outgoingPeer(string(request, "peerId"));
                        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
                        respond(output, responseStarted, Map.of("ok", true, "peerId", string(request, "peerId"),
                                "shares", remote.listShares(peer)));
                    }
                    case "remote.share.delete" -> {
                        String peerId = string(request, "peerId");
                        Map<String, String> peer = peers.outgoingPeer(peerId);
                        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
                        remote.deleteShare(peer, string(request, "shareId"));
                        respond(output, responseStarted, Map.of("ok", true, "peerId", peerId));
                    }
                    case "remote.share.download" -> {
                        String peerId = string(request, "peerId");
                        Map<String, String> peer = peers.outgoingPeer(peerId);
                        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
                        RemotePeerClient.DownloadResult result = remote.downloadShare(peer, string(request, "shareId"),
                                Path.of(string(request, "destination")));
                        respond(output, responseStarted, Map.of("ok", true, "path", result.path().toString(),
                                "size", result.sizeBytes(), "sha256", result.sha256()));
                    }
                    default -> throw new IllegalArgumentException("Unsupported local control command.");
                }
            } catch (Exception failure) {
                if (!responseStarted[0]) {
                    try { writeJson(output, error(safeMessage(failure))); } catch (Exception ignored) { }
                }
            }
        } catch (Exception ignored) {
            // A disconnected local client is isolated to its own request.
        }
    }

    private String requireMemberEndpoint(String memberId) throws Exception {
        Map<String, Object> member = membership.memberDetails(memberId);
        if (member.isEmpty() || !"ACTIVE".equals(String.valueOf(member.get("status")))) {
            throw new SecurityException("The requested device is not an active PersonalCloud network member.");
        }
        String endpoint = String.valueOf(member.getOrDefault("endpoint", ""));
        if (endpoint.isBlank() || "null".equals(endpoint)) throw new IllegalStateException("The member has no known direct network endpoint yet.");
        return endpoint;
    }

    private static void respond(OutputStream output, boolean[] responseStarted, Map<String, ?> value) throws Exception {
        responseStarted[0] = true;
        writeJson(output, value);
    }

    private void streamRead(Map<String, Object> request, OutputStream output, boolean[] responseStarted) throws Exception {
        String id = string(request, "referenceId");
        String path = string(request, "path");
        long offset = longValue(request, "offset", 0);
        long requestedLength = longValue(request, "length", 128 * 1024);
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (requestedLength < 0 || requestedLength > MAX_READ_BYTES) {
            throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        }
        Map<String, Object> metadata = references.metadata(id, path);
        long size = ((Number) metadata.get("size")).longValue();
        long actualLength = offset >= size ? 0 : Math.min(requestedLength, size - offset);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("ok", true);
        header.put("size", size);
        header.put("offset", offset);
        header.put("length", actualLength);
        header.put("storageKind", "REFERENCE");
        if (actualLength == 0) {
            responseStarted[0] = true;
            writeJson(output, header);
            return;
        }
        try (InputStream file = references.openFile(id, path)) {
            file.skipNBytes(offset);
            responseStarted[0] = true;
            writeJson(output, header);
            byte[] buffer = new byte[64 * 1024];
            long remaining = actualLength;
            while (remaining > 0) {
                int read = file.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (read < 0) throw new java.io.IOException("Referenced file changed during read.");
                output.write(buffer, 0, read);
                remaining -= read;
            }
            output.flush();
        }
    }

    private void streamLocalManagedRead(Map<String, Object> request, OutputStream output, boolean[] responseStarted) throws Exception {
        String fileId = string(request, "fileId");
        long offset = longValue(request, "offset", 0);
        long requestedLength = longValue(request, "length", 128 * 1024);
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (requestedLength < 0 || requestedLength > MAX_READ_BYTES) throw new IllegalArgumentException("Managed file read exceeds the local range limit.");
        Map<String, Object> metadata = managedStorage.statLocal(fileId);
        long size = ((Number) metadata.get("size")).longValue();
        byte[] bytes = managedStorage.readLocalRange(fileId, offset, (int) requestedLength);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("ok", true);
        header.put("size", size);
        header.put("offset", offset);
        header.put("length", bytes.length);
        header.put("storageKind", "MANAGED");
        header.put("sha256", metadata.getOrDefault("sha256", ""));
        responseStarted[0] = true;
        writeJson(output, header);
        if (bytes.length > 0) output.write(bytes);
        output.flush();
    }

    private void streamRemoteRead(Map<String, Object> request, OutputStream output, boolean[] responseStarted) throws Exception {
        String memberId = string(request, "memberId");
        String kind = string(request, "storageKind").toUpperCase(java.util.Locale.ROOT);
        long offset = longValue(request, "offset", 0);
        long requestedLength = longValue(request, "length", 128 * 1024);
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (requestedLength < 0 || requestedLength > MAX_READ_BYTES) {
            throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        }
        String endpoint = requireMemberEndpoint(memberId);
        NetworkPeerClient networkClient = new NetworkPeerClient();
        NetworkPeerClient.RemoteRangeResult range;
        if ("REFERENCE".equals(kind)) {
            range = networkClient.readRemoteReferenceRange(endpoint, string(request, "grantId"),
                    optionalString(request, "path", ""), offset, (int) requestedLength, membership);
        } else if ("MANAGED".equals(kind)) {
            String fileId = string(request, "fileId");
            Map<String, Object> metadata = networkClient.statManagedFile(endpoint, fileId, membership);
            long expectedSize = ((Number) metadata.get("size")).longValue();
            range = networkClient.readRemoteManagedRange(endpoint, fileId, expectedSize,
                    offset, (int) requestedLength, membership);
        } else {
            throw new IllegalArgumentException("Remote storage kind must be REFERENCE or MANAGED.");
        }
        byte[] bytes = range.bytes();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("ok", true);
        header.put("size", range.totalSize());
        header.put("offset", offset);
        header.put("length", bytes.length);
        header.put("storageKind", kind);
        if (range.sha256() != null && !range.sha256().isBlank()) header.put("sha256", range.sha256());
        responseStarted[0] = true;
        writeJson(output, header);
        if (bytes.length > 0) output.write(bytes);
        output.flush();
    }

    private static String normalizePermission(String supplied) {
        String value = supplied.trim().toUpperCase(java.util.Locale.ROOT).replace(' ', '_');
        return switch (value) {
            case "DOWNLOAD" -> "VIEW";
            case "DOWNLOAD_DELETE", "DOWNLOAD+DELETE", "DOWNLOAD_AND_DELETE" -> "MODIFY";
            case "VIEW", "MODIFY" -> value; // Transitional compatibility with PersonalCloud node/1 peers.
            default -> throw new IllegalArgumentException("Permission must be DOWNLOAD or DOWNLOAD+DELETE.");
        };
    }

    private static Map<String, Object> toUserGrant(Map<String, Object> grant) {
        Map<String, Object> result = new LinkedHashMap<>(grant);
        Object legacy = result.get("permission");
        if ("VIEW".equals(legacy)) result.put("permission", "DOWNLOAD");
        else if ("MODIFY".equals(legacy)) result.put("permission", "DOWNLOAD+DELETE");
        return result;
    }

    private static String readLine(InputStream input, int maxBytes) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1) {
            if (value == '\n') break;
            if (value != '\r') bytes.write(value);
            if (bytes.size() > maxBytes) throw new IllegalArgumentException("Local control request is too large.");
        }
        if (value == -1 && bytes.size() == 0) return null;
        return bytes.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void writeJson(OutputStream output, Map<String, ?> value) throws Exception {
        output.write(Json.stringify(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.write('\n');
        output.flush();
    }

    private static Map<String, Object> error(String message) { return Map.of("ok", false, "error", message); }
    private static String string(Map<String, Object> request, String key) {
        Object value = request.get(key);
        if (!(value instanceof String text) || text.isBlank()) throw new IllegalArgumentException("Request field '" + key + "' is required.");
        return text;
    }
    private static String optionalString(Map<String, Object> request, String key, String fallback) {
        Object value = request.get(key);
        return value instanceof String text ? text : fallback;
    }
    private static int integer(Map<String, Object> request, String key, int fallback) {
        long value = longValue(request, key, fallback);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) throw new IllegalArgumentException("Invalid integer field '" + key + "'.");
        return (int) value;
    }
    private static long longValue(Map<String, Object> request, String key, long fallback) {
        Object value = request.get(key);
        if (value == null) return fallback;
        if (!(value instanceof Number number)) throw new IllegalArgumentException("Request field '" + key + "' must be numeric.");
        double raw = number.doubleValue();
        long parsed = number.longValue();
        if (!Double.isFinite(raw) || raw != parsed) throw new IllegalArgumentException("Request field '" + key + "' must be an integer.");
        return parsed;
    }
    private static String safeMessage(Exception failure) {
        return failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage();
    }

    @Override public synchronized void close() {
        running.set(false);
        transferRetryScheduler.shutdownNow();
        try { if (server != null) server.close(); } catch (Exception ignored) { }
        workers.shutdownNow();
        // A failed second instance must never unlink the live socket owned by
        // the first instance. Only the server that completed bind may remove it.
        if (ownsSocket) {
            try { Files.deleteIfExists(socketPath); } catch (Exception ignored) { }
            ownsSocket = false;
        }
        try { if (processLock != null && processLock.isValid()) processLock.release(); } catch (Exception ignored) { }
        try { if (lockChannel != null) lockChannel.close(); } catch (Exception ignored) { }
    }
}
