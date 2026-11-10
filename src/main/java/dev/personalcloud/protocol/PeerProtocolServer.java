package dev.personalcloud.protocol;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.SecurityMonitor;
import dev.personalcloud.net.Json;
import dev.personalcloud.network.NetworkMembershipService;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceVersionService;
import dev.personalcloud.storage.StorageEntry;
import dev.personalcloud.storage.ManagedStorageService;
import dev.personalcloud.storage.EligibleStorageService;
import dev.personalcloud.policy.ApprovalRequiredException;
import dev.personalcloud.policy.FilesystemPolicyService;
import dev.personalcloud.policy.PolicyOperation;
import dev.personalcloud.policy.ProtectionApprovalService;
import dev.personalcloud.network.CoordinatedTransferService;
import dev.personalcloud.transfer.ResumableTransferManager;
import dev.personalcloud.transfer.TransferTicketService;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Headless PersonalCloud node protocol endpoint. It intentionally exposes only the peer protocol;
 * there is no browser dashboard, browser session, or remote administration surface.
 */
public final class PeerProtocolServer implements AutoCloseable {
    private static final int MAX_FORM_BYTES = 64 * 1024;
    private static final int RATE_REQUESTS_PER_MINUTE =
            envInt("PERSONALCLOUD_RATE_LIMIT_REQUESTS_PER_MINUTE", 600, 10, 100_000);
    private static final int RATE_CHALLENGES_PER_MINUTE =
            envInt("PERSONALCLOUD_RATE_LIMIT_CHALLENGES_PER_MINUTE", 30, 1, 10_000);
    private static final int RATE_ENROLLMENTS_PER_MINUTE =
            envInt("PERSONALCLOUD_RATE_LIMIT_ENROLLMENTS_PER_MINUTE", 12, 1, 10_000);
    private static final int RATE_FILESYSTEM_OPS_PER_MINUTE =
            envInt("PERSONALCLOUD_RATE_LIMIT_FILESYSTEM_OPS_PER_MINUTE", 300, 1, 100_000);
    private final AppConfig config;
    private final FileService files;
    private final PeerService peers;
    private final GrantService grants;
    private final AuditLog audit;
    private final NetworkMembershipService membership;
    private final ReferenceStorageService references;
    private final ReferenceGrantService referenceGrants;
    private final ReferenceVersionService referenceVersions;
    private final ManagedStorageService managedStorage;
    private final FilesystemPolicyService policy;
    private final ProtectionApprovalService approvals;
    private final EligibleStorageService filesystem;
    private final SecurityMonitor security = new SecurityMonitor();
    private ResumableTransferManager transfers;
    private TransferTicketService tickets;
    private CoordinatedTransferService coordinated;
    private HttpServer server;
    private ExecutorService executor;

    public PeerProtocolServer(AppConfig config, FileService files, PeerService peers,
                              GrantService grants, AuditLog audit, NetworkMembershipService membership,
                              ReferenceStorageService references, ReferenceGrantService referenceGrants,
                              ReferenceVersionService referenceVersions, ManagedStorageService managedStorage,
                              FilesystemPolicyService policy, ProtectionApprovalService approvals,
                              EligibleStorageService filesystem) {
        this.config = config;
        this.files = files;
        this.peers = peers;
        this.grants = grants;
        this.audit = audit;
        this.membership = membership;
        this.references = references;
        this.referenceGrants = referenceGrants;
        this.referenceVersions = referenceVersions;
        this.managedStorage = managedStorage;
        this.policy = policy;
        this.approvals = approvals;
        this.filesystem = filesystem;
    }

    public PeerProtocolServer(AppConfig config, FileService files, PeerService peers,
                              GrantService grants, AuditLog audit, NetworkMembershipService membership,
                              ReferenceStorageService references, ReferenceGrantService referenceGrants,
                              ReferenceVersionService referenceVersions, ManagedStorageService managedStorage) {
        this(config, files, peers, grants, audit, membership, references, referenceGrants, referenceVersions,
                managedStorage, legacyFilesystem(config));
    }

    private PeerProtocolServer(AppConfig config, FileService files, PeerService peers, GrantService grants,
                               AuditLog audit, NetworkMembershipService membership,
                               ReferenceStorageService references, ReferenceGrantService referenceGrants,
                               ReferenceVersionService referenceVersions, ManagedStorageService managedStorage,
                               LegacyFilesystem legacy) {
        this(config, files, peers, grants, audit, membership, references, referenceGrants, referenceVersions,
                managedStorage, legacy.policy(), legacy.approvals(), legacy.filesystem());
    }

    private static LegacyFilesystem legacyFilesystem(AppConfig config) {
        try {
            dev.personalcloud.core.StateStore store = new dev.personalcloud.core.StateStore(config.dataDirectory());
            FilesystemPolicyService policy = new FilesystemPolicyService(store);
            ProtectionApprovalService approvals = new ProtectionApprovalService();
            return new LegacyFilesystem(policy, approvals, new EligibleStorageService(config, store, policy, approvals));
        } catch (Exception failure) {
            throw new IllegalStateException("Unable to initialize filesystem policy services.", failure);
        }
    }

    private record LegacyFilesystem(FilesystemPolicyService policy, ProtectionApprovalService approvals,
                                    EligibleStorageService filesystem) { }

    public PeerProtocolServer(AppConfig config, FileService files, PeerService peers,
                              GrantService grants, AuditLog audit, NetworkMembershipService membership,
                              ReferenceStorageService references, ReferenceGrantService referenceGrants,
                              ReferenceVersionService referenceVersions) throws Exception {
        this(config, files, peers, grants, audit, membership, references, referenceGrants,
                referenceVersions, new ManagedStorageService(new dev.personalcloud.core.StateStore(config.dataDirectory()), config));
    }

    public PeerProtocolServer(AppConfig config, FileService files, PeerService peers,
                              GrantService grants, AuditLog audit, NetworkMembershipService membership) throws Exception {
        this(config, files, peers, grants, audit, membership,
                legacyReferenceDependencies(config, files, membership));
    }

    private PeerProtocolServer(AppConfig config, FileService files, PeerService peers, GrantService grants,
                               AuditLog audit, NetworkMembershipService membership, LegacyReferenceDependencies dependencies) {
        this(config, files, peers, grants, audit, membership, dependencies.references(),
                dependencies.grants(), dependencies.versions(), dependencies.managedStorage());
    }

    private static LegacyReferenceDependencies legacyReferenceDependencies(AppConfig config, FileService files,
                                                                            NetworkMembershipService membership) throws Exception {
        dev.personalcloud.core.StateStore store = new dev.personalcloud.core.StateStore(config.dataDirectory());
        ReferenceStorageService references = new ReferenceStorageService(store, config.dataDirectory(), files.root());
        return new LegacyReferenceDependencies(references, new ReferenceGrantService(store, references, membership),
                new ReferenceVersionService(config.dataDirectory(), references), new ManagedStorageService(store, config));
    }

    private record LegacyReferenceDependencies(ReferenceStorageService references, ReferenceGrantService grants,
                                               ReferenceVersionService versions, ManagedStorageService managedStorage) { }

    public PeerProtocolServer(AppConfig config, FileService files, PeerService peers,
                              GrantService grants, AuditLog audit) throws Exception {
        this(config, files, peers, grants, audit,
                new NetworkMembershipService(new dev.personalcloud.core.StateStore(config.dataDirectory()), config));
    }

    public void start() throws Exception {
        tickets = new TransferTicketService(new dev.personalcloud.core.StateStore(config.dataDirectory()), membership);
        coordinated = new CoordinatedTransferService(config, membership, filesystem, tickets,
                new dev.personalcloud.network.NetworkPeerClient(),
                new dev.personalcloud.core.StateStore(config.dataDirectory()));
        transfers = new ResumableTransferManager(config.dataDirectory().resolve("transfer-sessions"),
                config.nodeId(), config.maxFileBytes(), ResumableTransferManager.DEFAULT_CHUNK_BYTES,
                (transferId, uploader, relative, content, size, sha256) ->
                        managedStorage.receiveTransfer(transferId, uploader, relative, content, size, sha256),
                (transferId, uploader, relative, content, size, sha256, session) ->
                        filesystem.writeCoordinated(session.get("requester"), session.get("rootId"), relative,
                                content, size, sha256, Boolean.parseBoolean(session.get("overwrite")),
                                session.getOrDefault("destinationApprovalId", ""), session.get("ticketId")));
        InetSocketAddress address = new InetSocketAddress(config.bindAddress(), config.port());
        if (config.tlsKeystore() != null) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(config.tlsKeystore())) {
                keyStore.load(input, config.tlsKeystorePassword().toCharArray());
            }
            KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            managers.init(keyStore, config.tlsKeystorePassword().toCharArray());
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(managers.getKeyManagers(), null, null);
            HttpsServer https = HttpsServer.create(address, 64);
            https.setHttpsConfigurator(new HttpsConfigurator(ssl));
            server = https;
        } else {
            server = HttpServer.create(address, 64);
        }
        executor = Executors.newVirtualThreadPerTaskExecutor();
        try {
            server.setExecutor(executor);
            server.createContext("/", this::handle);
            server.start();
        } catch (Exception failure) {
            // A partially initialized listener must not leak a bound port or
            // worker pool when startup fails.
            try { server.stop(0); } catch (Exception ignored) { }
            executor.shutdownNow();
            server = null;
            executor = null;
            throw failure;
        }
    }

    public int port() {
        return server == null ? config.port() : server.getAddress().getPort();
    }

    @Override public void close() {
        if (server != null) { server.stop(1); server = null; }
        if (executor != null) { executor.shutdownNow(); executor = null; }
    }

    private void handle(HttpExchange exchange) {
        try {
            Headers headers = exchange.getResponseHeaders();
            headers.set("X-Content-Type-Options", "nosniff");
            headers.set("Cache-Control", "no-store");
            if (exchange instanceof HttpsExchange) headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase();
            String source = clientAddress(exchange);
            if (!security.requestAllowed("all:" + source, RATE_REQUESTS_PER_MINUTE, 60)) {
                sendJson(exchange, 429, Map.of("error", "Too many requests from this address; retry shortly."));
                return;
            }
            if (path.startsWith("/network/")) {
                if ("GET".equals(method) && "/network/challenge".equals(path)
                        && !security.requestAllowed("challenge:" + source, RATE_CHALLENGES_PER_MINUTE, 60)) {
                    sendJson(exchange, 429, Map.of("error", "Enrollment challenge requests are temporarily rate-limited."));
                    return;
                }
                if ("POST".equals(method) && "/network/enroll".equals(path)
                        && !security.requestAllowed("enroll:" + source, RATE_ENROLLMENTS_PER_MINUTE, 60)) {
                    sendJson(exchange, 429, Map.of("error", "Enrollment requests are temporarily rate-limited."));
                    return;
                }
                handleNetworkApi(exchange, path, method);
                return;
            }
            if ("GET".equals(method) && "/node/info".equals(path)) {
                sendJson(exchange, 200, peers.nodeInfo());
                return;
            }
            if ("POST".equals(method) && "/node/pair".equals(path)) {
                acceptPairing(exchange);
                return;
            }
            if (path.equals("/node/health") || path.equals("/node/peer") || path.equals("/node/shares")
                    || path.startsWith("/node/shares/")) {
                handleAuthenticatedPeerApi(exchange, path, method);
                return;
            }
            sendJson(exchange, 404, Map.of("error", "PersonalCloud exposes only the peer protocol on this endpoint."));
        } catch (Throwable failure) {
            try {
                if (failure instanceof ApprovalRequiredException approval) {
                    sendJson(exchange, 403, Map.of("error", approval.getMessage(), "approvalRequired", true,
                            "rootId", approval.rootId(), "path", approval.path(),
                            "operation", approval.operation().name()));
                    return;
                }
                int status = failure instanceof RangeNotSatisfiableException ? 416
                        : failure instanceof SecurityException ? 403
                        : failure instanceof IllegalArgumentException ? 400
                        : failure instanceof IllegalStateException ? 409 : 500;
                if (failure instanceof RangeNotSatisfiableException range) {
                    exchange.getResponseHeaders().set("Content-Range", "bytes */" + range.resourceSize);
                    exchange.getResponseHeaders().set("Accept-Ranges", "bytes");
                }
                // Unexpected failures may carry filesystem paths or provider
                // details. Return them only for deliberate, caller-visible
                // rejections; otherwise fail closed with a generic message.
                boolean safeMessage = failure instanceof SecurityException
                        || failure instanceof IllegalArgumentException
                        || failure instanceof IllegalStateException
                        || failure instanceof ApprovalRequiredException
                        || failure instanceof RangeNotSatisfiableException;
                String message = safeMessage && failure.getMessage() != null
                        ? failure.getMessage() : "Unexpected node error.";
                sendJson(exchange, status, Map.of("error", message));
            } catch (Exception ignored) {
                exchange.close();
            }
        }
    }

    private void handleNetworkApi(HttpExchange exchange, String path, String method) throws Exception {
        if ("GET".equals(method) && "/network/challenge".equals(path)) {
            sendJson(exchange, 200, membership.createChallenge());
            return;
        }
        if ("POST".equals(method) && "/network/enroll".equals(path)) {
            byte[] body = readLimitedBody(exchange.getRequestBody(), 32 * 1024);
            Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
            sendJson(exchange, 200, membership.submitEnrollment(request));
            return;
        }
        String statusPrefix = "/network/enroll/status/";
        if ("GET".equals(method) && path.startsWith(statusPrefix)) {
            String requestId = decode(path.substring(statusPrefix.length()));
            sendJson(exchange, 200, membership.enrollmentResult(requestId));
            return;
        }
        if (path.startsWith("/network/fs/")) {
            handleFilesystemApi(exchange, path, method);
            return;
        }
        if ("GET".equals(method) && "/network/coordinated/metadata".equals(path)) {
            String member = authenticateMember(exchange, method, new byte[0]);
            if (member == null) return;
            Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
            String role = query.getOrDefault("role", "source").toLowerCase(java.util.Locale.ROOT);
            String rootId = query.getOrDefault("rootId", "");
            String relativePath = query.getOrDefault("path", "");
            Map<String, Object> metadata = role.equals("destination")
                    ? filesystem.destinationMetadata(member, rootId, relativePath)
                    : filesystem.transferMetadata(member, rootId, relativePath);
            sendJson(exchange, 200, metadata);
            return;
        }
        if ("POST".equals(method) && "/network/coordinated/transfers".equals(path)) {
            byte[] body = readLimitedBody(exchange.getRequestBody(), 64 * 1024);
            if (!membership.authenticate(method, exchange.getRequestURI().toASCIIString(),
                    exchange.getRequestHeaders(), body)) {
                sendJson(exchange, 401, Map.of("error", "A valid active PersonalCloud network-member identity is required."));
                return;
            }
            String requester = exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
            Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
            Object ticketValue = request.get("ticket");
            if (!(ticketValue instanceof Map<?, ?>)) {
                throw new IllegalArgumentException("A coordinated transfer ticket is required.");
            }
            @SuppressWarnings("unchecked") Map<String, Object> ticket = (Map<String, Object>) ticketValue;
            Map<String, Object> result = coordinated.executeSource(ticket,
                    string(request, "ticketSignature"), requester);
            audit.record("COORDINATED_TRANSFER_EXECUTED", requester,
                    "ticket=" + TransferTicketService.text(ticket, "ticketId")
                            + ", transfer=" + TransferTicketService.text(ticket, "transferId")
                            + ", state=" + result.get("state"));
            sendJson(exchange, 200, result);
            return;
        }
        if ("GET".equals(method) && path.startsWith("/network/coordinated/transfers/")) {
            String member = authenticateMember(exchange, method, new byte[0]);
            if (member == null) return;
            String requestId = decode(path.substring("/network/coordinated/transfers/".length()));
            sendJson(exchange, 200, coordinated.sourceStatus(member, requestId));
            return;
        }

        if ("POST".equals(method) && "/network/transfers".equals(path)) {
            byte[] body = readLimitedBody(exchange.getRequestBody(), 64 * 1024);
            if (!membership.authenticate(method, exchange.getRequestURI().toASCIIString(),
                    exchange.getRequestHeaders(), body)) {
                sendJson(exchange, 401, Map.of("error", "A valid active PersonalCloud network-member identity is required."));
                return;
            }
            Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
            String uploader = exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
            if ("coordinated".equals(optionalString(request, "kind"))) {
                Object ticketValue = request.get("ticket");
                if (!(ticketValue instanceof Map<?, ?>)) {
                    throw new IllegalArgumentException("A coordinated transfer ticket is required.");
                }
                @SuppressWarnings("unchecked") Map<String, Object> ticket = (Map<String, Object>) ticketValue;
                String ticketSignature = string(request, "ticketSignature");
                tickets.verify(ticket, ticketSignature);
                String issuer = TransferTicketService.text(ticket, "issuerNodeId");
                String source = TransferTicketService.text(ticket, "sourceNodeId");
                String destination = TransferTicketService.text(ticket, "destinationNodeId");
                if (!uploader.equals(source)) {
                    throw new SecurityException("The coordinated transfer must be uploaded by the ticket's source device.");
                }
                if (!config.nodeId().equals(destination)) {
                    throw new SecurityException("The coordinated ticket is not bound to this destination device.");
                }
                String transferId = TransferTicketService.text(ticket, "transferId");
                String requestId = TransferTicketService.text(ticket, "requestId");
                String ticketId = TransferTicketService.text(ticket, "ticketId");
                if (!transferId.equals(String.valueOf(request.getOrDefault("transferId", "")))) {
                    throw new SecurityException("The coordinated transfer identity does not match its ticket.");
                }
                tickets.claim(ticket, "DESTINATION", transferId, requestId);
                String rootId = TransferTicketService.text(ticket, "destinationRootId");
                String destinationPath = TransferTicketService.text(ticket, "destinationPath");
                boolean overwrite = TransferTicketService.bool(ticket, "overwrite");
                long size = TransferTicketService.number(ticket, "size");
                String sha256 = TransferTicketService.text(ticket, "sha256");
                String destinationApprovalId = optionalString(ticket, "destinationApprovalId");
                filesystem.authorizeCoordinatedWrite(issuer, rootId, destinationPath, overwrite,
                        destinationApprovalId, ticketId, size, sha256);
                Map<String, Object> created = transfers.createCoordinated(uploader, transferId, issuer,
                        rootId, destinationPath, size, sha256, overwrite,
                        TransferTicketService.operation(ticket), ticketId, requestId, destinationApprovalId);
                sendJson(exchange, 201, created);
                return;
            }
            String requestedTransferId = String.valueOf(request.getOrDefault("transferId", ""));
            Map<String, Object> created = requestedTransferId.isBlank()
                    ? transfers.create(uploader, String.valueOf(request.getOrDefault("path", "")),
                            number(request.get("size")), String.valueOf(request.getOrDefault("sha256", "")))
                    : transfers.create(uploader, requestedTransferId, String.valueOf(request.getOrDefault("path", "")),
                            number(request.get("size")), String.valueOf(request.getOrDefault("sha256", "")));
            sendJson(exchange, 201, created);
            return;
        }
        if ("PUT".equals(method) && path.matches("/network/transfers/[0-9a-fA-F-]{36}/chunks/[0-9]+")) {
            String[] parts = path.substring("/network/transfers/".length()).split("/");
            String transferId = parts[0];
            int index;
            long length;
            try {
                index = Integer.parseInt(parts[2]);
                length = Long.parseLong(exchange.getRequestHeaders().getFirst("X-PC-Chunk-Length"));
            } catch (Exception invalid) { throw new IllegalArgumentException("Valid chunk index and length headers are required."); }
            String chunkHash = exchange.getRequestHeaders().getFirst("X-PC-Chunk-SHA256");
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("transferId", transferId); metadata.put("index", index);
            metadata.put("length", length); metadata.put("sha256", chunkHash == null ? "" : chunkHash);
            byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
            if (exchange.getRequestBody() == null || !membership.authenticate(method,
                    exchange.getRequestURI().toASCIIString(), exchange.getRequestHeaders(), signedMetadata)) {
                sendJson(exchange, 401, Map.of("error", "A valid signed member identity is required for this chunk."));
                return;
            }
            long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
            if (contentLength != length) throw new IllegalArgumentException("HTTP content length does not match the signed chunk length.");
            Map<String, Object> result = transfers.receiveChunk(
                    exchange.getRequestHeaders().getFirst("X-PC-Node-ID"), transferId, index,
                    contentLength, chunkHash, exchange.getRequestBody());
            sendJson(exchange, 200, result);
            return;
        }
        if ("PUT".equals(method) && "/network/managed/files".equals(path)) {
            Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
            String destination = query.getOrDefault("path", "");
            long declaredSize;
            try { declaredSize = Long.parseLong(exchange.getRequestHeaders().getFirst("X-PC-File-Length")); }
            catch (Exception invalid) { throw new IllegalArgumentException("A valid signed managed-file length is required."); }
            String declaredHash = exchange.getRequestHeaders().getFirst("X-PC-File-SHA256");
            Map<String, Object> uploadMetadata = new LinkedHashMap<>();
            uploadMetadata.put("path", destination);
            uploadMetadata.put("size", declaredSize);
            uploadMetadata.put("sha256", declaredHash == null ? "" : declaredHash);
            byte[] authenticationBody = Json.stringify(uploadMetadata).getBytes(StandardCharsets.UTF_8);
            if (!membership.authenticate(method, exchange.getRequestURI().toASCIIString(), exchange.getRequestHeaders(), authenticationBody)) {
                sendJson(exchange, 401, Map.of("error", "A valid active PersonalCloud network-member identity is required."));
                return;
            }
            String uploaderId = exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
            Map<String, Object> stored = managedStorage.receive(uploaderId, destination, exchange.getRequestBody(), declaredSize, declaredHash);
            sendJson(exchange, 201, stored);
            return;
        }
        byte[] body = new byte[0];
        if ("POST".equals(method)) body = readLimitedBody(exchange.getRequestBody(), 64 * 1024);
        if (!membership.authenticate(method, exchange.getRequestURI().toASCIIString(),
                exchange.getRequestHeaders(), body)) {
            sendJson(exchange, 401, Map.of("error", "A valid active PersonalCloud network-member identity is required."));
            return;
        }
        if ("GET".equals(method) && "/network/members".equals(path)) {
            sendJson(exchange, 200, Map.of("networkId", membership.status().get("networkId"),
                    "members", membership.membersForWire()));
            return;
        }
        if ("GET".equals(method) && "/network/presence".equals(path)) {
            sendJson(exchange, 200, membership.signedPresence());
            return;
        }
        String requesterId = exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
        String transferPrefix = "/network/transfers/";
        if (path.startsWith(transferPrefix)) {
            String remainder = path.substring(transferPrefix.length());
            if (remainder.endsWith("/commit") && "POST".equals(method)) {
                String id = remainder.substring(0, remainder.length() - "/commit".length());
                sendJson(exchange, 200, transfers.commit(requesterId, id));
                return;
            }
            if ("GET".equals(method) && !remainder.contains("/")) {
                sendJson(exchange, 200, transfers.status(requesterId, remainder));
                return;
            }
            if ("DELETE".equals(method) && !remainder.contains("/")) {
                transfers.abort(requesterId, remainder);
                sendJson(exchange, 200, Map.of("transferId", remainder, "aborted", true));
                return;
            }
        }
        if ("GET".equals(method) && "/network/managed/files".equals(path)) {
            sendJson(exchange, 200, Map.of("files", managedStorage.listForMember(requesterId)));
            return;
        }
        String managedPrefix = "/network/managed/files/";
        if (path.startsWith(managedPrefix)) {
            String remainder = path.substring(managedPrefix.length());
            if ("GET".equals(method) && remainder.endsWith("/content")) {
                String fileId = decode(remainder.substring(0, remainder.length() - "/content".length()));
                streamManagedFile(exchange, requesterId, fileId);
                return;
            }
            if ("GET".equals(method) && !remainder.contains("/")) {
                String fileId = decode(remainder);
                sendJson(exchange, 200, managedStorage.statForMember(requesterId, fileId));
                return;
            }
            if ("DELETE".equals(method) && !remainder.contains("/")) {
                String fileId = decode(remainder);
                managedStorage.deleteForMember(requesterId, fileId);
                audit.record("MANAGED_FILE_DELETED", requesterId, "fileId=" + fileId);
                sendJson(exchange, 200, Map.of("ok", true, "fileId", fileId, "deleted", true));
                return;
            }
        }
        if ("GET".equals(method) && "/network/references".equals(path)) {
            sendJson(exchange, 200, Map.of("references", referenceGrants.listForMember(requesterId)));
            return;
        }
        if ("GET".equals(method) && path.startsWith("/network/search")) {
            Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
            String term = query.getOrDefault("q", "");
            int limit;
            try { limit = Integer.parseInt(query.getOrDefault("limit", "50")); }
            catch (NumberFormatException invalid) { throw new IllegalArgumentException("Search limit must be an integer."); }
            sendJson(exchange, 200, Map.of("results", referenceGrants.search(requesterId, term, limit)));
            return;
        }
        String referencePrefix = "/network/references/";
        if (path.startsWith(referencePrefix)) {
            String remainder = path.substring(referencePrefix.length());
            String[] segments = remainder.split("/", -1);
            String grantId = decode(segments[0]);
            Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
            String relativePath = query.getOrDefault("path", "");
            if ("GET".equals(method) && segments.length == 2 && "entries".equals(segments[1])) {
                List<Map<String, Object>> entries = referenceGrants.browse(requesterId, grantId, relativePath)
                        .stream().map(StorageEntry::toMap).toList();
                sendJson(exchange, 200, Map.of("entries", entries));
                return;
            }
            if ("GET".equals(method) && segments.length == 2 && "stat".equals(segments[1])) {
                sendJson(exchange, 200, referenceGrants.stat(requesterId, grantId, relativePath));
                return;
            }
            if ("GET".equals(method) && segments.length == 2 && "content".equals(segments[1])) {
                streamReferenceFile(exchange, requesterId, grantId, relativePath);
                return;
            }
            if ("DELETE".equals(method) && segments.length == 1) {
                Map<String, Object> deleted = referenceGrants.delete(requesterId, grantId, relativePath,
                        referenceVersions, config.maxFileBytes());
                audit.record("REFERENCED_FILE_DELETED", requesterId, "grant=" + grantId + ", path=" + relativePath);
                sendJson(exchange, 200, deleted);
                return;
            }
        }
        if ("POST".equals(method) && "/network/heartbeat".equals(path)) {
            Map<String, Object> heartbeat = Json.object(new String(body, StandardCharsets.UTF_8));
            String nodeId = string(heartbeat, "nodeId");
            String authenticatedNode = exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
            if (!nodeId.equals(authenticatedNode)) throw new SecurityException("Heartbeat identity does not match the authenticated member.");
            membership.recordHeartbeat(nodeId, string(heartbeat, "endpoint"), string(heartbeat, "nodeName"));
            sendJson(exchange, 200, Map.of("ok", true, "receivedAt", java.time.Instant.now().toString()));
            return;
        }
        sendJson(exchange, 404, Map.of("error", "Network route not found."));
    }

    private void handleFilesystemApi(HttpExchange exchange, String path, String method) throws Exception {
        String prefix = "/network/fs/";
        String remainder = path.substring(prefix.length());
        if ("GET".equals(method) && "roots".equals(remainder)) {
            String member = authenticateMember(exchange, method, new byte[0]);
            if (member == null || !filesystemRequestAllowed(member, exchange)) return;
            sendJson(exchange, 200, Map.of("roots", filesystem.rootsForMember()));
            return;
        }
        if ("PUT".equals(method) && remainder.matches("[^/]+/content")) {
            handleFilesystemWrite(exchange, path, remainder.substring(0, remainder.length() - "/content".length()));
            return;
        }
        byte[] body = "POST".equals(method) ? readLimitedBody(exchange.getRequestBody(), 64 * 1024) : new byte[0];
        String member = authenticateMember(exchange, method, body);
        if (member == null || !filesystemRequestAllowed(member, exchange)) return;
        String[] segments = remainder.split("/", -1);
        Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
        if (segments.length == 2 && "approvals".equals(segments[0])) {
            if ("GET".equals(method)) {
                sendJson(exchange, 200, filesystem.approvalStatus(member, decode(segments[1])));
                return;
            }
            throw new IllegalArgumentException("Unsupported filesystem approval route.");
        }
        if (segments.length != 2) throw new IllegalArgumentException("Invalid filesystem route.");
        String rootId = decode(segments[0]);
        String action = segments[1];
        String relativePath = query.getOrDefault("path", "");
        switch (action) {
            case "entries" -> {
                if (!"GET".equals(method)) break;
                sendJson(exchange, 200, Map.of("entries", filesystem.list(member, rootId, relativePath)));
                return;
            }
            case "stat" -> {
                if (!"GET".equals(method)) break;
                sendJson(exchange, 200, filesystem.stat(member, rootId, relativePath));
                return;
            }
            case "content" -> {
                if (!"GET".equals(method)) break;
                streamEligibleFile(exchange, member, rootId, relativePath);
                return;
            }
            case "directories" -> {
                if (!"POST".equals(method)) break;
                Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
                Map<String, Object> created = filesystem.createDirectory(member, rootId, string(request, "path"));
                audit.record("FILESYSTEM_DIRECTORY_CREATED", member,
                        "root=" + rootId + ", path=" + created.get("path"));
                sendJson(exchange, 201, created);
                return;
            }
            case "move" -> {
                if (!"POST".equals(method)) break;
                Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
                Map<String, Object> moved = filesystem.move(member, rootId, string(request, "from"), string(request, "to"),
                        booleanValue(request, "overwrite", false), optionalString(request, "approvalId"),
                        optionalString(request, "destinationApprovalId"));
                audit.record("FILESYSTEM_MOVED", member, "root=" + rootId
                        + ", from=" + string(request, "from") + ", to=" + string(request, "to"));
                sendJson(exchange, 200, moved);
                return;
            }
            case "entry" -> {
                if (!"DELETE".equals(method)) break;
                Map<String, Object> deleted = filesystem.delete(member, rootId, relativePath,
                        booleanValue(query, "recursive", false), optionalString(query, "approvalId"));
                audit.record("FILESYSTEM_DELETED", member, "root=" + rootId + ", path=" + relativePath
                        + ", recursive=" + booleanValue(query, "recursive", false));
                sendJson(exchange, 200, deleted);
                return;
            }
            case "approvals" -> {
                if (!"POST".equals(method)) break;
                Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
                String operation = string(request, "operation").strip().toUpperCase(java.util.Locale.ROOT);
                Map<String, Object> approval = filesystem.requestApproval(member, rootId, string(request, "path"),
                        PolicyOperation.valueOf(operation), longValue(request, "ttlSeconds", 0));
                audit.record("FILESYSTEM_APPROVAL_REQUESTED", member, "root=" + rootId
                        + ", path=" + string(request, "path") + ", operation=" + operation);
                sendJson(exchange, 201, approval);
                return;
            }
            default -> { }
        }
        throw new IllegalArgumentException("Unsupported filesystem operation.");
    }

    private void handleFilesystemWrite(HttpExchange exchange, String path, String encodedRootId) throws Exception {
        Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
        String relativePath = query.getOrDefault("path", "");
        long declaredSize;
        try { declaredSize = Long.parseLong(exchange.getRequestHeaders().getFirst("X-PC-File-Length")); }
        catch (Exception invalid) { throw new IllegalArgumentException("A valid signed filesystem-file length is required."); }
        String declaredHash = exchange.getRequestHeaders().getFirst("X-PC-File-SHA256");
        boolean overwrite = Boolean.parseBoolean(query.getOrDefault("overwrite", "false"));
        String approvalId = exchange.getRequestHeaders().getFirst("X-PC-Approval-ID");
        Map<String, Object> uploadMetadata = new LinkedHashMap<>();
        uploadMetadata.put("path", relativePath);
        uploadMetadata.put("size", declaredSize);
        uploadMetadata.put("sha256", declaredHash == null ? "" : declaredHash);
        uploadMetadata.put("overwrite", overwrite);
        uploadMetadata.put("approvalId", approvalId == null ? "" : approvalId);
        byte[] authenticationBody = Json.stringify(uploadMetadata).getBytes(StandardCharsets.UTF_8);
        if (!membership.authenticate("PUT", exchange.getRequestURI().toASCIIString(),
                exchange.getRequestHeaders(), authenticationBody)) {
            sendJson(exchange, 401, Map.of("error", "A valid active PersonalCloud network-member identity is required."));
            return;
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength != declaredSize) throw new IllegalArgumentException("HTTP content length does not match the signed filesystem-file length.");
        String member = exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
        if (!filesystemRequestAllowed(member, exchange)) return;
        Map<String, Object> stored = filesystem.write(member, decode(encodedRootId), relativePath,
                exchange.getRequestBody(), declaredSize, declaredHash, overwrite, approvalId);
        audit.record("FILESYSTEM_FILE_WRITTEN", member, "root=" + decode(encodedRootId)
                + ", path=" + relativePath + ", size=" + declaredSize
                + ", sha256=" + (declaredHash == null ? "" : declaredHash.toLowerCase(java.util.Locale.ROOT)));
        sendJson(exchange, 201, stored);
    }

    private void streamEligibleFile(HttpExchange exchange, String memberId, String rootId,
                                    String relativePath) throws Exception {
        Map<String, Object> metadata = filesystem.stat(memberId, rootId, relativePath);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The requested path is not a file.");
        long size = ((Number) metadata.get("size")).longValue();
        long start = 0;
        long end = size - 1;
        int status = 200;
        long[] range = requestedRange(exchange, size);
        if (range != null) {
            start = range[0];
            end = range[1];
            status = 206;
        }
        long length = Math.max(0, end - start + 1);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Accept-Ranges", "bytes");
        headers.set("X-Content-SHA256", filesystem.sha256(memberId, rootId, relativePath));
        setAttachmentName(headers, String.valueOf(metadata.get("name")));
        if (status == 206) {
            headers.set("Content-Range", "bytes " + start + "-" + end + "/" + size);
            try (InputStream digestInput = filesystem.open(memberId, rootId, relativePath)) {
                headers.set("X-Content-Range-SHA256", sha256Range(digestInput, start, length));
            }
        }
        try (InputStream input = filesystem.open(memberId, rootId, relativePath)) {
            input.skipNBytes(start);
            exchange.sendResponseHeaders(status, length);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output, length); }
        }
    }

    private String authenticateMember(HttpExchange exchange, String method, byte[] body) throws Exception {
        if (!membership.authenticate(method, exchange.getRequestURI().toASCIIString(),
                exchange.getRequestHeaders(), body)) {
            sendJson(exchange, 401, Map.of("error", "A valid active PersonalCloud network-member identity is required."));
            return null;
        }
        return exchange.getRequestHeaders().getFirst("X-PC-Node-ID");
    }

    private static boolean booleanValue(Map<String, ?> map, String key, boolean fallback) {
        Object value = map.get(key);
        if (value == null) return fallback;
        if (value instanceof Boolean bool) return bool;
        return Boolean.parseBoolean(String.valueOf(value));
    }

    private static String optionalString(Map<String, ?> map, String key) {
        Object value = map.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private static long longValue(Map<String, ?> map, String key, long fallback) {
        Object value = map.get(key);
        if (value instanceof Number number) return number.longValue();
        try { return Long.parseLong(String.valueOf(value)); } catch (Exception ignored) { return fallback; }
    }

    private static long number(Object value) {
        if (!(value instanceof Number number)) throw new IllegalArgumentException("Transfer size must be an integer.");
        return number.longValue();
    }

    private static long parseContentLength(String value) {
        try { return Long.parseLong(value); }
        catch (Exception invalid) { throw new IllegalArgumentException("A valid HTTP content length is required."); }
    }

    private static byte[] readLimitedBody(InputStream input, int maxBytes) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (bytes.size() + read > maxBytes) throw new IllegalArgumentException("Network request body exceeds the permitted size.");
            bytes.write(buffer, 0, read);
        }
        return bytes.toByteArray();
    }

    private void acceptPairing(HttpExchange exchange) throws Exception {
        String actor = clientAddress(exchange);
        if (!security.pairingAllowed(actor)) {
            sendJson(exchange, 429, Map.of("error", "Pairing attempts are temporarily rate-limited for this address."));
            return;
        }
        try {
            Map<String, String> form = readForm(exchange);
            String token = peers.acceptInvitation(form.get("code"), form.get("nodeId"), form.get("nodeName"));
            Map<String, Object> response = new LinkedHashMap<>(peers.nodeInfo());
            response.put("accessToken", token);
            security.pairingSucceeded(actor);
            audit.record("PAIR_ACCEPTED", actor, "node=" + form.get("nodeId"));
            sendJson(exchange, 200, response);
        } catch (Exception rejected) {
            security.pairingFailed(actor);
            audit.record("PAIR_REJECTED", actor, "invalid pairing attempt");
            throw rejected;
        }
    }

    private void handleAuthenticatedPeerApi(HttpExchange exchange, String path, String method) throws Exception {
        String token = bearer(exchange);
        Map<String, String> peer = peers.authenticateIncoming(token);
        if (peer == null) {
            sendJson(exchange, 401, Map.of("error", "Invalid or revoked peer token."));
            return;
        }
        String peerId = peer.get("_id");
        if ("GET".equals(method) && "/node/health".equals(path)) {
            sendJson(exchange, 200, Map.of("ok", true, "nodeId", config.nodeId(), "time", java.time.Instant.now().toString()));
            return;
        }
        if ("GET".equals(method) && "/node/shares".equals(path)) {
            sendJson(exchange, 200, Map.of("shares", grants.listForPeer(peerId)));
            return;
        }
        if ("DELETE".equals(method) && "/node/peer".equals(path)) {
            peers.removeTrustedPeer(peerId);
            sendJson(exchange, 200, Map.of("ok", true));
            return;
        }
        String prefix = "/node/shares/";
        if (!path.startsWith(prefix)) {
            sendJson(exchange, 404, Map.of("error", "Node route not found."));
            return;
        }
        String remainder = path.substring(prefix.length());
        if ("GET".equals(method) && remainder.endsWith("/archive")) {
            String grantId = decode(remainder.substring(0, remainder.length() - "/archive".length()));
            streamFolderArchive(exchange, grantId, peerId);
            return;
        }
        if ("GET".equals(method) && remainder.endsWith("/content")) {
            String shareId = decode(remainder.substring(0, remainder.length() - "/content".length()));
            String relativePath = grants.resolveSharePath(shareId, peerId);
            Map<String, Object> metadata = files.metadata(relativePath);
            streamFile(exchange, relativePath, String.valueOf(metadata.get("name")));
            return;
        }
        if ("DELETE".equals(method)) {
            String shareId = decode(remainder);
            String deletedPath = grants.deleteSharedOriginal(shareId, peerId);
            audit.record("REMOTE_FILE_DELETED", peerId, "path=" + deletedPath);
            sendJson(exchange, 200, Map.of("ok", true, "deleted", deletedPath));
            return;
        }
        sendJson(exchange, 404, Map.of("error", "Node route not found."));
    }

    private void streamManagedFile(HttpExchange exchange, String memberId, String fileId) throws Exception {
        Map<String, Object> metadata = managedStorage.statForMember(memberId, fileId);
        long size = ((Number) metadata.get("size")).longValue();
        long start = 0;
        long end = size - 1;
        int status = 200;
        long[] range = requestedRange(exchange, size);
        if (range != null) {
            start = range[0];
            end = range[1];
            status = 206;
        }
        long length = Math.max(0, end - start + 1);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Accept-Ranges", "bytes");
        headers.set("X-Content-SHA256", String.valueOf(metadata.get("sha256")));
        setAttachmentName(headers, String.valueOf(metadata.get("name")));
        if (status == 206) {
            headers.set("Content-Range", "bytes " + start + "-" + end + "/" + size);
            try (InputStream digestInput = managedStorage.openForMember(memberId, fileId)) {
                headers.set("X-Content-Range-SHA256", sha256Range(digestInput, start, length));
            }
        }
        try (InputStream input = managedStorage.openForMember(memberId, fileId)) {
            input.skipNBytes(start);
            exchange.sendResponseHeaders(status, length);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output, length); }
        }
    }

    private void streamReferenceFile(HttpExchange exchange, String memberId, String grantId, String relativePath) throws Exception {
        Map<String, Object> metadata = referenceGrants.stat(memberId, grantId, relativePath);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The requested path is not a file.");
        long size = ((Number) metadata.get("size")).longValue();
        long start = 0;
        long end = size - 1;
        int status = 200;
        long[] range = requestedRange(exchange, size);
        if (range != null) {
            start = range[0];
            end = range[1];
            status = 206;
        }
        long length = Math.max(0, end - start + 1);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Accept-Ranges", "bytes");
        headers.set("X-Content-SHA256", referenceGrants.sha256(memberId, grantId, relativePath));
        setAttachmentName(headers, String.valueOf(metadata.get("name")));
        if (status == 206) {
            headers.set("Content-Range", "bytes " + start + "-" + end + "/" + size);
            try (InputStream digestInput = referenceGrants.openFile(memberId, grantId, relativePath)) {
                headers.set("X-Content-Range-SHA256", sha256Range(digestInput, start, length));
            }
        }
        try (InputStream input = referenceGrants.openFile(memberId, grantId, relativePath)) {
            input.skipNBytes(start);
            exchange.sendResponseHeaders(status, length);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output, length); }
        }
    }

    private static String sha256Range(InputStream input, long offset, long length) throws Exception {
        try (InputStream source = input) {
            source.skipNBytes(offset);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[32 * 1024];
            long remaining = length;
            while (remaining > 0) {
                int read = source.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (read < 0) throw new java.io.IOException("File changed while calculating the requested byte-range digest.");
                if (read == 0) continue;
                digest.update(buffer, 0, read);
                remaining -= read;
            }
            return HexFormat.of().formatHex(digest.digest());
        }
    }

    private static final class RangeNotSatisfiableException extends IllegalArgumentException {
        private final long resourceSize;
        private RangeNotSatisfiableException(long resourceSize, String message) {
            super(message);
            this.resourceSize = resourceSize;
        }
    }

    private static Map<String, String> queryParameters(String rawQuery) {
        Map<String, String> result = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) return result;
        for (String pair : rawQuery.split("&")) {
            int separator = pair.indexOf('=');
            String key = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            result.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return result;
    }

    private void streamFolderArchive(HttpExchange exchange, String grantId, String peerId) throws Exception {
        String folder = grants.folderPathForPeer(grantId, peerId);
        java.util.List<String> paths = grants.folderFilesForPeer(grantId, peerId);
        String name = folder.substring(folder.lastIndexOf('/') + 1) + ".zip";
        exchange.getResponseHeaders().set("Content-Type", "application/zip");
        setAttachmentName(exchange.getResponseHeaders(), name);
        exchange.sendResponseHeaders(200, 0);
        try (java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(exchange.getResponseBody())) {
            String prefix = folder.endsWith("/") ? folder : folder + "/";
            for (String path : paths) {
                String entryName = safeZipEntryName(path.substring(prefix.length()));
                zip.putNextEntry(new java.util.zip.ZipEntry(entryName));
                try (InputStream input = files.open(path)) { copy(input, zip); }
                zip.closeEntry();
            }
            zip.finish();
        }
    }

    private void streamFile(HttpExchange exchange, String relativePath, String name) throws Exception {
        long size = ((Number) files.metadata(relativePath).get("size")).longValue();
        long start = 0;
        long end = size - 1;
        int status = 200;
        long[] range = requestedRange(exchange, size);
        if (range != null) {
            start = range[0];
            end = range[1];
            status = 206;
        }
        long length = Math.max(0, end - start + 1);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Accept-Ranges", "bytes");
        headers.set("X-Content-SHA256", files.sha256(relativePath));
        setAttachmentName(headers, name);
        if (status == 206) {
            headers.set("Content-Range", "bytes " + start + "-" + end + "/" + size);
            try (InputStream digestInput = files.open(relativePath)) {
                headers.set("X-Content-Range-SHA256", sha256Range(digestInput, start, length));
            }
        }
        try (InputStream input = files.open(relativePath)) {
            input.skipNBytes(start);
            exchange.sendResponseHeaders(status, length);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output, length); }
        }
    }

    private static long[] requestedRange(HttpExchange exchange, long size) {
        Map<String, String> query = queryParameters(exchange.getRequestURI().getRawQuery());
        boolean hasOffset = query.containsKey("offset");
        boolean hasLength = query.containsKey("length");
        if (hasOffset || hasLength) {
            if (!hasOffset || !hasLength) throw new IllegalArgumentException("Both offset and length are required for a byte-range request.");
            long offset;
            long length;
            try {
                offset = Long.parseLong(query.get("offset"));
                length = Long.parseLong(query.get("length"));
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("The byte-range offset and length must be integers.");
            }
            if (offset < 0 || offset >= size || length < 1 || length > 8L * 1024 * 1024) {
                throw new IllegalArgumentException("The requested byte range is outside the permitted bounds.");
            }
            long end;
            try { end = Math.min(size - 1, Math.addExact(offset, length - 1)); }
            catch (ArithmeticException overflow) { end = size - 1; }
            return new long[]{offset, end};
        }
        String header = exchange.getRequestHeaders().getFirst("Range");
        if (header == null || header.isBlank()) return null;
        long[] range = parseRange(header, size);
        if (range == null) throw new RangeNotSatisfiableException(size, "The requested HTTP byte range is invalid or unsatisfiable.");
        if (range[1] - range[0] + 1 > 8L * 1024 * 1024) {
            throw new RangeNotSatisfiableException(size, "A single HTTP range cannot exceed 8 MiB.");
        }
        return range;
    }

    private static long[] parseRange(String header, long size) {
        if (size <= 0 || header == null || !header.startsWith("bytes=") || header.indexOf(',') >= 0) return null;
        String value = header.substring(6).trim();
        int dash = value.indexOf('-');
        if (dash < 0) return null;
        try {
            String left = value.substring(0, dash).trim();
            String right = value.substring(dash + 1).trim();
            long start;
            long end;
            if (left.isEmpty()) {
                long suffix = Long.parseLong(right);
                if (suffix <= 0) return null;
                start = Math.max(0, size - suffix);
                end = size - 1;
            } else {
                start = Long.parseLong(left);
                end = right.isEmpty() ? size - 1 : Math.min(Long.parseLong(right), size - 1);
            }
            if (start < 0 || start >= size || end < start) return null;
            return new long[]{start, end};
        } catch (NumberFormatException invalid) {
            return null;
        }
    }

    private static Map<String, String> readForm(HttpExchange exchange) throws Exception {
        byte[] body = exchange.getRequestBody().readNBytes(MAX_FORM_BYTES + 1);
        if (body.length > MAX_FORM_BYTES) throw new IllegalArgumentException("Request body is too large.");
        String text = new String(body, StandardCharsets.UTF_8);
        Map<String, String> result = new LinkedHashMap<>();
        if (text.isBlank()) return result;
        for (String item : text.split("&")) {
            int equals = item.indexOf('=');
            String key = equals < 0 ? item : item.substring(0, equals);
            String value = equals < 0 ? "" : item.substring(equals + 1);
            result.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return result;
    }

    private static String bearer(HttpExchange exchange) {
        String value = exchange.getRequestHeaders().getFirst("Authorization");
        return value != null && value.startsWith("Bearer ") ? value.substring(7).trim() : null;
    }

    private static String decode(String value) { return URLDecoder.decode(value, StandardCharsets.UTF_8); }

    private static String string(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) throw new IllegalArgumentException("Request field '" + key + "' is required.");
        return text;
    }

    private static void sendJson(HttpExchange exchange, int status, Object value) throws Exception {
        byte[] bytes = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
    }

    private static void setAttachmentName(Headers headers, String name) {
        String encoded = URLEncoder.encode(name, StandardCharsets.UTF_8).replace("+", "%20");
        headers.set("Content-Disposition", "attachment; filename*=UTF-8''" + encoded);
    }

    private static String safeZipEntryName(String value) {
        String portable = value.replace('\\', '_');
        if (portable.isBlank() || portable.startsWith("/") || portable.matches("^[A-Za-z]:.*")) {
            throw new IllegalArgumentException("Invalid path in shared folder archive.");
        }
        for (String segment : portable.split("/")) {
            if (segment.equals(".") || segment.equals("..")) throw new IllegalArgumentException("Invalid path in shared folder archive.");
        }
        return portable;
    }

    private static void copy(InputStream input, OutputStream output) throws Exception {
        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = input.read(buffer)) != -1) output.write(buffer, 0, read);
        output.flush();
    }

    private static void copy(InputStream input, OutputStream output, long remaining) throws Exception {
        byte[] buffer = new byte[64 * 1024];
        long left = remaining;
        while (left > 0) {
            int read = input.read(buffer, 0, (int) Math.min(buffer.length, left));
            if (read < 0) throw new java.io.IOException("File changed or stream ended before the requested range was complete.");
            output.write(buffer, 0, read);
            left -= read;
        }
        output.flush();
    }

    private static String clientAddress(HttpExchange exchange) {
        return exchange.getRemoteAddress() == null ? "unknown" : exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private boolean filesystemRequestAllowed(String member, HttpExchange exchange) throws Exception {
        if (security.requestAllowed("fs:" + member, RATE_FILESYSTEM_OPS_PER_MINUTE, 60)) return true;
        sendJson(exchange, 429, Map.of("error", "Filesystem operations from this member are temporarily rate-limited."));
        return false;
    }

    private static int envInt(String name, int fallback, int minimum, int maximum) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) return fallback;
        try {
            return Math.max(minimum, Math.min(maximum, Integer.parseInt(value.trim())));
        } catch (NumberFormatException invalid) {
            return fallback;
        }
    }
}
