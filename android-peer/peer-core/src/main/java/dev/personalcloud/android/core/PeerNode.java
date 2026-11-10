package dev.personalcloud.android.core;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Android-compatible implementation of the PersonalCloud /node protocol. */
public final class PeerNode implements AutoCloseable {
    public interface Events { void onStateChanged(String message); }
    private final String nodeId;
    private final String nodeName;
    private final Path root;
    private final Path realRoot;
    private final StateStore stateStore;
    private final Events events;
    private final Map<String, Object> state;
    private final NetworkStorageService networkStorage;
    private final ResumableTransferManager transfers;
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(2, 8, 30, TimeUnit.SECONDS,
            new ArrayBlockingQueue<Runnable>(64), new ThreadPoolExecutor.AbortPolicy());
    private final LinkedHashMap<String, AttemptWindow> pairingAttempts = new LinkedHashMap<String, AttemptWindow>();
    private volatile boolean running;
    private ServerSocket server;
    private Thread acceptThread;
    private volatile NetworkMembershipClient networkMembership;
    private volatile ExternalReferenceStore externalReferenceStore;

    public PeerNode(String nodeId, String nodeName, Path root, StateStore store, Events events) throws Exception {
        this(nodeId, nodeName, root, null, "app-private", store, events);
    }

    public PeerNode(String nodeId, String nodeName, Path root, Path managedStorageRoot,
                    String managedStorageId, StateStore store, Events events) throws Exception {
        this(nodeId, nodeName, root, managedStorageRoot, managedStorageId, null, store, events);
    }

    public PeerNode(String nodeId, String nodeName, Path root, Path managedStorageRoot,
                    String managedStorageId, ManagedStorageBackend managedBackend,
                    StateStore store, Events events) throws Exception {
        this.nodeId = nodeId;
        this.nodeName = nodeName;
        this.root = root.toAbsolutePath().normalize();
        Files.createDirectories(this.root);
        this.realRoot = this.root.toRealPath();
        this.stateStore = store;
        this.events = events;
        Map<String, Object> loaded = store.load();
        this.state = loaded == null ? new LinkedHashMap<String, Object>() : loaded;
        ensureMap("invites"); ensureMap("incoming"); ensureMap("outgoing"); ensureMap("grants"); ensureMap("versions");
        persist();
        this.networkStorage = new NetworkStorageService(nodeId, this.root,
                managedStorageRoot, managedStorageId, store, managedBackend);
        this.transfers = new ResumableTransferManager(this.root.resolve("transfer-sessions"), nodeId,
                NetworkStorageService.MAX_MANAGED_FILE_BYTES,
                (transferId, uploader, relative, content, size, sha256) ->
                        this.networkStorage.receiveManagedTransfer(transferId, uploader, relative, content, size, sha256));
    }

    /** Enables the signed network-membership API without changing the legacy file-share API. */
    public synchronized void configureNetworkMembership(NetworkMembershipClient membership) {
        if (running) throw new IllegalStateException("Configure network membership before starting the Android peer.");
        this.networkMembership = membership;
    }

    /** Installs a platform-backed in-place reference adapter before the listener starts. */
    public synchronized void configureExternalReferenceStore(ExternalReferenceStore store) {
        if (running) throw new IllegalStateException("Configure external references before starting the Android peer.");
        this.externalReferenceStore = store;
    }

    public synchronized void start(InetAddress bind, int port, SSLServerSocketFactory factory) throws Exception {
        if (running) throw new IllegalStateException("Peer node is already running.");
        SSLServerSocket socket = (SSLServerSocket) factory.createServerSocket(port, 32, bind);
        socket.setNeedClientAuth(false);
        List<String> supported = new ArrayList<String>();
        for (String protocol : socket.getSupportedProtocols()) if ("TLSv1.3".equals(protocol) || "TLSv1.2".equals(protocol)) supported.add(protocol);
        if (supported.isEmpty()) { socket.close(); throw new IllegalStateException("This Android runtime does not support TLS 1.2 or newer."); }
        socket.setEnabledProtocols(supported.toArray(new String[0]));
        server = socket; running = true;
        acceptThread = new Thread(new Runnable() { public void run() { acceptLoop(); } }, "personalcloud-accept");
        acceptThread.setDaemon(true); acceptThread.start();
        events.onStateChanged("Peer node listening on " + bind.getHostAddress() + ":" + port);
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket socket = server.accept(); socket.setSoTimeout(30000);
                try { workers.execute(new Runnable() { public void run() { handle(socket); } }); }
                catch (java.util.concurrent.RejectedExecutionException overloaded) { try { socket.close(); } catch (Exception ignored) { } events.onStateChanged("Connection rejected: request queue is full."); }
            } catch (Exception error) { if (running) events.onStateChanged("Listener error: " + safe(error)); }
        }
    }

    private void handle(Socket raw) {
        try (Socket socket = raw; InputStream in = new BufferedInputStream(socket.getInputStream()); OutputStream out = new BufferedOutputStream(socket.getOutputStream())) {
            Request request = readRequest(in);
            if (request == null) return;
            Response response;
            try { response = route(request, socket.getInetAddress().getHostAddress()); }
            catch (SecurityException denied) { response = json(403, error(safe(denied))); }
            catch (IllegalArgumentException invalid) { response = json(400, error(safe(invalid))); }
            catch (Exception failure) { events.onStateChanged("Request failed: " + safe(failure)); response = json(500, error("Internal node error.")); }
            writeResponse(out, response);
        } catch (Exception error) { events.onStateChanged("Request failed: " + safe(error)); }
    }

    private Response route(Request req, String actor) throws Exception {
        String path = req.path;
        NetworkMembershipClient membership = networkMembership;
        if (membership != null && "GET".equals(req.method) && "/network/challenge".equals(path)) {
            return json(200, membership.createChallenge());
        }
        if (membership != null && "POST".equals(req.method) && "/network/enroll".equals(path)) {
            return json(200, membership.submitEnrollment(Json.object(new String(req.readBody(32 * 1024), StandardCharsets.UTF_8))));
        }
        String enrollmentStatusPrefix = "/network/enroll/status/";
        if (membership != null && "GET".equals(req.method) && path.startsWith(enrollmentStatusPrefix)) {
            return json(200, membership.enrollmentResult(decode(path.substring(enrollmentStatusPrefix.length()))));
        }
        if (membership != null && path.startsWith("/network/")) {
            if ("POST".equals(req.method) && "/network/transfers".equals(path)) {
                byte[] body = req.readBody(64 * 1024);
                if (!membership.authenticate(req.method, req.rawPath, req.headers, body)) {
                    return json(401, error("A valid active PersonalCloud network-member identity is required."));
                }
                Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
                long size;
                try { size = ((Number) request.get("size")).longValue(); }
                catch (Exception invalid) { throw new IllegalArgumentException("Transfer size must be an integer."); }
                String requestedTransferId = String.valueOf(request.getOrDefault("transferId", ""));
                Map<String, Object> created = requestedTransferId.isBlank()
                        ? transfers.create(req.headers.getOrDefault("x-pc-node-id", ""),
                                String.valueOf(request.getOrDefault("path", "")), size,
                                String.valueOf(request.getOrDefault("sha256", "")))
                        : transfers.create(req.headers.getOrDefault("x-pc-node-id", ""), requestedTransferId,
                                String.valueOf(request.getOrDefault("path", "")), size,
                                String.valueOf(request.getOrDefault("sha256", "")));
                return json(201, created);
            }
            if ("PUT".equals(req.method) && path.matches("/network/transfers/[0-9a-fA-F-]{36}/chunks/[0-9]+")) {
                String[] parts = path.substring("/network/transfers/".length()).split("/");
                String transferId = parts[0];
                int index;
                long length;
                try {
                    index = Integer.parseInt(parts[2]);
                    length = Long.parseLong(req.headers.getOrDefault("x-pc-chunk-length", ""));
                } catch (Exception invalid) { throw new IllegalArgumentException("Valid chunk index and length headers are required."); }
                String chunkHash = req.headers.getOrDefault("x-pc-chunk-sha256", "");
                Map<String, Object> metadata = new LinkedHashMap<>();
                metadata.put("transferId", transferId); metadata.put("index", index);
                metadata.put("length", length); metadata.put("sha256", chunkHash);
                byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
                if (req.contentLength != length || !membership.authenticate(req.method, req.rawPath, req.headers, signedMetadata)) {
                    return json(401, error("A valid signed member identity and matching chunk length are required."));
                }
                Map<String, Object> result = transfers.receiveChunk(req.headers.getOrDefault("x-pc-node-id", ""),
                        transferId, index, req.contentLength, chunkHash, req.bodyStream);
                return json(200, result);
            }
            if ("PUT".equals(req.method) && "/network/managed/files".equals(path)) {
                Map<String, String> query = queryParameters(req.rawPath);
                String destination = query.getOrDefault("path", "");
                long declaredSize;
                try { declaredSize = Long.parseLong(req.headers.getOrDefault("x-pc-file-length", "")); }
                catch (NumberFormatException invalid) { throw new IllegalArgumentException("A valid signed managed-file length is required."); }
                String declaredHash = req.headers.getOrDefault("x-pc-file-sha256", "");
                Map<String, Object> metadata = new LinkedHashMap<>();
                metadata.put("path", destination); metadata.put("size", declaredSize); metadata.put("sha256", declaredHash);
                byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
                if (req.contentLength != declaredSize || !membership.authenticate(req.method, req.rawPath, req.headers, signedMetadata)) {
                    return json(401, error("A valid signed member identity and matching managed-file length are required."));
                }
                String uploaderId = req.headers.getOrDefault("x-pc-node-id", "");
                Map<String, Object> stored = networkStorage.receiveManagedFile(uploaderId, destination,
                        req.bodyStream, req.contentLength, declaredSize, declaredHash);
                return json(201, stored);
            }
            byte[] signedBody = "POST".equals(req.method) ? req.readBody(64 * 1024) : new byte[0];
            if (!membership.authenticate(req.method, req.rawPath, req.headers, signedBody)) {
                return json(401, error("A valid active PersonalCloud network-member identity is required."));
            }
            String requesterId = req.headers.getOrDefault("x-pc-node-id", "");
            String transferPrefix = "/network/transfers/";
            if (path.startsWith(transferPrefix)) {
                String remainder = path.substring(transferPrefix.length());
                if ("POST".equals(req.method) && remainder.endsWith("/commit")) {
                    String id = remainder.substring(0, remainder.length() - "/commit".length());
                    return json(200, transfers.commit(requesterId, id));
                }
                if ("GET".equals(req.method) && !remainder.contains("/")) {
                    return json(200, transfers.status(requesterId, remainder));
                }
                if ("DELETE".equals(req.method) && !remainder.contains("/")) {
                    transfers.abort(requesterId, remainder);
                    return json(200, Map.of("transferId", remainder, "aborted", true));
                }
            }
            if ("GET".equals(req.method) && "/network/members".equals(path)) {
                Map<String,Object> response = map(); response.put("networkId", membership.status().get("networkId"));
                response.put("members", membership.membersForWire()); return json(200, response);
            }
            if ("GET".equals(req.method) && "/network/presence".equals(path)) {
                return json(200, membership.signedPresence());
            }
            if ("GET".equals(req.method) && "/network/references".equals(path)) {
                List<Map<String, Object>> references = new ArrayList<>(networkStorage.listReferencesForMember(requesterId));
                ExternalReferenceStore external = externalReferenceStore;
                if (external != null) references.addAll(external.listReferencesForMember(requesterId));
                return json(200, Map.of("references", references));
            }
            if ("GET".equals(req.method) && "/network/search".equals(path)) {
                Map<String, String> query = queryParameters(req.rawPath);
                int limit;
                try { limit = Integer.parseInt(query.getOrDefault("limit", "50")); }
                catch (NumberFormatException invalid) { throw new IllegalArgumentException("Search limit must be an integer."); }
                List<Map<String, Object>> results = new ArrayList<>(networkStorage.searchReferences(requesterId, query.getOrDefault("q", ""), limit));
                ExternalReferenceStore external = externalReferenceStore;
                if (external != null && results.size() < Math.max(1, Math.min(limit, 100))) {
                    results.addAll(external.searchReferences(requesterId, query.getOrDefault("q", ""),
                            Math.max(1, Math.min(limit, 100)) - results.size()));
                }
                return json(200, Map.of("results", results));
            }
            if ("GET".equals(req.method) && "/network/managed/files".equals(path)) {
                return json(200, Map.of("files", networkStorage.listManagedFilesForMember(requesterId)));
            }
            String managedPrefix = "/network/managed/files/";
            if (path.startsWith(managedPrefix)) {
                String remainder = path.substring(managedPrefix.length());
                if ("GET".equals(req.method) && remainder.endsWith("/content")) {
                    String fileId = decode(remainder.substring(0, remainder.length() - "/content".length()));
                    return storageContent(networkStorage.openManagedContent(requesterId, fileId), req.rawPath);
                }
                if ("GET".equals(req.method) && !remainder.contains("/")) {
                    return json(200, networkStorage.statManagedFile(requesterId, decode(remainder)));
                }
                if ("DELETE".equals(req.method) && !remainder.contains("/")) {
                    return json(200, networkStorage.deleteManagedFile(requesterId, decode(remainder)));
                }
            }
            String referencePrefix = "/network/references/";
            if (path.startsWith(referencePrefix)) {
                String[] segments = path.substring(referencePrefix.length()).split("/", -1);
                if (segments.length < 1 || segments.length > 2 || segments[0].isEmpty()) throw new IllegalArgumentException("Invalid reference endpoint.");
                String grantId = decode(segments[0]);
                Map<String, String> query = queryParameters(req.rawPath);
                String relativePath = query.getOrDefault("path", "");
                ExternalReferenceStore external = externalReferenceStore;
                boolean externalGrant = external != null && external.hasGrant(requesterId, grantId);
                if ("GET".equals(req.method) && segments.length == 2 && "entries".equals(segments[1])) {
                    List<Map<String, Object>> entries = externalGrant
                            ? external.browseReference(requesterId, grantId, relativePath)
                            : networkStorage.browseReference(requesterId, grantId, relativePath);
                    return json(200, Map.of("entries", entries));
                }
                if ("GET".equals(req.method) && segments.length == 2 && "stat".equals(segments[1])) {
                    return json(200, externalGrant
                            ? external.statReference(requesterId, grantId, relativePath)
                            : networkStorage.statReference(requesterId, grantId, relativePath));
                }
                if ("GET".equals(req.method) && segments.length == 2 && "content".equals(segments[1])) {
                    if (externalGrant) return storageContent(external.openReference(requesterId, grantId, relativePath), req.rawPath);
                    return storageContent(networkStorage.openReference(requesterId, grantId, relativePath), req.rawPath);
                }
                if ("DELETE".equals(req.method) && segments.length == 1) {
                    return json(200, externalGrant
                            ? external.deleteReference(requesterId, grantId, relativePath)
                            : networkStorage.deleteReference(requesterId, grantId, relativePath));
                }
            }
            if ("POST".equals(req.method) && "/network/heartbeat".equals(path)) {
                Map<String,Object> heartbeat = Json.object(new String(signedBody, StandardCharsets.UTF_8));
                String authenticatedNode = req.headers.getOrDefault("x-pc-node-id", "");
                if (!authenticatedNode.equals(String.valueOf(heartbeat.get("nodeId")))) throw new SecurityException("Heartbeat identity does not match the authenticated member.");
                membership.recordHeartbeat(authenticatedNode, String.valueOf(heartbeat.get("endpoint")), String.valueOf(heartbeat.get("nodeName")));
                return json(200, Map.of("ok", true, "receivedAt", Instant.now().toString()));
            }
            return json(404,error("Network route not found."));
        }
        if ("GET".equals(req.method) && "/node/info".equals(path)) {
            Map<String,Object> m = map(); m.put("nodeId", nodeId); m.put("nodeName", nodeName); m.put("protocol", "personalcloud-node/1"); return json(200,m);
        }
        if ("POST".equals(req.method) && "/node/pair".equals(path)) {
            Map<String,String> form = parseForm(new String(req.readBody(64 * 1024), StandardCharsets.UTF_8));
            String code = form.get("code"), remoteId = form.get("nodeId"), remoteName = form.get("nodeName");
            String token = acceptInviteRateLimited(actor, code, remoteId, remoteName);
            if (token == null) return json(429, error("Pairing temporarily rate-limited for this address."));
            Map<String,Object> m = map(); m.put("nodeId",nodeId); m.put("nodeName",nodeName); m.put("protocol","personalcloud-node/1"); m.put("accessToken",token); return json(200,m);
        }
        if (path.startsWith("/node/")) {
            String peerId = authenticate(req.headers.get("authorization"));
            if (peerId == null) return json(401, error("Invalid or revoked peer token."));
            if ("GET".equals(req.method) && "/node/health".equals(path)) { Map<String,Object> m=map();m.put("ok",true);m.put("nodeId",nodeId);m.put("time",Instant.now().toString());return json(200,m); }
            if ("GET".equals(req.method) && "/node/shares".equals(path)) { Map<String,Object> m=map();m.put("shares",sharesFor(peerId));return json(200,m); }
            if ("DELETE".equals(req.method) && "/node/peer".equals(path)) { revokeIncoming(peerId);return json(200,ok()); }
            String prefix="/node/shares/";
            if (path.startsWith(prefix) && "GET".equals(req.method) && path.endsWith("/archive")) {
                String grantId=decode(path.substring(prefix.length(),path.length()-8));
                return folderArchive(grantId,peerId);
            }
            if (path.startsWith(prefix) && "GET".equals(req.method) && path.endsWith("/content")) {
                String shareId=decode(path.substring(prefix.length(),path.length()-8));
                Resolved resolved=resolveShare(shareId,peerId,false);
                return file(resolved.path, req.headers.get("range"));
            }
            if (path.startsWith(prefix) && "DELETE".equals(req.method)) {
                String shareId=decode(path.substring(prefix.length()));
                Resolved resolved=resolveShare(shareId,peerId,true);
                snapshotBeforeDelete(resolved.path, resolved.relative); Files.delete(resolved.path); events.onStateChanged("Peer deleted shared original; recovery snapshot retained: " + resolved.relative); return json(200,ok());
            }
        }
        return json(404,error("Node route not found."));
    }

    public synchronized String createInvitation() throws Exception {
        byte[] bytes=new byte[8];new SecureRandom().nextBytes(bytes);String code=hex(bytes).toUpperCase(Locale.ROOT);
        Map<String,Object> invites=object(state.get("invites"));invites.clear();Map<String,Object> item=map();item.put("expires",System.currentTimeMillis()+600000L);invites.put(sha(code),item);persist();return code;
    }

    /** Grants one network member read/delete access to a file or directory in phone-owned storage. */
    public synchronized Map<String, Object> grantNetworkReference(String memberId, String relativePath,
                                                                    String permission) throws Exception {
        if (networkMembership == null || !networkMembership.isActiveMember(memberId)) {
            throw new SecurityException("The selected device is not an active PersonalCloud network member.");
        }
        return networkStorage.grantReference(memberId, relativePath, permission);
    }

    public synchronized Map<String, Object> grantExternalNetworkReference(String memberId, String selector,
                                                                            String permission) throws Exception {
        if (networkMembership == null || !networkMembership.isActiveMember(memberId)) {
            throw new SecurityException("The selected device is not an active PersonalCloud network member.");
        }
        ExternalReferenceStore external = externalReferenceStore;
        if (external == null) throw new IllegalStateException("This Android node has no external reference provider configured.");
        return external.grantReference(memberId, selector, permission);
    }

    public synchronized void revokeNetworkReference(String grantId) throws Exception {
        ExternalReferenceStore external = externalReferenceStore;
        if (external != null && external.hasGrantForOwner(grantId)) {
            external.revokeReference(grantId);
            return;
        }
        networkStorage.revokeReference(grantId);
    }

    private synchronized String acceptInviteRateLimited(String actor,String code,String remoteId,String remoteName)throws Exception{AttemptWindow w=pairingAttempts.get(actor);long now=System.currentTimeMillis();if(w!=null&&now-w.firstAt<=600000L&&w.failures>=5)return null;if(w!=null&&now-w.firstAt>600000L)pairingAttempts.remove(actor);try{String token=acceptInvite(code,remoteId,remoteName);pairingAttempts.remove(actor);return token;}catch(Exception invalid){AttemptWindow current=pairingAttempts.get(actor);if(current==null||now-current.firstAt>600000L)current=new AttemptWindow(now,0);current.failures++;pairingAttempts.put(actor,current);while(pairingAttempts.size()>256){String first=pairingAttempts.keySet().iterator().next();pairingAttempts.remove(first);}throw invalid;}}
    private static final class AttemptWindow{final long firstAt;int failures;AttemptWindow(long first,int count){firstAt=first;failures=count;}}

    private synchronized String acceptInvite(String code,String remoteId,String remoteName) throws Exception {
        if(code==null||!code.matches("[A-Fa-f0-9]{16}")||remoteId==null||remoteId.length()>120||remoteId.equals(nodeId))throw new IllegalArgumentException("Invalid pairing details.");
        Map<String,Object> invites=object(state.get("invites"));Object value=invites.remove(sha(code.toUpperCase(Locale.ROOT)));
        if(!(value instanceof Map)||((Number)object(value).get("expires")).longValue()<System.currentTimeMillis()){persist();throw new IllegalArgumentException("Invitation is invalid, expired or already used.");}
        String token=randomToken();Map<String,Object> peer=map();peer.put("name",cleanName(remoteName));peer.put("tokenHash",sha(token));peer.put("createdAt",Instant.now().toString());object(state.get("incoming")).put(remoteId,peer);persist();events.onStateChanged("Paired with " + cleanName(remoteName));return token;
    }

    public synchronized void pairWith(String baseUrl,String code, String trustCertificatePath) throws Exception {
        PeerConnector.PairResult result=PeerConnector.pair(baseUrl,nodeId,nodeName,code,trustCertificatePath);
        if(nodeId.equals(result.nodeId))throw new IllegalArgumentException("Cannot pair a node with itself.");
        Map<String,Object> peer=map();peer.put("name",cleanName(result.nodeName));peer.put("baseUrl",result.baseUrl);peer.put("token",result.token);peer.put("createdAt",Instant.now().toString());object(state.get("outgoing")).put(result.nodeId,peer);persist();events.onStateChanged("Paired with " + result.nodeName);
    }

    public synchronized void grant(String peerId,String relativePath,String permission) throws Exception {
        if(!object(state.get("incoming")).containsKey(peerId))throw new IllegalArgumentException("Peer has not paired with this node.");
        Path file=resolve(relativePath);if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&!Files.isDirectory(file,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Share must be a regular file or directory.");
        if(Files.isSymbolicLink(file))throw new IllegalArgumentException("Symbolic links cannot be shared.");
        String level="MODIFY".equalsIgnoreCase(permission)?"MODIFY":"VIEW";Map<String,Object> existing=object(state.get("grants"));List<String> old=new ArrayList<String>();for(Map.Entry<String,Object> e:existing.entrySet()){Map<String,Object> g=object(e.getValue());if(peerId.equals(g.get("peerId"))&&relative(file).equals(g.get("path")))old.add(e.getKey());}for(String key:old)existing.remove(key);String id=UUID.randomUUID().toString();Map<String,Object> grant=map();grant.put("peerId",peerId);grant.put("path",relative(file));grant.put("permission",level);grant.put("kind",Files.isDirectory(file)?"FOLDER":"FILE");grant.put("createdAt",Instant.now().toString());object(state.get("grants")).put(id,grant);persist();
    }

    public synchronized List<Map<String,Object>> peers() {
        List<Map<String,Object>> result=new ArrayList<Map<String,Object>>();for(String direction:new String[]{"incoming","outgoing"})for(Map.Entry<String,Object> e:object(state.get(direction)).entrySet()){Map<String,Object> m=map();m.put("nodeId",e.getKey());m.put("name",object(e.getValue()).get("name"));m.put("direction",direction.toUpperCase(Locale.ROOT));result.add(m);}return result;
    }

    public synchronized List<Map<String,Object>> outgoingShares(String peerId,String caPath) throws Exception {
        Map<String,Object> peer=object(state.get("outgoing")).get(peerId)==null?null:object(object(state.get("outgoing")).get(peerId));if(peer==null)throw new IllegalArgumentException("Unknown outgoing peer.");
        return PeerConnector.listShares(String.valueOf(peer.get("baseUrl")),String.valueOf(peer.get("token")),caPath);
    }
    public synchronized PeerConnector.RangeResult readShareRange(String peerId,String shareId,long offset,int length,String caPath) throws Exception {
        Map<String,Object> peer=object(state.get("outgoing")).get(peerId)==null?null:object(object(state.get("outgoing")).get(peerId));if(peer==null)throw new IllegalArgumentException("Unknown outgoing peer.");
        return PeerConnector.readRange(String.valueOf(peer.get("baseUrl")),String.valueOf(peer.get("token")),shareId,offset,length,caPath);
    }
    public synchronized void downloadShare(String peerId,String shareId,Path destination,String caPath) throws Exception {
        Map<String,Object> peer=object(state.get("outgoing")).get(peerId)==null?null:object(object(state.get("outgoing")).get(peerId));if(peer==null)throw new IllegalArgumentException("Unknown outgoing peer.");
        PeerConnector.download(String.valueOf(peer.get("baseUrl")),String.valueOf(peer.get("token")),shareId,destination,caPath);
    }
    public synchronized void revokePeer(String peerId,String direction,String caPath) throws Exception {
        if("INCOMING".equalsIgnoreCase(direction)){object(state.get("incoming")).remove(peerId);Map<String,Object> grants=object(state.get("grants"));List<String> remove=new ArrayList<String>();for(Map.Entry<String,Object> e:grants.entrySet())if(peerId.equals(object(e.getValue()).get("peerId")))remove.add(e.getKey());for(String id:remove)grants.remove(id);}
        else {Map<String,Object> peer=object(state.get("outgoing")).get(peerId)==null?null:object(object(state.get("outgoing")).get(peerId));if(peer!=null)PeerConnector.revoke(String.valueOf(peer.get("baseUrl")),String.valueOf(peer.get("token")),caPath);object(state.get("outgoing")).remove(peerId);}persist();
    }

    private synchronized Response folderArchive(String grantId,String peerId)throws Exception{Map<String,Object> grant=object(state.get("grants")).get(grantId)==null?null:object(object(state.get("grants")).get(grantId));if(grant==null||!peerId.equals(grant.get("peerId"))||!"FOLDER".equals(grant.get("kind")))throw new IllegalArgumentException("Shared folder not found.");Path folder=resolve(String.valueOf(grant.get("path")));if(!Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Shared folder no longer exists.");Path exportDir=root.getParent().resolve("exports");Files.createDirectories(exportDir);Path archive=exportDir.resolve(UUID.randomUUID()+".zip");int count=0;long total=0;try(ZipOutputStream zip=new ZipOutputStream(new java.io.BufferedOutputStream(Files.newOutputStream(archive)))){try(java.util.stream.Stream<Path> paths=Files.walk(folder)){java.util.Iterator<Path> it=paths.iterator();while(it.hasNext()){Path child=it.next();if(child.equals(folder)||Files.isSymbolicLink(child)||!Files.isRegularFile(child,LinkOption.NOFOLLOW_LINKS))continue;if(++count>10000)throw new IllegalArgumentException("Folder archive exceeds 10,000 files.");long size=Files.size(child);total+=size;if(total>20L*1024*1024*1024)throw new IllegalArgumentException("Folder archive exceeds 20 GiB.");String entryName=folder.relativize(child).toString().replace('\\','/');if(entryName.startsWith("/")||entryName.matches("^[A-Za-z]:.*")||entryName.contains("../")||entryName.equals(".."))throw new SecurityException("Unsafe ZIP entry path.");zip.putNextEntry(new ZipEntry(entryName));try(InputStream in=Files.newInputStream(child)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)zip.write(b,0,n);}zip.closeEntry();}}}catch(Exception e){Files.deleteIfExists(archive);throw e;}Map<String,String> h=new HashMap<String,String>();h.put("Content-Type","application/zip");h.put("Content-Disposition","attachment; filename=\""+folder.getFileName().toString().replace('\"','_')+".zip\"");return new Response(200,h,archive,true);}

    public synchronized List<String> listLocalFiles()throws Exception{List<String> files=new ArrayList<String>();try(java.util.stream.Stream<Path> paths=Files.walk(root)){java.util.Iterator<Path> it=paths.iterator();while(it.hasNext()){Path p=it.next();if(Files.isSymbolicLink(p)||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))continue;files.add(relative(p));if(files.size()>10000)throw new IllegalStateException("Local file listing exceeds 10,000 files.");}}Collections.sort(files,String.CASE_INSENSITIVE_ORDER);return files;}
    public synchronized void revokeGrant(String peerId,String relativePath)throws Exception{Map<String,Object> grants=object(state.get("grants"));List<String> ids=new ArrayList<String>();for(Map.Entry<String,Object> e:grants.entrySet()){Map<String,Object> g=object(e.getValue());if(peerId.equals(g.get("peerId"))&&relativePath.equals(g.get("path")))ids.add(e.getKey());}for(String id:ids)grants.remove(id);persist();}

    private synchronized List<Map<String,Object>> sharesFor(String peerId) throws Exception {
        List<Map<String,Object>> result=new ArrayList<Map<String,Object>>();for(Map.Entry<String,Object> e:object(state.get("grants")).entrySet()){Map<String,Object> g=object(e.getValue());if(!peerId.equals(g.get("peerId")))continue;String base=String.valueOf(g.get("path"));Path path=resolve(base);if("FOLDER".equals(g.get("kind"))){if(!Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))continue;Map<String,Object> folder=map();folder.put("shareId",e.getKey());folder.put("name",path.getFileName().toString());folder.put("path",base);folder.put("kind","FOLDER");folder.put("permission",g.get("permission"));result.add(folder);try(java.util.stream.Stream<Path> stream=Files.walk(path)){for(Path child:(Iterable<Path>)stream.filter(p->Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))::iterator){if(Files.isSymbolicLink(child))continue;String folderShareId="f_"+Base64.getUrlEncoder().withoutPadding().encodeToString((e.getKey()+"\n"+relative(child)).getBytes(StandardCharsets.UTF_8));Map<String,Object> item=shareItem(folderShareId,child,g);result.add(item);}}}else if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))result.add(shareItem(e.getKey(),path,g));}return result;
    }
    private Map<String,Object> shareItem(String grantId,Path file,Map<String,Object> grant)throws Exception{Map<String,Object> m=map();m.put("shareId",grantId);m.put("name",file.getFileName().toString());m.put("path",relative(file));m.put("kind","FILE");m.put("size",Files.size(file));m.put("permission",grant.get("permission"));return m;}
    private synchronized Resolved resolveShare(String id,String peerId,boolean delete)throws Exception{Map<String,Object> grants=object(state.get("grants"));String grantId=id;String filePath=null;if(id.startsWith("f_")){try{String decoded=new String(Base64.getUrlDecoder().decode(id.substring(2)),StandardCharsets.UTF_8);int split=decoded.indexOf('\n');if(split<1)throw new IllegalArgumentException();grantId=decoded.substring(0,split);filePath=decoded.substring(split+1);}catch(Exception bad){throw new IllegalArgumentException("Invalid folder share identifier.");}}Map<String,Object> grant=grants.get(grantId)==null?null:object(grants.get(grantId));if(grant==null||!peerId.equals(grant.get("peerId")))throw new IllegalArgumentException("Shared file not found.");if(delete&&!("MODIFY".equals(grant.get("permission"))))throw new SecurityException("This share has VIEW permission; deletion is not allowed.");if("FOLDER".equals(grant.get("kind"))&&filePath==null)throw new IllegalArgumentException("Folder archive endpoint is not available in the Android peer yet.");Path path=resolve(filePath==null?String.valueOf(grant.get("path")):filePath);if("FOLDER".equals(grant.get("kind"))&&!path.startsWith(resolve(String.valueOf(grant.get("path")))))throw new SecurityException("Requested file is outside the shared folder.");if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Shared file no longer exists.");return new Resolved(path,relative(path));}
    private synchronized String authenticate(String header)throws Exception{if(header==null||!header.startsWith("Bearer "))return null;String candidate=sha(header.substring(7));for(Map.Entry<String,Object> e:object(state.get("incoming")).entrySet())if(MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8),String.valueOf(object(e.getValue()).get("tokenHash")).getBytes(StandardCharsets.UTF_8)))return e.getKey();return null;}
    private synchronized void revokeIncoming(String peerId)throws Exception{object(state.get("incoming")).remove(peerId);Map<String,Object> grants=object(state.get("grants"));List<String> ids=new ArrayList<String>();for(Map.Entry<String,Object> e:grants.entrySet())if(peerId.equals(object(e.getValue()).get("peerId")))ids.add(e.getKey());for(String id:ids)grants.remove(id);persist();}
    private Response file(Path path,String rangeHeader)throws Exception{
        long size=Files.size(path);
        Map<String,String> headers=new HashMap<String,String>();
        headers.put("Content-Type","application/octet-stream");
        headers.put("Content-Disposition","attachment; filename=\""+path.getFileName().toString().replaceAll("[\r\n\"]","_")+"\"");
        headers.put("Accept-Ranges","bytes");
        if(rangeHeader==null||rangeHeader.trim().length()==0){headers.put("X-Content-SHA256",sha256File(path));return new Response(200,headers,path,0,size,false);}
        long[] range=parseRange(rangeHeader,size);
        if(range==null){
            Map<String,String> invalidHeaders=new HashMap<String,String>();
            invalidHeaders.put("Content-Range","bytes */"+size);
            invalidHeaders.put("Accept-Ranges","bytes");
            return new Response(416,invalidHeaders,Json.stringify(error("Requested byte range is not satisfiable.")).getBytes(StandardCharsets.UTF_8));
        }
        long offset=range[0],length=range[1]-range[0]+1;
        headers.put("Content-Range","bytes "+range[0]+"-"+range[1]+"/"+size);
        headers.put("X-Content-Range-SHA256",sha256Range(path,offset,length));
        return new Response(206,headers,path,offset,length,false);
    }

    private static String sha256Range(Path path,long offset,long length)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(java.nio.channels.FileChannel channel=java.nio.channels.FileChannel.open(path,java.nio.file.StandardOpenOption.READ)){
            channel.position(offset);java.nio.ByteBuffer buffer=java.nio.ByteBuffer.allocate(65536);long remaining=length;
            while(remaining>0){buffer.clear();buffer.limit((int)Math.min(buffer.capacity(),remaining));int n=channel.read(buffer);if(n<0)throw new EOFException("File changed while calculating range digest.");if(n==0)continue;digest.update(buffer.array(),0,n);remaining-=n;}
        }
        return hex(digest.digest());
    }

    private static long[] parseRange(String header,long size){
        if(header==null||!header.startsWith("bytes=")||header.indexOf(',')>=0||size<=0)return null;
        String value=header.substring(6).trim();
        int separator=value.indexOf('-');
        if(separator<0||separator!=value.lastIndexOf('-'))return null;
        String first=value.substring(0,separator).trim(),last=value.substring(separator+1).trim();
        try{
            long start,end;
            if(first.length()==0){
                long suffix=Long.parseLong(last);
                if(suffix<=0)return null;
                start=Math.max(0,size-suffix);end=size-1;
            }else{
                start=Long.parseLong(first);
                if(start<0||start>=size)return null;
                end=last.length()==0?size-1:Long.parseLong(last);
                if(end<start)return null;
                end=Math.min(end,size-1);
            }
            return new long[]{start,end};
        }catch(NumberFormatException invalid){return null;}
    }

    private void snapshotBeforeDelete(Path original,String relative)throws Exception{if(Files.size(original)>10L*1024*1024*1024)throw new IllegalArgumentException("This file exceeds the Android node's 10 GiB recovery snapshot budget; deletion is blocked to preserve recoverability.");Path versions=root.getParent().resolve("versions");Files.createDirectories(versions);String id=UUID.randomUUID().toString();Path blob=versions.resolve(id+".blob");Files.copy(original,blob);Map<String,Object> record=map();record.put("id",id);record.put("path",relative);record.put("createdAt",Instant.now().toString());record.put("size",Files.size(blob));Map<String,Object> history=object(state.get("versions"));history.put(id,record);List<String> same=new ArrayList<String>();for(Map.Entry<String,Object> e:history.entrySet())if(relative.equals(object(e.getValue()).get("path")))same.add(e.getKey());if(same.size()>20){Collections.sort(same,new Comparator<String>(){public int compare(String a,String b){return String.valueOf(object(history.get(a)).get("createdAt")).compareTo(String.valueOf(object(history.get(b)).get("createdAt")));}});while(same.size()>20){String old=same.remove(0);history.remove(old);Files.deleteIfExists(versions.resolve(old+".blob"));}}long total=0;for(String snapshotId:(Iterable<String>)history.keySet()){Path snapshotBlob=versions.resolve(snapshotId+".blob");if(Files.exists(snapshotBlob))total+=Files.size(snapshotBlob);}while(total>10L*1024*1024*1024&&!history.isEmpty()){String oldest=null;long oldestTime=Long.MAX_VALUE;for(Map.Entry<String,Object> e:history.entrySet()){long time=0;try{time=Instant.parse(String.valueOf(object(e.getValue()).get("createdAt"))).toEpochMilli();}catch(Exception ignored){}if(time<oldestTime){oldestTime=time;oldest=e.getKey();}}if(oldest==null)break;Path oldestBlob=versions.resolve(oldest+".blob");if(Files.exists(oldestBlob)){long size=Files.size(oldestBlob);Files.deleteIfExists(oldestBlob);total-=size;}history.remove(oldest);}persist();}
    private static String sha256File(Path path)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");try(InputStream in=Files.newInputStream(path)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}return hex(d.digest());}
    private Path resolve(String relative)throws Exception{if(relative==null||relative.length()==0||relative.indexOf('\0')>=0)throw new IllegalArgumentException("Invalid relative path.");Path supplied=java.nio.file.Paths.get(relative);if(supplied.isAbsolute())throw new IllegalArgumentException("Absolute paths are not allowed.");Path target=root.resolve(supplied).normalize();if(!target.startsWith(root)||target.equals(root))throw new IllegalArgumentException("Path escapes storage root.");Path current=root;for(Path part:root.relativize(target)){current=current.resolve(part);if(Files.isSymbolicLink(current))throw new IllegalArgumentException("Symbolic links are not allowed.");}if(Files.exists(target,LinkOption.NOFOLLOW_LINKS)&&!target.toRealPath().startsWith(realRoot))throw new IllegalArgumentException("Path escapes storage root.");return target;}
    private String relative(Path path){return root.relativize(path.toAbsolutePath().normalize()).toString().replace('\\','/');}
    private synchronized void persist()throws Exception{stateStore.save(state);}
    private void ensureMap(String key){if(!(state.get(key) instanceof Map))state.put(key,map());}
    @SuppressWarnings("unchecked")private static Map<String,Object> object(Object value){return value instanceof Map?(Map<String,Object>)value:new LinkedHashMap<String,Object>();}
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    private static Map<String,Object> error(String text){Map<String,Object> m=map();m.put("error",text);return m;}
    private static Map<String,Object> ok(){Map<String,Object> m=map();m.put("ok",true);return m;}
    private static String cleanName(String name){if(name==null||name.trim().length()==0)return "Unnamed Android device";return name.length()>80?name.substring(0,80):name;}
    private static String sha(String text)throws Exception{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
    private static String randomToken(){byte[] b=new byte[32];new SecureRandom().nextBytes(b);return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
    private static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format(Locale.ROOT,"%02x",v&255));return s.toString();}
    private static String decode(String s){return java.net.URLDecoder.decode(s.replace("+","%2B"),StandardCharsets.UTF_8);}
    private static String safe(Exception e){return e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
    private static Map<String,String> parseForm(String body){Map<String,String> m=new HashMap<String,String>();for(String p:body.split("&")){int i=p.indexOf('=');if(i>0)m.put(decode(p.substring(0,i)),decode(p.substring(i+1)));}return m;}

    private static Request readRequest(InputStream input)throws Exception{
        String line=readLine(input,8192);if(line==null)return null;String[] first=line.split(" ");if(first.length!=3)throw new IOException("Malformed HTTP request line.");String method=first[0],target=first[1];int q=target.indexOf('?');String path=q<0?target:target.substring(0,q);Map<String,String> headers=new HashMap<String,String>();int total=0;while(true){String h=readLine(input,8192);if(h==null)throw new EOFException();if(h.length()==0)break;total+=h.length();if(total>16384)throw new IOException("Headers too large.");int colon=h.indexOf(':');if(colon>0)headers.put(h.substring(0,colon).trim().toLowerCase(Locale.ROOT),h.substring(colon+1).trim());}if(!headers.getOrDefault("transfer-encoding","").isEmpty())throw new IOException("Chunked request bodies are not supported; use Content-Length.");long length;try{length=Long.parseLong(headers.getOrDefault("content-length","0"));}catch(NumberFormatException invalid){throw new IOException("Invalid Content-Length.");}if(length<0||length>NetworkStorageService.MAX_MANAGED_FILE_BYTES)throw new IOException("Request body exceeds the Android node transfer limit.");return new Request(method,path,target,headers,input,length);
    }
    private static String readLine(InputStream in,int max)throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();int c;while((c=in.read())!=-1){if(c=='\n')break;if(c!='\r')b.write(c);if(b.size()>max)throw new IOException("HTTP line too long.");}if(c==-1&&b.size()==0)return null;return new String(b.toByteArray(),StandardCharsets.US_ASCII);}
    private static void writeResponse(OutputStream out,Response r)throws Exception{
        try{
            String reason=r.status==200?"OK":r.status==201?"Created":r.status==206?"Partial Content":r.status==401?"Unauthorized":r.status==403?"Forbidden":r.status==404?"Not Found":r.status==400?"Bad Request":r.status==416?"Range Not Satisfiable":"Error";
            long length=r.file!=null||r.externalContent!=null?r.fileLength:r.body.length;
            StringBuilder h=new StringBuilder("HTTP/1.1 ").append(r.status).append(' ').append(reason).append("\r\nConnection: close\r\nContent-Length: ").append(length).append("\r\n");
            for(Map.Entry<String,String> e:r.headers.entrySet())h.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            h.append("\r\n");out.write(h.toString().getBytes(StandardCharsets.US_ASCII));
            if(r.file!=null){
                try(java.nio.channels.FileChannel channel=java.nio.channels.FileChannel.open(r.file,java.nio.file.StandardOpenOption.READ)){
                    channel.position(r.fileOffset);java.nio.ByteBuffer buffer=java.nio.ByteBuffer.allocate(65536);long remaining=r.fileLength;
                    while(remaining>0){buffer.clear();buffer.limit((int)Math.min(buffer.capacity(),remaining));int n=channel.read(buffer);if(n<0)throw new EOFException("File changed while a response was being streamed.");if(n==0)continue;out.write(buffer.array(),0,n);remaining-=n;}
                }
            }else if(r.externalContent!=null){
                try(InputStream content=r.externalContent.openRange(r.fileOffset,r.fileLength)){
                    byte[] buffer=new byte[65536];long remaining=r.fileLength;
                    while(remaining>0){int n=content.read(buffer,0,(int)Math.min(buffer.length,remaining));if(n<0)throw new EOFException("External document changed or ended while a response was being streamed.");if(n==0)continue;out.write(buffer,0,n);remaining-=n;}
                }
            }else out.write(r.body);
            out.flush();
        }finally{if(r.deleteAfter&&r.file!=null)Files.deleteIfExists(r.file);}
    }

    private static Response json(int status,Object value){Map<String,String> h=new HashMap<String,String>();h.put("Content-Type","application/json; charset=utf-8");return new Response(status,h,Json.stringify(value).getBytes(StandardCharsets.UTF_8));}
    private static Response storageContent(Path file, String rawPath) throws Exception {
        long size = Files.size(file);
        Map<String, String> query = queryParameters(rawPath);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/octet-stream");
        headers.put("Accept-Ranges", "bytes");
        if (query.containsKey("offset") || query.containsKey("length")) {
            long offset; int requested;
            try { offset = Long.parseLong(query.getOrDefault("offset", "-1")); requested = Integer.parseInt(query.getOrDefault("length", "-1")); }
            catch (NumberFormatException invalid) { throw new IllegalArgumentException("Invalid byte range parameters."); }
            if (offset < 0 || requested < 1 || requested > NetworkStorageService.MAX_RANGE_BYTES || offset >= size) {
                headers.put("Content-Range", "bytes */" + size);
                return new Response(416, headers, Json.stringify(error("Requested byte range is not satisfiable.")).getBytes(StandardCharsets.UTF_8));
            }
            long length = Math.min((long) requested, size - offset);
            long end = offset + length - 1;
            headers.put("Content-Range", "bytes " + offset + "-" + end + "/" + size);
            headers.put("X-Content-Range-SHA256", sha256Range(file, offset, length));
            return new Response(206, headers, file, offset, length, false);
        }
        headers.put("X-Content-SHA256", sha256File(file));
        return new Response(200, headers, file, 0, size, false);
    }

    private static Response storageContent(ExternalReferenceStore.NetworkReferenceContent content, String rawPath) throws Exception {
        long size=content.size();
        if(size<0)throw new IllegalArgumentException("The external document provider did not report a stable file size.");
        Map<String,String> headers=new LinkedHashMap<>();headers.put("Content-Type","application/octet-stream");headers.put("Accept-Ranges","bytes");
        Map<String,String> query=queryParameters(rawPath);
        if(query.containsKey("offset")||query.containsKey("length")){
            long offset;int requested;
            try{offset=Long.parseLong(query.getOrDefault("offset","-1"));requested=Integer.parseInt(query.getOrDefault("length","-1"));}
            catch(NumberFormatException invalid){throw new IllegalArgumentException("Invalid byte range parameters.");}
            if(offset<0||requested<1||requested>NetworkStorageService.MAX_RANGE_BYTES||offset>=size){
                headers.put("Content-Range","bytes */"+size);
                return new Response(416,headers,Json.stringify(error("Requested byte range is not satisfiable.")).getBytes(StandardCharsets.UTF_8));
            }
            long length=Math.min((long)requested,size-offset),end=offset+length-1;
            headers.put("Content-Range","bytes "+offset+"-"+end+"/"+size);
            headers.put("X-Content-Range-SHA256",sha256ExternalRange(content,offset,length));
            return new Response(206,headers,content,offset,length);
        }
        headers.put("X-Content-SHA256",sha256ExternalRange(content,0,size));
        return new Response(200,headers,content,0,size);
    }

    private static String sha256ExternalRange(ExternalReferenceStore.NetworkReferenceContent content,long offset,long length)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");long remaining=length;
        try(InputStream input=content.openRange(offset,length)){
            byte[] buffer=new byte[65536];
            while(remaining>0){int read=input.read(buffer,0,(int)Math.min(buffer.length,remaining));if(read<0)throw new EOFException("External document ended before the requested range was hashed.");if(read==0)continue;digest.update(buffer,0,read);remaining-=read;}
            if(input.read()!=-1)throw new IOException("External document returned more bytes than its declared range.");
        }
        return hex(digest.digest());
    }

    private static Map<String, String> queryParameters(String rawPath) {
        int index = rawPath.indexOf('?');
        if (index < 0 || index == rawPath.length() - 1) return Collections.emptyMap();
        Map<String, String> result = new LinkedHashMap<>();
        for (String pair : rawPath.substring(index + 1).split("&")) {
            int split = pair.indexOf('=');
            String key = decode(split < 0 ? pair : pair.substring(0, split));
            String value = decode(split < 0 ? "" : pair.substring(split + 1));
            result.put(key, value);
        }
        return result;
    }
    public synchronized void close(){running=false;try{if(server!=null)server.close();}catch(Exception ignored){}workers.shutdownNow();}
    private static final class Request{final String method,path,rawPath;final Map<String,String>headers;final InputStream bodyStream;final long contentLength;private boolean bodyRead;Request(String m,String p,String raw,Map<String,String>h,InputStream input,long length){method=m;path=p;rawPath=raw;headers=h;bodyStream=input;contentLength=length;}synchronized byte[] readBody(int max)throws Exception{if(bodyRead)throw new IllegalStateException("HTTP request body was already consumed.");if(contentLength>max)throw new IOException("Request body exceeds the endpoint limit.");if(contentLength>Integer.MAX_VALUE)throw new IOException("Request body is too large.");byte[] result=new byte[(int)contentLength];int offset=0;while(offset<result.length){int read=bodyStream.read(result,offset,result.length-offset);if(read<0)throw new EOFException("HTTP request body ended before Content-Length.");offset+=read;}bodyRead=true;return result;}}
    private static final class Response{
        final int status;final Map<String,String>headers;final byte[]body;final Path file;final ExternalReferenceStore.NetworkReferenceContent externalContent;final long fileOffset,fileLength;final boolean deleteAfter;
        Response(int s,Map<String,String>h,byte[]b){status=s;headers=h;body=b;file=null;externalContent=null;fileOffset=0;fileLength=0;deleteAfter=false;}
        Response(int s,Map<String,String>h,Path f){this(s,h,f,0,length(f),false);}
        Response(int s,Map<String,String>h,Path f,boolean d){this(s,h,f,0,length(f),d);}
        Response(int s,Map<String,String>h,Path f,long offset,long length,boolean d){status=s;headers=h;body=new byte[0];file=f;externalContent=null;fileOffset=offset;fileLength=length;deleteAfter=d;}
        Response(int s,Map<String,String>h,ExternalReferenceStore.NetworkReferenceContent content,long offset,long length){status=s;headers=h;body=new byte[0];file=null;externalContent=content;fileOffset=offset;fileLength=length;deleteAfter=false;}
        private static long length(Path path){try{return Files.size(path);}catch(Exception unavailable){return 0;}}
    }
    private static final class Resolved{final Path path;final String relative;Resolved(Path p,String r){path=p;relative=r;}}

}
