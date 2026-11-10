package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Periodic direct-member heartbeat and signed membership-catalogue exchange. */
public final class DeviceCatalogueService implements AutoCloseable {
    private final AppConfig config;
    private final NetworkMembershipService membership;
    private final NetworkPeerClient client;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "personalcloud-device-catalogue");
        thread.setDaemon(true);
        return thread;
    });
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean synchronizing = new AtomicBoolean();
    private final ExecutorService peerWorkers = Executors.newFixedThreadPool(4, task -> {
        Thread thread = new Thread(task, "personalcloud-catalogue-peer");
        thread.setDaemon(true);
        return thread;
    });

    public DeviceCatalogueService(AppConfig config, NetworkMembershipService membership) throws Exception {
        this.config = config;
        this.membership = membership;
        this.client = new NetworkPeerClient();
    }

    public void start() {
        if (!started.compareAndSet(false, true)) return;
        scheduler.scheduleWithFixedDelay(this::syncSafely, 3, 20, TimeUnit.SECONDS);
    }

    /** Runs one bounded-concurrency catalogue pass; exposed for deterministic integration tests. */
    public void synchronizeOnce() throws Exception {
        if (!Boolean.TRUE.equals(membership.status().get("joined"))) return;
        if (!synchronizing.compareAndSet(false, true)) {
            throw new IllegalStateException("A PersonalCloud catalogue synchronization pass is already running.");
        }
        try {
            // A device may have moved networks since its membership record was
            // first created. Reconcile only our own endpoint before advertising
            // the catalogue or sending this node's heartbeat.
            membership.reconcileLocalEndpoint();
            List<Map<String, Object>> members = membership.members();
            List<Future<?>> tasks = new java.util.ArrayList<>();
            for (Map<String, Object> member : members) {
                String nodeId = String.valueOf(member.get("nodeId"));
                if (nodeId.equals(config.nodeId()) || !"ACTIVE".equals(String.valueOf(member.get("status")))) continue;
                tasks.add(peerWorkers.submit(() -> synchronizeMember(member)));
            }
            for (Future<?> task : tasks) {
                try { task.get(); }
                catch (ExecutionException failure) {
                    Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                    System.err.println("PersonalCloud catalogue peer task failed: " + safeFailure(cause));
                }
            }
        } finally {
            synchronizing.set(false);
        }
    }

    private void synchronizeMember(Map<String, Object> member) {
        String nodeId = String.valueOf(member.get("nodeId"));
        try {
            String endpoint = String.valueOf(member.get("endpoint"));
            if (endpoint.isBlank() || "null".equals(endpoint)) {
                membership.markOffline(nodeId);
                return;
            }
            Map<String, Object> presence = client.getJson(endpoint, "/network/presence", membership);
            membership.verifyPresence(presence, nodeId, endpoint);
            String remoteName = String.valueOf(presence.get("nodeName"));
            String remoteEndpoint = String.valueOf(presence.get("endpoint"));
            membership.recordHeartbeat(nodeId, remoteEndpoint, remoteName);
            Map<String, Object> remoteCatalogue = client.getJson(endpoint, "/network/members", membership);
            String localNetworkId = String.valueOf(membership.status().get("networkId"));
            if (!localNetworkId.equals(String.valueOf(remoteCatalogue.get("networkId")))) {
                throw new SecurityException("Peer catalogue belongs to a different PersonalCloud network.");
            }
            Object remoteMembers = remoteCatalogue.get("members");
            if (!(remoteMembers instanceof List<?> list)) {
                throw new SecurityException("Peer catalogue omitted its member list.");
            }
            membership.importMembers(list);
            Map<String, Object> heartbeat = new LinkedHashMap<>();
            heartbeat.put("nodeId", config.nodeId());
            heartbeat.put("nodeName", config.nodeName());
            heartbeat.put("endpoint", membership.localEndpointForProtocol());
            heartbeat.put("sentAt", Instant.now().toString());
            client.postJson(endpoint, "/network/heartbeat", heartbeat, membership);
        } catch (Exception unreachable) {
            try { membership.markOffline(nodeId); }
            catch (Exception persistenceFailure) { unreachable.addSuppressed(persistenceFailure); }
            System.err.println("PersonalCloud member " + nodeId + " sync failed: " + safeFailure(unreachable));
        }
    }

    private static String safeFailure(Throwable failure) {
        String message = failure.getMessage();
        String value = message == null || message.isBlank() ? failure.getClass().getSimpleName() : message;
        return value.substring(0, Math.min(200, value.length()));
    }

    private void syncSafely() {
        try { synchronizeOnce(); }
        catch (Exception failure) {
            System.err.println("PersonalCloud device catalogue synchronization failed: " +
                    (failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage()));
        }
    }

    @Override public void close() {
        scheduler.shutdownNow();
        peerWorkers.shutdownNow();
        started.set(false);
    }
}
