package dev.personalcloud.android.core;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Regression tests for liveness expiry, stale-catalogue merge and lock-free outbound sync. */
public final class NetworkMembershipConcurrencyTest {
    private static final String PASSWORD = "Correct-Horse-2026";

    public static void main(String[] args) throws Exception {
        MemoryStore rootStore = new MemoryStore();
        BlockingTransport transport = new BlockingTransport(2);
        NetworkMembershipClient root = new NetworkMembershipClient(rootStore, "root-node-0001",
                "Root Device", "http://127.0.0.1:18881", transport);
        root.bootstrap("PersonalCloud Test", "owner", PASSWORD.toCharArray());

        MemoryStore firstPeerStore = new MemoryStore();
        NetworkIdentity firstPeer = new NetworkIdentity(firstPeerStore);
        enroll(root, firstPeer, "peer-node-0001", "Peer One", "http://127.0.0.1:18882");

        MemoryStore secondPeerStore = new MemoryStore();
        NetworkIdentity secondPeer = new NetworkIdentity(secondPeerStore);
        enroll(root, secondPeer, "peer-node-0002", "Peer Two", "http://127.0.0.1:18883");

        root.recordHeartbeat("peer-node-0001", "http://127.0.0.1:18882", "Peer One");
        root.recordHeartbeat("peer-node-0002", "http://127.0.0.1:18883", "Peer Two");
        check(isOnline(root.members(), "peer-node-0001"), "fresh direct heartbeat must mark a member online");

        // A device endpoint is mutable routing state, not part of its immutable
        // Ed25519 membership certificate. A network change must update only the
        // local member's endpoint and preserve every remote member record.
        Map<String, Object> beforeMove = rootStore.loadDomain("network");
        String rootCertificateBeforeMove = String.valueOf(beforeMove.get("localCertificate"));
        Map<String, Object> move = root.updateLocalEndpoint("https://10.0.0.10:18881");
        check(Boolean.TRUE.equals(move.get("changed")), "a changed local address must be accepted");
        check("https://10.0.0.10:18881".equals(root.status().get("endpoint")),
                "status must expose the newly active endpoint");
        check("https://10.0.0.10:18881".equals(memberEndpoint(root.membersForWire(), "root-node-0001")),
                "the local member catalogue row must advertise the new endpoint");
        check("http://127.0.0.1:18882".equals(memberEndpoint(root.membersForWire(), "peer-node-0001")),
                "changing the local endpoint must not rewrite a remote member endpoint");
        check(rootCertificateBeforeMove.equals(String.valueOf(rootStore.loadDomain("network").get("localCertificate"))),
                "endpoint movement must not rewrite the signed local membership certificate");
        check(!Boolean.TRUE.equals(root.updateLocalEndpoint("https://10.0.0.10:18881").get("changed")),
                "repeated endpoint reconciliation must be idempotent");
        check("https://10.0.0.10:18881".equals(root.createChallenge().get("issuerEndpoint")),
                "new enrollment challenges must advertise the current mutable endpoint");

        // A stale catalogue may not roll back a more recent locally-observed heartbeat.
        List<Map<String, Object>> staleWire = mutableRows(root.membersForWire());
        for (Map<String, Object> row : staleWire) {
            if ("peer-node-0001".equals(row.get("nodeId"))) {
                // Even a catalogue timestamp slightly newer than the local timestamp does
                // not supersede a direct connection verified by this node moments ago.
                row.put("lastSeenEpoch", Instant.now().getEpochSecond() + 30);
                row.put("online", false);
            }
        }
        root.importMembers(staleWire);
        check(isOnline(root.members(), "peer-node-0001"),
                "stale catalogue metadata must not overwrite a newer local heartbeat");

        // Simulate process restart with an old persisted online flag.
        Map<String, Object> persisted = rootStore.loadDomain("network");
        Map<String, Object> members = object(persisted.get("members"));
        Map<String, Object> oldPeer = object(members.get("peer-node-0001"));
        oldPeer.put("online", true);
        oldPeer.put("lastSeenEpoch", Instant.now().getEpochSecond() - 300);
        members.put("peer-node-0001", oldPeer);
        rootStore.saveDomain("network", persisted);
        NetworkMembershipClient restored = new NetworkMembershipClient(rootStore, "root-node-0001",
                "Root Device", "http://127.0.0.1:18881", transport);
        check(!isOnline(restored.members(), "peer-node-0001"),
                "persisted online state must expire when the last heartbeat is stale");
        check(!isOnline(restored.membersForWire(), "peer-node-0001"),
                "stale online state must not be propagated to other members");

        // Hold two outbound peer requests open. Both must be in flight at once, while the
        // membership monitor remains available to local status and inbound authentication.
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try {
            Future<Map<String, Object>> sync = caller.submit(() -> restored.synchronizeOnce(null));
            check(transport.awaitBoth(3, TimeUnit.SECONDS),
                    "catalogue sync must work on several peers concurrently instead of serially");
            long start = System.nanoTime();
            restored.status();
            boolean authenticated = restored.authenticate("GET", "/network/members", Map.of(), new byte[0]);
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            check(!authenticated, "an empty signature must remain rejected during synchronization");
            check(elapsedMillis < 500,
                    "local status and inbound authentication must not wait for an outbound peer timeout");
            check(transport.maximumConcurrent.get() >= 2,
                    "the bounded worker pool must overlap independent member synchronization requests");
            transport.release();
            Map<String, Object> result = sync.get(5, TimeUnit.SECONDS);
            check(number(result.get("attempted")) == 2, "sync result must report both active peers");
            check(((List<?>) result.get("offline")).size() == 2,
                    "simulated unavailable peers must be individually reported offline");
        } finally {
            transport.release();
            caller.shutdownNow();
            caller.awaitTermination(2, TimeUnit.SECONDS);
        }

        System.out.println("PASS: Android catalogue synchronization is bounded-concurrent, preserves local responsiveness and fresh heartbeats, expires stale peers, and safely reconciles the mutable local endpoint without changing signed identity or remote endpoints.");
    }

    private static void enroll(NetworkMembershipClient root, NetworkIdentity peer, String nodeId,
                               String nodeName, String endpoint) throws Exception {
        Map<String, Object> challenge = root.createChallenge();
        byte[] salt = Base64.getDecoder().decode(String.valueOf(challenge.get("salt")));
        byte[] verifier = derivePassword(PASSWORD.toCharArray(), salt);
        String networkId = String.valueOf(challenge.get("networkId"));
        String account = String.valueOf(challenge.get("accountName"));
        String challengeId = String.valueOf(challenge.get("challengeId"));
        String publicKey = peer.publicKeyBase64();
        String proofInput = String.join("\n", networkId, account, challengeId,
                String.valueOf(challenge.get("nonce")), nodeId, nodeName, publicKey, endpoint);
        String proof = Base64.getEncoder().encodeToString(hmac(verifier, proofInput.getBytes(StandardCharsets.UTF_8)));
        String signaturePayload = String.join("\n", networkId, nodeId, nodeName, publicKey, endpoint,
                challengeId, proof);
        String signature = Base64.getEncoder().encodeToString(
                peer.sign(signaturePayload.getBytes(StandardCharsets.UTF_8)));
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("networkId", networkId); request.put("accountName", account);
        request.put("challengeId", challengeId); request.put("nodeId", nodeId);
        request.put("nodeName", nodeName); request.put("publicKey", publicKey);
        request.put("endpoint", endpoint); request.put("proof", proof); request.put("signature", signature);
        Map<String, Object> submitted = root.submitEnrollment(request);
        Map<String, Object> approval = root.approve(String.valueOf(submitted.get("requestId")));
        check("APPROVED".equals(approval.get("status")), "test peer must be approval-gated into the network");
        java.util.Arrays.fill(verifier, (byte) 0);
    }

    private static byte[] derivePassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 310_000, 256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); java.util.Arrays.fill(password, '\0'); }
    }

    private static byte[] hmac(byte[] key, byte[] input) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input);
    }

    private static String memberEndpoint(List<Map<String, Object>> members, String nodeId) {
        for (Map<String, Object> member : members) {
            if (nodeId.equals(member.get("nodeId"))) return String.valueOf(member.get("endpoint"));
        }
        return "";
    }

    private static boolean isOnline(List<Map<String, Object>> members, String nodeId) {
        for (Map<String, Object> member : members) {
            if (nodeId.equals(member.get("nodeId"))) return Boolean.TRUE.equals(member.get("online"));
        }
        return false;
    }

    private static List<Map<String, Object>> mutableRows(List<Map<String, Object>> rows) {
        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> row : rows) result.add(new LinkedHashMap<String, Object>(row));
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) { return (Map<String, Object>) value; }
    private static long number(Object value) { return ((Number) value).longValue(); }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class BlockingTransport implements NetworkMembershipClient.CatalogueTransport {
        private final CountDownLatch entered;
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger maximumConcurrent = new AtomicInteger();

        private BlockingTransport(int expectedPeers) { entered = new CountDownLatch(expectedPeers); }

        @Override public Map<String, Object> getSignedJson(String baseUrl, String path,
                Map<String, String> headers, String trustedCaPath) throws Exception {
            int now = active.incrementAndGet();
            maximumConcurrent.accumulateAndGet(now, Math::max);
            entered.countDown();
            try {
                if (!release.await(4, TimeUnit.SECONDS)) throw new IOException("test transport release timed out");
                throw new IOException("simulated peer unavailable");
            } finally { active.decrementAndGet(); }
        }

        @Override public Map<String, Object> postSignedJson(String baseUrl, String path,
                Map<String, Object> body, Map<String, String> headers, String trustedCaPath) throws Exception {
            throw new IOException("unexpected heartbeat POST");
        }

        private boolean awaitBoth(long timeout, TimeUnit unit) throws InterruptedException {
            return entered.await(timeout, unit);
        }
        private void release() { release.countDown(); }
    }

    private static final class MemoryStore implements StateStore {
        private Map<String, Object> legacy = new LinkedHashMap<String, Object>();
        private final Map<String, Map<String, Object>> domains = new LinkedHashMap<String, Map<String, Object>>();
        @Override public synchronized Map<String, Object> load() { return copy(legacy); }
        @Override public synchronized void save(Map<String, Object> state) { legacy = copy(state); }
        @Override public synchronized Map<String, Object> loadDomain(String domain) {
            return copy(domains.getOrDefault(domain, new LinkedHashMap<String, Object>()));
        }
        @Override public synchronized void saveDomain(String domain, Map<String, Object> state) {
            domains.put(domain, copy(state));
        }
        @SuppressWarnings("unchecked")
        private static Map<String, Object> copy(Map<String, Object> source) {
            Map<String, Object> result = new LinkedHashMap<String, Object>();
            for (Map.Entry<String, Object> entry : source.entrySet()) result.put(entry.getKey(), copyValue(entry.getValue()));
            return result;
        }
        @SuppressWarnings("unchecked")
        private static Object copyValue(Object value) {
            if (value instanceof Map<?, ?> map) {
                Map<String, Object> result = new LinkedHashMap<String, Object>();
                for (Map.Entry<?, ?> entry : map.entrySet()) result.put(String.valueOf(entry.getKey()), copyValue(entry.getValue()));
                return result;
            }
            if (value instanceof List<?> list) {
                List<Object> result = new ArrayList<Object>();
                for (Object item : list) result.add(copyValue(item));
                return result;
            }
            return value;
        }
    }
}
