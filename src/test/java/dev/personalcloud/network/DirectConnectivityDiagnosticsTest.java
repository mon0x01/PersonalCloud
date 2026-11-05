package dev.personalcloud.network;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Deterministic STUN protocol tests; no public STUN service or internet access is required. */
public final class DirectConnectivityDiagnosticsTest {
    private static final int COOKIE = 0x2112A442;

    public static void main(String[] args) throws Exception {
        testSingleMappingAndNeverClaimsInboundReachability();
        testConsistentAndEndpointDependentMappings();
        testTimeoutIsReportedWithoutFailingWholeDiagnostic();
        testMissingTlsIdentityIsExplicit();
        testLoopbackDoesNotSendExternalStunRequests();
        testAddressScopeClassification();
        testGlobalInterfaceCandidateIsIndependentOfLoopbackBind();
        testIpv6XorMappedAddressDecoding();
        testMalformedTransactionIsRejected();
        testServerConfigurationParsing();
        System.out.println("PASS: direct connectivity diagnostics; bounded STUN, mapping consistency, timeout isolation, IPv6 XOR decoding and strict response validation.");
    }

    private static void testSingleMappingAndNeverClaimsInboundReachability() throws Exception {
        try (MockStunServer server = new MockStunServer("198.51.100.7", 8787, Mode.NORMAL)) {
            Map<String, Object> result = DirectConnectivityDiagnostics.diagnose("0.0.0.0", 8787, true,
                    List.of(server.endpoint()), 700);
            check("SINGLE_SERVER_MAPPING".equals(result.get("mappingAssessment")), "single STUN mapping classification");
            check("DIRECT_CONNECTIVITY_UNVERIFIED".equals(result.get("assessment")), "one mapping does not prove inbound TCP reachability");
            check("UNVERIFIED".equals(result.get("inboundTcpTlsReachability")), "inbound reachability remains explicitly unverified");
            List<?> rows = (List<?>) result.get("stun");
            Map<?, ?> row = (Map<?, ?>) rows.get(0);
            check("198.51.100.7".equals(row.get("mappedAddress")), "decoded mapped address");
            check(Boolean.TRUE.equals(row.get("udpPortPreserved")), "mapped port comparison");
        }
    }

    private static void testConsistentAndEndpointDependentMappings() throws Exception {
        try (MockStunServer first = new MockStunServer("198.51.100.9", 8787, Mode.NORMAL);
             MockStunServer second = new MockStunServer("198.51.100.9", 8787, Mode.NORMAL);
             MockStunServer different = new MockStunServer("198.51.100.10", 8787, Mode.NORMAL)) {
            Map<String, Object> consistent = DirectConnectivityDiagnostics.diagnose("0.0.0.0", 8787, true,
                    List.of(first.endpoint(), second.endpoint()), 700);
            check("CONSISTENT_MAPPING".equals(consistent.get("mappingAssessment")), "same mapping across STUN endpoints");
            Map<String, Object> dependent = DirectConnectivityDiagnostics.diagnose("0.0.0.0", 8787, true,
                    List.of(first.endpoint(), different.endpoint()), 700);
            check("MAPPING_DEPENDENT".equals(dependent.get("mappingAssessment")), "different mappings across STUN endpoints");
            check("DIRECT_CONNECTIVITY_UNCERTAIN".equals(dependent.get("assessment")), "endpoint-dependent mapping warning");
        }
    }

    private static void testTimeoutIsReportedWithoutFailingWholeDiagnostic() throws Exception {
        try (MockStunServer server = new MockStunServer("198.51.100.9", 8787, Mode.NO_RESPONSE)) {
            Map<String, Object> result = DirectConnectivityDiagnostics.diagnose("0.0.0.0", 8787, true,
                    List.of(server.endpoint()), 150);
            check("STUN_UNAVAILABLE".equals(result.get("mappingAssessment")), "timeout should not crash diagnostic");
            Map<?, ?> row = (Map<?, ?>) ((List<?>) result.get("stun")).get(0);
            check("TIMEOUT".equals(row.get("status")), "timeout result status");
        }
        Map<String, Object> loopback = DirectConnectivityDiagnostics.diagnose("127.0.0.1", 8787, false,
                List.of(new DirectConnectivityDiagnostics.StunServer("127.0.0.1", 9)), 100);
        check("LOOPBACK_BIND".equals(loopback.get("mappingAssessment")), "loopback bind is reported even if STUN cannot run");
        check("NOT_PEER_REACHABLE".equals(loopback.get("assessment")), "loopback listener cannot accept remote peers");
    }

    private static void testMissingTlsIdentityIsExplicit() throws Exception {
        try (MockStunServer first = new MockStunServer("198.51.100.9", 8787, Mode.NORMAL);
             MockStunServer second = new MockStunServer("198.51.100.9", 8787, Mode.NORMAL)) {
            Map<String, Object> result = DirectConnectivityDiagnostics.diagnose("0.0.0.0", 8787, false,
                    List.of(first.endpoint(), second.endpoint()), 700);
            check("TLS_IDENTITY_MISSING".equals(result.get("assessment")), "non-loopback listener without TLS identity must be blocked");
        }
        check(!DirectConnectivityDiagnostics.hasUsableTlsIdentity("/path/that/does/not/exist", "password".toCharArray()),
                "missing TLS identity must not be accepted");
    }

    private static void testLoopbackDoesNotSendExternalStunRequests() throws Exception {
        try (MockStunServer server = new MockStunServer("198.51.100.9", 8787, Mode.NO_RESPONSE)) {
            Map<String, Object> result = DirectConnectivityDiagnostics.diagnose("127.0.0.1", 8787, false,
                    List.of(server.endpoint()), 150);
            Map<?, ?> row = (Map<?, ?>) ((List<?>) result.get("stun")).get(0);
            check("SKIPPED_LOOPBACK_BIND".equals(row.get("status")), "loopback binding should not send misleading STUN traffic");
        }
    }

    private static void testAddressScopeClassification() throws Exception {
        check("CARRIER_GRADE_NAT".equals(DirectConnectivityDiagnostics.addressScope(InetAddress.getByName("100.64.1.2"))),
                "carrier-grade NAT range classification");
        check("SPECIAL_USE".equals(DirectConnectivityDiagnostics.addressScope(InetAddress.getByName("192.0.2.1"))),
                "documentation IPv4 range must not be presented as public");
        check("UNIQUE_LOCAL".equals(DirectConnectivityDiagnostics.addressScope(InetAddress.getByName("fd00::1"))),
                "IPv6 unique-local classification");
        check("SPECIAL_USE".equals(DirectConnectivityDiagnostics.addressScope(InetAddress.getByName("2001:db8::1"))),
                "IPv6 documentation range must not be presented as public");
        check("GLOBAL_CANDIDATE".equals(DirectConnectivityDiagnostics.addressScope(InetAddress.getByName("2001:4860::1"))),
                "IPv6 global-unicast candidate classification");
    }


    private static void testGlobalInterfaceCandidateIsIndependentOfLoopbackBind() throws Exception {
        Map<String, Object> ipv6 = Map.of(
                "interface", "wlp1s0",
                "address", "2401:4900:ae45:7fcb:5103:9a9:9c94:7c45",
                "scope", "GLOBAL_CANDIDATE",
                "interfaceUp", true);
        List<Map<String, Object>> addresses = List.of(ipv6);
        check(DirectConnectivityDiagnostics.hasGlobalCandidate(addresses),
                "global IPv6 candidate must be reported even while listener is loopback-only");
        check(!DirectConnectivityDiagnostics.hasGlobalCandidateForBind(addresses, InetAddress.getByName("127.0.0.1")),
                "loopback listener must not be classified as bound to global IPv6");
        check(DirectConnectivityDiagnostics.hasGlobalCandidateForBind(addresses, InetAddress.getByName("::")),
                "IPv6 wildcard listener must recognize global IPv6 candidate");
        check(!DirectConnectivityDiagnostics.hasGlobalCandidate(List.of(Map.of(
                "interface", "wlp1s0", "address", "2401:4900::1", "scope", "GLOBAL_CANDIDATE", "interfaceUp", false))),
                "addresses on a down interface must not be reported as active candidates");
    }

    private static void testIpv6XorMappedAddressDecoding() throws Exception {
        byte[] transaction = new byte[12];
        for (int index = 0; index < transaction.length; index++) transaction[index] = (byte) (index + 1);
        byte[] address = InetAddress.getByName("2001:db8::5").getAddress();
        byte[] packet = response(transaction, address, 45678);
        DirectConnectivityDiagnostics.Mapping decoded = DirectConnectivityDiagnostics.decodeBindingResponse(packet,
                packet.length, transaction);
        check(decoded.address().getHostAddress().equalsIgnoreCase("2001:db8:0:0:0:0:0:5"), "IPv6 XOR mapped address");
        check(decoded.port() == 45678, "IPv6 XOR mapped port");
    }

    private static void testMalformedTransactionIsRejected() throws Exception {
        byte[] transaction = new byte[12];
        byte[] packet = response(transaction, new byte[] {(byte) 198, 51, 100, 12}, 50000);
        packet[19] = 1;
        boolean rejected = false;
        try { DirectConnectivityDiagnostics.decodeBindingResponse(packet, packet.length, transaction); }
        catch (java.io.IOException expected) { rejected = true; }
        check(rejected, "wrong transaction ID must be rejected");
    }

    private static void testServerConfigurationParsing() {
        List<DirectConnectivityDiagnostics.StunServer> parsed = DirectConnectivityDiagnostics.parseServers("stun.example:3478,[2001:db8::1]:5349");
        check(parsed.size() == 2 && parsed.get(1).host().equals("2001:db8::1") && parsed.get(1).port() == 5349,
                "IPv6 STUN endpoint parsing");
        boolean rejected = false;
        try { DirectConnectivityDiagnostics.parseServers("stun.example:70000"); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected, "invalid STUN port must fail");
    }

    private static byte[] response(byte[] transaction, byte[] mappedAddress, int mappedPort) throws Exception {
        int attributeLength = mappedAddress.length + 4;
        int paddedLength = (attributeLength + 3) & ~3;
        ByteBuffer response = ByteBuffer.allocate(20 + 4 + paddedLength).order(ByteOrder.BIG_ENDIAN);
        response.putShort((short) 0x0101).putShort((short) (4 + paddedLength)).putInt(COOKIE).put(transaction);
        response.putShort((short) 0x0020).putShort((short) attributeLength);
        response.put((byte) 0).put((byte) (mappedAddress.length == 4 ? 1 : 2));
        response.putShort((short) (mappedPort ^ (COOKIE >>> 16)));
        byte[] mask = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putInt(COOKIE).put(transaction).array();
        for (int index = 0; index < mappedAddress.length; index++) response.put((byte) (mappedAddress[index] ^ mask[index]));
        while (response.hasRemaining()) response.put((byte) 0);
        return response.array();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private enum Mode { NORMAL, NO_RESPONSE }

    private static final class MockStunServer implements AutoCloseable {
        private final DatagramSocket socket;
        private final Thread worker;
        private final AtomicReference<Throwable> failure = new AtomicReference<>();

        private MockStunServer(String mappedAddress, int mappedPort, Mode mode) throws Exception {
            socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            worker = new Thread(() -> {
                try {
                    while (!socket.isClosed()) {
                        byte[] request = new byte[128];
                        DatagramPacket incoming = new DatagramPacket(request, request.length);
                        socket.receive(incoming);
                        if (mode == Mode.NO_RESPONSE) continue;
                        if (incoming.getLength() != 20) throw new AssertionError("Unexpected STUN request length");
                        if (incoming.getPort() != 8787) throw new AssertionError("STUN request did not use the configured UDP listener port");
                        ByteBuffer header = ByteBuffer.wrap(request, 8, 12);
                        byte[] transaction = new byte[12];
                        header.get(transaction);
                        byte[] result = response(transaction, InetAddress.getByName(mappedAddress).getAddress(), mappedPort);
                        socket.send(new DatagramPacket(result, result.length, incoming.getAddress(), incoming.getPort()));
                    }
                } catch (Throwable throwable) {
                    if (!socket.isClosed()) failure.set(throwable);
                }
            }, "personalcloud-test-stun");
            worker.setDaemon(true);
            worker.start();
        }

        private DirectConnectivityDiagnostics.StunServer endpoint() {
            return new DirectConnectivityDiagnostics.StunServer("127.0.0.1", socket.getLocalPort());
        }

        @Override public void close() throws Exception {
            socket.close();
            worker.join(1000);
            if (worker.isAlive()) throw new AssertionError("Mock STUN server did not stop");
            if (failure.get() != null) throw new AssertionError("Mock STUN server failed", failure.get());
        }
    }
}
