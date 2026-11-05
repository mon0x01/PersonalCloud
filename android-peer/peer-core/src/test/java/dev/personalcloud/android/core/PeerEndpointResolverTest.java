package dev.personalcloud.android.core;

import java.net.InetAddress;
import java.util.List;

/** Address selection and endpoint formatting tests for Android network changes. */
public final class PeerEndpointResolverTest {
    public static void main(String[] args) throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        InetAddress linkLocal = InetAddress.getByName("169.254.4.9");
        InetAddress current = InetAddress.getByName("10.239.151.117");
        InetAddress unrelated = InetAddress.getByName("10.239.151.118");
        byte[] san = PeerEndpointResolver.parseIpv4San("10.239.151.117");
        check(san != null && san.length == 4, "a valid IPv4 SAN must parse to raw address bytes");
        check(PeerEndpointResolver.parseIpv4San("personalcloud.local") == null,
                "DNS SANs must not be treated as IP address SANs or resolved through DNS");
        check(PeerEndpointResolver.parseIpv4San("10.239.151.999") == null,
                "out-of-range IPv4 SAN octets must be rejected");
        check(PeerEndpointResolver.parseIpv4San(new byte[]{10, 1, 2, 3}).length == 4,
                "DER-decoded SAN byte arrays must be supported");

        InetAddress selected = PeerEndpointResolver.selectIpv4Address(
                List.of(loopback, linkLocal, unrelated, current), List.of(san));
        check(current.equals(selected), "only the active address exactly covered by the TLS IP SAN may be selected");
        check("https://10.239.151.117:8879".equals(PeerEndpointResolver.httpsEndpoint(selected, 8879)),
                "IPv4 peer endpoint must be formatted with the configured port");

        boolean noMatchRejected = false;
        try { PeerEndpointResolver.selectIpv4Address(List.of(unrelated), List.of(san)); }
        catch (IllegalStateException expected) { noMatchRejected = true; }
        check(noMatchRejected, "an address not covered by the certificate must fail closed");

        boolean loopbackEndpointRejected = false;
        try { PeerEndpointResolver.httpsEndpoint(loopback, 8879); }
        catch (IllegalArgumentException expected) { loopbackEndpointRejected = true; }
        check(loopbackEndpointRejected, "loopback must not be advertised as a reachable peer endpoint");

        boolean invalidPortRejected = false;
        try { PeerEndpointResolver.httpsEndpoint(current, 70000); }
        catch (IllegalArgumentException expected) { invalidPortRejected = true; }
        check(invalidPortRejected, "invalid listener ports must be rejected");

        System.out.println("PASS: Android network endpoint selection matches active IPv4 addresses to certificate IP SANs, rejects unsafe or stale addresses, and formats direct HTTPS endpoints safely.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
