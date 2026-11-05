package dev.personalcloud.android.core;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/** Selects only an active IPv4 address explicitly covered by the peer TLS certificate. */
public final class PeerEndpointResolver {
    private PeerEndpointResolver() { }

    public static Inet4Address selectIpv4Address(Collection<InetAddress> candidates,
                                                  Collection<byte[]> certificateIpSans) {
        if (candidates == null || certificateIpSans == null || certificateIpSans.isEmpty()) {
            throw new IllegalStateException("No IPv4 address is covered by the Android peer TLS certificate.");
        }
        List<byte[]> allowed = new ArrayList<byte[]>();
        for (byte[] san : certificateIpSans) {
            if (san != null && san.length == 4) allowed.add(san.clone());
        }
        for (InetAddress candidate : candidates) {
            if (!(candidate instanceof Inet4Address address)) continue;
            if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                    || address.isLinkLocalAddress() || address.isMulticastAddress()) continue;
            byte[] raw = address.getAddress();
            for (byte[] san : allowed) {
                if (java.util.Arrays.equals(raw, san)) return address;
            }
        }
        throw new IllegalStateException("No active Wi-Fi IPv4 address matches an IP SAN in the Android peer TLS certificate. The listener remains bound, but this address cannot be advertised securely; renew the TLS identity with the new address.");
    }

    public static String httpsEndpoint(InetAddress address, int port) {
        if (!(address instanceof Inet4Address) || address.isAnyLocalAddress()
                || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isMulticastAddress()) {
            throw new IllegalArgumentException("A reachable, non-loopback IPv4 peer address is required.");
        }
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Peer port must be between 1 and 65535.");
        return "https://" + address.getHostAddress() + ":" + port;
    }

    /** Parses an X.509 subjectAltName IP value without DNS resolution. */
    public static byte[] parseIpv4San(Object value) {
        if (value instanceof byte[] bytes) return bytes.length == 4 ? bytes.clone() : null;
        if (!(value instanceof String text)) return null;
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) return null;
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (parts[i].isEmpty() || !parts[i].matches("[0-9]{1,3}")) return null;
            int octet;
            try { octet = Integer.parseInt(parts[i]); }
            catch (NumberFormatException invalid) { return null; }
            if (octet < 0 || octet > 255) return null;
            result[i] = (byte) octet;
        }
        return result;
    }
}
