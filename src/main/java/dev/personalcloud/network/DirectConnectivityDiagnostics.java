package dev.personalcloud.network;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Read-only diagnostics for direct peer connectivity. STUN only discovers an outbound
 * UDP mapping; it deliberately does not claim that an inbound TCP/TLS peer connection
 * will work. No firewall, router, interface, or endpoint configuration is modified.
 */
public final class DirectConnectivityDiagnostics {
    private static final int STUN_MAGIC_COOKIE = 0x2112A442;
    private static final int STUN_BINDING_REQUEST = 0x0001;
    private static final int STUN_BINDING_SUCCESS = 0x0101;
    private static final int ATTR_MAPPED_ADDRESS = 0x0001;
    private static final int ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    private static final int MAX_PACKET_BYTES = 2048;
    private static final int MAX_SERVERS = 4;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final List<StunServer> DEFAULT_SERVERS = List.of(
            new StunServer("stun.l.google.com", 19302),
            new StunServer("stun1.l.google.com", 19302));

    private DirectConnectivityDiagnostics() { }

    public record StunServer(String host, int port) {
        public StunServer {
            if (host == null || host.isBlank() || host.length() > 253
                    || host.contains("/") || host.contains("\\") || port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid STUN server.");
            }
        }
        public String display() { return host.indexOf(':') >= 0 ? "[" + host + "]:" + port : host + ":" + port; }
    }

    record Mapping(InetAddress address, int port) { }

    /** Runs a bounded, read-only snapshot using the supplied STUN endpoints. */
    public static Map<String, Object> diagnose(String bindAddress, int listenPort,
                                                boolean tlsConfigured, List<StunServer> servers,
                                                int timeoutMillis) throws IOException {
        if (bindAddress == null || bindAddress.isBlank() || bindAddress.length() > 255) {
            throw new IllegalArgumentException("A bind address is required.");
        }
        if (listenPort < 1 || listenPort > 65535) throw new IllegalArgumentException("Invalid listen port.");
        if (timeoutMillis < 100 || timeoutMillis > 5000) throw new IllegalArgumentException("STUN timeout must be between 100 and 5000 milliseconds.");
        List<StunServer> selectedServers = List.copyOf(Objects.requireNonNull(servers, "servers"));
        if (selectedServers.isEmpty() || selectedServers.size() > MAX_SERVERS) {
            throw new IllegalArgumentException("Configure between one and four STUN servers.");
        }

        InetAddress bind = InetAddress.getByName(bindAddress);
        List<Map<String, Object>> local = localAddresses();
        List<Map<String, Object>> stun = new ArrayList<>();
        List<Mapping> mappings = new ArrayList<>();
        for (StunServer server : selectedServers) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("server", server.display());
            try {
                if (bind.isLoopbackAddress()) {
                    row.put("status", "SKIPPED_LOOPBACK_BIND");
                    row.put("reason", "The peer listener is loopback-only; outbound STUN results would not describe a peer-reachable listener.");
                } else {
                    Mapping mapping = query(server, timeoutMillis, bind, listenPort);
                    mappings.add(mapping);
                    row.put("status", "SUCCESS");
                    row.put("mappedAddress", mapping.address().getHostAddress());
                    row.put("mappedPort", mapping.port());
                    row.put("udpPortPreserved", mapping.port() == listenPort);
                }
            } catch (SocketTimeoutException timeout) {
                row.put("status", "TIMEOUT");
                row.put("reason", "No STUN response before the timeout.");
            } catch (Exception failure) {
                row.put("status", "ERROR");
                row.put("reason", safeMessage(failure));
            }
            stun.add(row);
        }

        String mappingAssessment;
        if (bind.isLoopbackAddress()) mappingAssessment = "LOOPBACK_BIND";
        else if (mappings.isEmpty()) mappingAssessment = "STUN_UNAVAILABLE";
        else if (mappings.size() == 1) mappingAssessment = "SINGLE_SERVER_MAPPING";
        else if (mappings.stream().allMatch(value -> sameMapping(mappings.get(0), value))) {
            mappingAssessment = "CONSISTENT_MAPPING";
        } else mappingAssessment = "MAPPING_DEPENDENT";

        // Report interface discovery independently from listener configuration. A loopback
        // listener must not hide a public IPv6 candidate present on a separate interface.
        boolean hasGlobalCandidate = hasGlobalCandidate(local);
        boolean boundAddressGlobalCandidate = hasGlobalCandidateForBind(local, bind);
        boolean carrierGradeNatAddressPresent = local.stream().anyMatch(row -> Boolean.TRUE.equals(row.get("interfaceUp"))
                && "CARRIER_GRADE_NAT".equals(row.get("scope")));
        boolean allPortsPreserved = !mappings.isEmpty() && mappings.stream().allMatch(value -> value.port() == listenPort);
        String assessment;
        String guidance;
        if (bind.isLoopbackAddress()) {
            assessment = "NOT_PEER_REACHABLE";
            guidance = "The node is bound to loopback. Configure a non-loopback bind address and TLS before accepting remote peers.";
        } else if (!tlsConfigured) {
            assessment = "TLS_IDENTITY_MISSING";
            guidance = "A non-loopback PersonalCloud listener requires a valid PKCS#12 TLS identity. Configure it before advertising this node to other devices.";
        } else if (mappingAssessment.equals("MAPPING_DEPENDENT")) {
            assessment = "DIRECT_CONNECTIVITY_UNCERTAIN";
            guidance = "Different STUN servers observed different UDP mappings. This is consistent with endpoint-dependent NAT behavior; configure an explicit inbound route or test IPv6 from another network.";
        } else if (mappingAssessment.equals("SINGLE_SERVER_MAPPING")) {
            assessment = "DIRECT_CONNECTIVITY_UNVERIFIED";
            guidance = "Only one STUN server replied, so mapping consistency could not be compared. Retry with at least two STUN endpoints, then test the exact HTTPS listener from another network.";
        } else if (mappings.isEmpty() && !boundAddressGlobalCandidate) {
            assessment = "DIRECT_CONNECTIVITY_UNVERIFIED";
            guidance = hasGlobalCandidate
                    ? "A global address exists on another interface or address family, but not on the configured listener binding. Bind to the intended interface/family and validate its firewall and route."
                    : "No public address was discovered on an active interface. Check outbound UDP/DNS, router port forwarding, firewall rules, or a globally routed IPv6 address.";
        } else {
            assessment = "CANDIDATE_ADDRESS_FOUND";
            boolean udpPortChanged = !mappings.isEmpty() && !allPortsPreserved;
            guidance = udpPortChanged
                    ? "A candidate address is visible, but the UDP mapping changed the source port. UDP mapping does not predict the TCP listener mapping; test the exact HTTPS endpoint from another network."
                    : "A candidate address is visible, but inbound TCP/TLS reachability is not proven. Test the exact HTTPS endpoint from a different network before relying on it.";
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bindAddress", bind.getHostAddress());
        result.put("listenPort", listenPort);
        result.put("tlsConfigured", tlsConfigured);
        result.put("bindMode", bind.isAnyLocalAddress() ? "WILDCARD" : bind.isLoopbackAddress() ? "LOOPBACK" : "SPECIFIC_INTERFACE");
        result.put("localAddresses", local);
        result.put("globalInterfaceCandidatePresent", hasGlobalCandidate);
        result.put("boundAddressGlobalCandidatePresent", boundAddressGlobalCandidate);
        result.put("carrierGradeNatAddressPresent", carrierGradeNatAddressPresent);
        result.put("stun", stun);
        result.put("mappingAssessment", mappingAssessment);
        result.put("assessment", assessment);
        result.put("inboundTcpTlsReachability", "UNVERIFIED");
        result.put("guidance", guidance);
        result.put("disclaimer", "STUN reports outbound UDP address mapping only; it cannot prove inbound TCP/TLS reachability or peer identity.");
        return result;
    }

    /** Validates the configured PKCS#12 server identity without exposing its path or password. */
    public static boolean hasUsableTlsIdentity(String keyStorePath, char[] password) {
        if (keyStorePath == null || keyStorePath.isBlank() || password == null || password.length == 0) return false;
        Path path;
        try {
            path = Path.of(keyStorePath).toAbsolutePath().normalize();
            if (!Files.isRegularFile(path) || Files.isSymbolicLink(path)) return false;
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(path)) { keyStore.load(input, password); }
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!keyStore.isKeyEntry(alias)) continue;
                if (!(keyStore.getKey(alias, password) instanceof PrivateKey)) continue;
                if (!(keyStore.getCertificate(alias) instanceof X509Certificate certificate)) continue;
                certificate.checkValidity();
                KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                managers.init(keyStore, password);
                return managers.getKeyManagers().length > 0;
            }
        } catch (Exception ignored) {
            return false;
        }
        return false;
    }

    public static List<StunServer> defaultServers() { return DEFAULT_SERVERS; }

    public static List<StunServer> parseServers(String value) {
        if (value == null || value.isBlank()) return DEFAULT_SERVERS;
        String[] entries = value.split(",", -1);
        if (entries.length < 1 || entries.length > MAX_SERVERS) throw new IllegalArgumentException("PERSONALCLOUD_STUN_SERVERS must contain one to four comma-separated host:port values.");
        List<StunServer> result = new ArrayList<>();
        for (String raw : entries) {
            String entry = raw.trim();
            String host;
            int port = 3478;
            if (entry.startsWith("[")) {
                int close = entry.indexOf(']');
                if (close < 2) throw new IllegalArgumentException("Invalid bracketed STUN server: " + entry);
                host = entry.substring(1, close);
                if (close + 1 < entry.length()) {
                    if (entry.charAt(close + 1) != ':') throw new IllegalArgumentException("Invalid STUN server port: " + entry);
                    port = parsePort(entry.substring(close + 2));
                }
            } else {
                int colon = entry.lastIndexOf(':');
                if (colon > 0 && entry.indexOf(':') == colon) {
                    host = entry.substring(0, colon);
                    port = parsePort(entry.substring(colon + 1));
                } else host = entry;
            }
            result.add(new StunServer(host, port));
        }
        return List.copyOf(result);
    }

    private static int parsePort(String text) {
        try {
            int port = Integer.parseInt(text);
            if (port < 1 || port > 65535) throw new NumberFormatException();
            return port;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("Invalid STUN server port.");
        }
    }

    private static Mapping query(StunServer server, int timeoutMillis, InetAddress bindAddress, int localPort) throws Exception {
        InetAddress[] resolved = InetAddress.getAllByName(server.host());
        if (resolved.length == 0) throw new IOException("STUN host did not resolve.");
        IOException last = null;
        for (InetAddress address : resolved) {
            try { return query(address, server.port(), timeoutMillis, bindAddress, localPort); }
            catch (IOException failure) { last = failure; }
        }
        throw last == null ? new IOException("STUN host did not resolve.") : last;
    }

    private static Mapping query(InetAddress server, int port, int timeoutMillis,
                                 InetAddress bindAddress, int localPort) throws IOException {
        byte[] transaction = new byte[12];
        RANDOM.nextBytes(transaction);
        ByteBuffer request = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        request.putShort((short) STUN_BINDING_REQUEST).putShort((short) 0)
                .putInt(STUN_MAGIC_COOKIE).put(transaction);
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(false);
            socket.bind(new java.net.InetSocketAddress(bindAddress, localPort));
            socket.connect(server, port);
            socket.setSoTimeout(timeoutMillis);
            byte[] bytes = request.array();
            socket.send(new DatagramPacket(bytes, bytes.length));
            byte[] received = new byte[MAX_PACKET_BYTES];
            DatagramPacket response = new DatagramPacket(received, received.length);
            socket.receive(response);
            return decodeBindingResponse(received, response.getLength(), transaction);
        }
    }

    static Mapping decodeBindingResponse(byte[] packet, int length, byte[] expectedTransaction) throws IOException {
        if (packet == null || expectedTransaction == null || expectedTransaction.length != 12
                || length < 20 || length > packet.length || length > MAX_PACKET_BYTES) {
            throw new IOException("Malformed STUN response length.");
        }
        ByteBuffer input = ByteBuffer.wrap(packet, 0, length).slice().order(ByteOrder.BIG_ENDIAN);
        int type = Short.toUnsignedInt(input.getShort());
        int messageLength = Short.toUnsignedInt(input.getShort());
        int cookie = input.getInt();
        byte[] transaction = new byte[12];
        input.get(transaction);
        if (type != STUN_BINDING_SUCCESS) throw new IOException("STUN server did not return a Binding Success response.");
        if (cookie != STUN_MAGIC_COOKIE || !java.security.MessageDigest.isEqual(transaction, expectedTransaction)) {
            throw new IOException("STUN response transaction validation failed.");
        }
        if ((messageLength & 3) != 0 || messageLength != length - 20) throw new IOException("Malformed STUN attribute length.");
        Mapping mapped = null;
        int end = 20 + messageLength;
        while (input.position() < end) {
            if (end - input.position() < 4) throw new IOException("Truncated STUN attribute header.");
            int attribute = Short.toUnsignedInt(input.getShort());
            int attributeLength = Short.toUnsignedInt(input.getShort());
            if (attributeLength > end - input.position()) throw new IOException("Truncated STUN attribute value.");
            int valueStart = input.position();
            if (attribute == ATTR_XOR_MAPPED_ADDRESS || (attribute == ATTR_MAPPED_ADDRESS && mapped == null)) {
                Mapping candidate = decodeAddressAttribute(packet, valueStart, attributeLength,
                        attribute == ATTR_XOR_MAPPED_ADDRESS, transaction);
                if (candidate != null && (attribute == ATTR_XOR_MAPPED_ADDRESS || mapped == null)) mapped = candidate;
                if (attribute == ATTR_XOR_MAPPED_ADDRESS && candidate != null) return candidate;
            }
            int padded = (attributeLength + 3) & ~3;
            if (padded > end - input.position()) throw new IOException("Invalid STUN attribute padding.");
            input.position(input.position() + padded);
        }
        if (mapped == null) throw new IOException("STUN response omitted a supported mapped-address attribute.");
        return mapped;
    }

    private static Mapping decodeAddressAttribute(byte[] packet, int offset, int length,
                                                   boolean xor, byte[] transaction) throws IOException {
        if (length < 4) throw new IOException("Truncated STUN address attribute.");
        int family = Byte.toUnsignedInt(packet[offset + 1]);
        int port = Short.toUnsignedInt(ByteBuffer.wrap(packet, offset + 2, 2).order(ByteOrder.BIG_ENDIAN).getShort());
        if (xor) port ^= (STUN_MAGIC_COOKIE >>> 16);
        int addressLength = family == 1 ? 4 : family == 2 ? 16 : -1;
        if (addressLength < 0 || length != 4 + addressLength) throw new IOException("Invalid STUN address family or length.");
        byte[] address = new byte[addressLength];
        System.arraycopy(packet, offset + 4, address, 0, addressLength);
        if (xor) {
            byte[] mask = new byte[16];
            ByteBuffer.wrap(mask).order(ByteOrder.BIG_ENDIAN).putInt(STUN_MAGIC_COOKIE).put(transaction);
            for (int index = 0; index < address.length; index++) address[index] ^= mask[index];
        }
        try { return new Mapping(InetAddress.getByAddress(address), port); }
        catch (Exception invalid) { throw new IOException("Invalid STUN mapped address.", invalid); }
    }

    private static List<Map<String, Object>> localAddresses() throws IOException {
        List<Map<String, Object>> result = new ArrayList<>();
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        if (interfaces == null) return List.of();
        for (NetworkInterface network : Collections.list(interfaces)) {
            boolean up;
            try { up = network.isUp(); }
            catch (Exception ignored) { up = false; }
            for (InetAddress address : Collections.list(network.getInetAddresses())) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("interface", network.getName());
                row.put("displayName", network.getDisplayName());
                row.put("address", address.getHostAddress());
                row.put("family", address instanceof Inet6Address ? "IPv6" : address instanceof Inet4Address ? "IPv4" : "OTHER");
                row.put("scope", addressScope(address));
                row.put("interfaceUp", up);
                result.add(row);
            }
        }
        result.sort((left, right) -> String.valueOf(left.get("interface")).compareTo(String.valueOf(right.get("interface"))));
        return List.copyOf(result);
    }

    static String addressScope(InetAddress address) {
        if (address.isAnyLocalAddress()) return "UNSPECIFIED";
        if (address.isLoopbackAddress()) return "LOOPBACK";
        if (address.isLinkLocalAddress()) return "LINK_LOCAL";
        if (address.isMulticastAddress()) return "MULTICAST";
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = Byte.toUnsignedInt(bytes[0]);
            int second = Byte.toUnsignedInt(bytes[1]);
            int third = Byte.toUnsignedInt(bytes[2]);
            if (first == 10 || first == 172 && second >= 16 && second <= 31 || first == 192 && second == 168) return "PRIVATE";
            if (first == 100 && second >= 64 && second <= 127) return "CARRIER_GRADE_NAT";
            if (first == 192 && (second == 0 && (third == 0 || third == 2) || second == 88 && third == 99)
                    || first == 198 && (second == 18 || second == 19 || second == 51 && third == 100)
                    || first == 203 && second == 0 && third == 113 || first == 255) return "SPECIAL_USE";
            if (first == 0 || first >= 224) return "SPECIAL_USE";
            return "GLOBAL_CANDIDATE";
        }
        if (address instanceof Inet6Address) {
            int first = Byte.toUnsignedInt(bytes[0]);
            int second = Byte.toUnsignedInt(bytes[1]);
            if ((first & 0xFE) == 0xFC) return "UNIQUE_LOCAL";
            if (first == 0xFE && (second & 0xC0) == 0xC0) return "SITE_LOCAL";
            // Global unicast currently occupies 2000::/3; documentation and non-global
            // ranges must not be advertised as real public candidates.
            if ((first & 0xE0) != 0x20) return "SPECIAL_USE";
            if (first == 0x20 && second == 0x01 && Byte.toUnsignedInt(bytes[2]) == 0x0D
                    && Byte.toUnsignedInt(bytes[3]) == 0xB8) return "SPECIAL_USE";
            return "GLOBAL_CANDIDATE";
        }
        return "UNKNOWN";
    }

    static boolean hasGlobalCandidate(List<Map<String, Object>> addresses) {
        for (Map<String, Object> row : addresses) {
            if (Boolean.TRUE.equals(row.get("interfaceUp")) && "GLOBAL_CANDIDATE".equals(row.get("scope"))) return true;
        }
        return false;
    }

    /** True only when a public candidate belongs to the address/family selected for this listener. */
    static boolean hasGlobalCandidateForBind(List<Map<String, Object>> addresses, InetAddress bind) {
        for (Map<String, Object> row : addresses) {
            if (!Boolean.TRUE.equals(row.get("interfaceUp")) || !"GLOBAL_CANDIDATE".equals(row.get("scope"))) continue;
            try {
                String value = String.valueOf(row.get("address"));
                InetAddress candidate = InetAddress.getByName(value);
                if (bind.isAnyLocalAddress()) {
                    if ((bind instanceof Inet6Address) == (candidate instanceof Inet6Address)) return true;
                } else if (java.util.Arrays.equals(bind.getAddress(), candidate.getAddress())) return true;
            } catch (Exception ignored) { }
        }
        return false;
    }

    private static boolean sameMapping(Mapping left, Mapping right) {
        return left.port() == right.port() && left.address().equals(right.address());
    }

    private static String safeMessage(Throwable failure) {
        String message = failure.getMessage();
        String value = message == null || message.isBlank() ? failure.getClass().getSimpleName() : message;
        return value.substring(0, Math.min(160, value.length()));
    }
}
