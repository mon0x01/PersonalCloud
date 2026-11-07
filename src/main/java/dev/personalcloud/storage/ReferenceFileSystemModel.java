package dev.personalcloud.storage;

import dev.personalcloud.control.LocalControlClient;
import dev.personalcloud.net.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Read-only, network-wide virtual filesystem projection.
 *
 * <pre>
 * /Devices/<device>/References/<shared-root>/...
 * /Devices/<device>/Distributed-Storage/<managed-path>/...
 * </pre>
 *
 * File bytes are read in bounded ranges through the owner-only Java control socket. Remote
 * metadata is cached under the private data directory so an offline device can remain visible
 * with its last known catalogue; opening unavailable content still fails rather than pretending
 * that stale metadata is live data.
 */
public final class ReferenceFileSystemModel {
    private static final int MAX_READ_BYTES = 8 * 1024 * 1024;
    private static final String REFERENCES = "References";
    private static final String MANAGED = "Distributed-Storage";

    private final LocalControlClient client;
    private final Path cacheFile;
    private Map<String, Object> cache;

    public ReferenceFileSystemModel(LocalControlClient client) {
        this.client = Objects.requireNonNull(client, "client");
        this.cacheFile = client.socketPath().getParent().resolve("filesystem-catalogue-cache.json");
        this.cache = loadCache();
    }

    public synchronized List<String> list(String virtualPath) throws IOException {
        List<String> parts = segments(virtualPath);
        if (parts.isEmpty()) return List.of("Devices");
        if (parts.size() == 1 && "Devices".equals(parts.getFirst())) return deviceNames();
        if (!"Devices".equals(parts.getFirst()) || parts.size() < 2) throw new NoSuchFileException(virtualPath);
        Device device = requireDevice(parts.get(1));
        if (parts.size() == 2) return List.of(REFERENCES, MANAGED);
        if (parts.size() == 3 && REFERENCES.equals(parts.get(2))) {
            return referenceRoots(device).stream().map(ReferenceRootInfo::displayName)
                    .sorted(String.CASE_INSENSITIVE_ORDER).toList();
        }
        if (parts.size() == 3 && MANAGED.equals(parts.get(2))) {
            return managedChildren(device, "");
        }
        if (REFERENCES.equals(parts.get(2))) {
            ReferenceRootInfo root = requireReferenceRoot(device, parts.get(3));
            if (root.file()) return List.of();
            String relative = parts.size() <= 4 ? "" : String.join("/", parts.subList(4, parts.size()));
            return referenceEntries(device, root, relative).stream().map(entry -> optionalString(entry, "name"))
                    .sorted(String.CASE_INSENSITIVE_ORDER).toList();
        }
        if (MANAGED.equals(parts.get(2))) {
            String relativeDirectory = parts.size() <= 4 ? "" : String.join("/", parts.subList(3, parts.size()));
            return managedChildren(device, relativeDirectory);
        }
        throw new NoSuchFileException(virtualPath);
    }

    public synchronized Attributes attributes(String virtualPath) throws IOException {
        List<String> parts = segments(virtualPath);
        if (parts.isEmpty() || (parts.size() == 1 && "Devices".equals(parts.getFirst()))) {
            return new Attributes(true, 0, "", true);
        }
        if (!"Devices".equals(parts.getFirst()) || parts.size() < 2) throw new NoSuchFileException(virtualPath);
        Device device = requireDevice(parts.get(1));
        if (parts.size() == 2 || (parts.size() == 3 && (REFERENCES.equals(parts.get(2)) || MANAGED.equals(parts.get(2))))) {
            return new Attributes(true, 0, "", device.online());
        }
        if (REFERENCES.equals(parts.get(2))) {
            ReferenceRootInfo root = requireReferenceRoot(device, parts.get(3));
            if (parts.size() == 4) {
                if (root.file()) return new Attributes(false, root.size(), root.modified(), device.online());
                return new Attributes(true, 0, root.modified(), device.online());
            }
            String relative = String.join("/", parts.subList(4, parts.size()));
            Map<String, Object> metadata = referenceStat(device, root, relative);
            boolean directory = "DIRECTORY".equalsIgnoreCase(string(metadata, "kind"));
            return new Attributes(directory, directory ? 0 : number(metadata, "size"), optionalString(metadata, "modified"), device.online());
        }
        if (MANAGED.equals(parts.get(2))) {
            String relative = String.join("/", parts.subList(3, parts.size()));
            if (relative.isEmpty() || hasManagedDescendant(device, relative)) {
                return new Attributes(true, 0, "", device.online());
            }
            Map<String, Object> file = findManagedFile(device, relative);
            if (file == null) throw new NoSuchFileException(virtualPath);
            return new Attributes(false, number(file, "size"), optionalString(file, "modified"), device.online());
        }
        throw new NoSuchFileException(virtualPath);
    }

    public synchronized byte[] read(String virtualPath, long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        List<String> parts = segments(virtualPath);
        if (parts.size() < 4 || !"Devices".equals(parts.getFirst())) throw new NoSuchFileException(virtualPath);
        Device device = requireDevice(parts.get(1));
        if (REFERENCES.equals(parts.get(2))) {
            ReferenceRootInfo root = requireReferenceRoot(device, parts.get(3));
            String relative = root.file() ? "" : String.join("/", parts.subList(4, parts.size()));
            Attributes attributes = attributes(virtualPath);
            if (attributes.directory()) throw new IOException("Cannot read a directory.");
            if (device.local()) return client.readRange(root.referenceId(), relative, offset, length);
            return client.readRemoteRange(device.nodeId(), "REFERENCE", root.grantId(), relative, offset, length);
        }
        if (MANAGED.equals(parts.get(2))) {
            String relative = String.join("/", parts.subList(3, parts.size()));
            Map<String, Object> file = findManagedFile(device, relative);
            if (file == null) throw new NoSuchFileException(virtualPath);
            String fileId = string(file, "fileId");
            return device.local() ? client.readLocalManagedRange(fileId, offset, length)
                    : client.readRemoteRange(device.nodeId(), "MANAGED", fileId, "", offset, length);
        }
        throw new NoSuchFileException(virtualPath);
    }

    /**
     * Device rows for native adapters that add additional per-device subtrees. The
     * display name is the stable kernel path segment; node identity is never guessed
     * from it.
     */
    public synchronized List<Map<String, Object>> deviceRows() throws IOException {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Device device : devices()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("nodeId", device.nodeId());
            row.put("name", device.name());
            row.put("displayName", device.displayName());
            row.put("local", device.local());
            row.put("online", device.online());
            row.put("active", device.active());
            rows.add(row);
        }
        return List.copyOf(rows);
    }

    /** Resolves a kernel-visible device display name, failing closed when it is unknown. */
    public synchronized Map<String, Object> requireDeviceRow(String displayName) throws IOException {
        for (Map<String, Object> row : deviceRows()) {
            if (String.valueOf(row.get("displayName")).equals(displayName)) return row;
        }
        throw new NoSuchFileException(displayName);
    }

    /**
     * Global metadata search; content is never indexed or read during search. Results from
     * unreachable members are returned only from the last successful exact-query cache and are
     * explicitly marked stale/unavailable. This avoids presenting cached metadata as live data.
     */
    public synchronized List<Map<String, Object>> search(String query, int limit) throws IOException {
        if (query == null || query.isBlank()) throw new IllegalArgumentException("Search query is required.");
        int boundedLimit = Math.max(1, Math.min(100, limit));
        String normalizedQuery = query.strip().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        String cacheKey = "network-search:" + normalizedQuery;
        LocalControlClient.NetworkSearchResult search = client.networkSearchWithStatus(query, boundedLimit);

        java.util.Set<String> unavailableOwners = new java.util.HashSet<>();
        for (Map<String, Object> unavailable : search.unavailableDevices()) {
            String owner = optionalString(unavailable, "nodeId");
            if (!owner.isBlank()) unavailableOwners.add(owner);
        }
        try {
            for (Map<String, Object> member : client.networkMembers()) {
                String owner = optionalString(member, "nodeId");
                if (owner.isBlank() || !"ACTIVE".equalsIgnoreCase(optionalString(member, "status"))) continue;
                if (!Boolean.TRUE.equals(member.get("online"))) unavailableOwners.add(owner);
            }
        } catch (IOException membershipUnavailable) {
            // The per-request unavailable list is still usable if catalogue status cannot be read.
        }

        List<Map<String, Object>> previous = cacheList(cacheKey);
        if (previous == null) previous = List.of();
        List<Map<String, Object>> result = new ArrayList<>();
        List<Map<String, Object>> nextCache = new ArrayList<>();
        java.util.Set<String> liveOwners = new java.util.HashSet<>();
        java.util.Set<String> included = new java.util.HashSet<>();
        for (Map<String, Object> item : search.results()) {
            Map<String, Object> live = new LinkedHashMap<>(item);
            live.put("availability", "AVAILABLE");
            live.put("stale", false);
            String owner = optionalString(live, "ownerNodeId");
            if (!owner.isBlank()) liveOwners.add(owner);
            nextCache.add(new LinkedHashMap<>(item));
            if (result.size() < boundedLimit) {
                result.add(Map.copyOf(live));
                included.add(searchIdentity(live));
            }
        }

        // Retain the last result rows only for members known to be unreachable. Results from
        // reachable members are refreshed authoritatively and stale rows are discarded.
        for (Map<String, Object> cached : previous) {
            String owner = optionalString(cached, "ownerNodeId");
            if (owner.isBlank() || !unavailableOwners.contains(owner) || liveOwners.contains(owner)) continue;
            nextCache.add(new LinkedHashMap<>(cached));
            if (result.size() >= boundedLimit) continue;
            Map<String, Object> stale = new LinkedHashMap<>(cached);
            stale.put("availability", "UNAVAILABLE");
            stale.put("stale", true);
            stale.put("source", "CACHED");
            if (included.add(searchIdentity(stale))) result.add(Map.copyOf(stale));
        }
        putCache(cacheKey, nextCache);
        return List.copyOf(result.subList(0, Math.min(result.size(), boundedLimit)));
    }

    private static String searchIdentity(Map<String, Object> item) {
        return optionalString(item, "ownerNodeId") + "|" + optionalString(item, "storageId") + "|"
                + optionalString(item, "path") + "|" + optionalString(item, "name");
    }

    private List<String> deviceNames() throws IOException {
        return devices().stream().map(Device::displayName).sorted(String.CASE_INSENSITIVE_ORDER).toList();
    }

    private List<Device> devices() throws IOException {
        Map<String, Object> local = client.ping();
        String localId = string(local, "nodeId");
        String localName = string(local, "nodeName");
        List<Map<String, Object>> members;
        try { members = client.networkMembers(); }
        catch (IOException notJoinedOrUnavailable) { members = List.of(); }
        List<DeviceSeed> seeds = new ArrayList<>();
        boolean localFound = false;
        for (Map<String, Object> member : members) {
            String nodeId = optionalString(member, "nodeId");
            if (nodeId.isBlank()) continue;
            String name = firstNonBlank(optionalString(member, "nodeName"), optionalString(member, "name"), "Unknown device");
            boolean isLocal = nodeId.equals(localId);
            localFound |= isLocal;
            boolean online = isLocal || Boolean.TRUE.equals(member.get("online"));
            boolean active = "ACTIVE".equalsIgnoreCase(optionalString(member, "status"));
            seeds.add(new DeviceSeed(nodeId, name, isLocal, online && active, active));
        }
        if (!localFound) seeds.add(new DeviceSeed(localId, localName, true, true, true));
        Map<String, Long> counts = seeds.stream().collect(java.util.stream.Collectors.groupingBy(
                seed -> seed.name().toLowerCase(Locale.ROOT), java.util.stream.Collectors.counting()));
        List<Device> result = new ArrayList<>();
        for (DeviceSeed seed : seeds) {
            String display = seed.name();
            if (counts.getOrDefault(display.toLowerCase(Locale.ROOT), 0L) > 1) display += " [" + shortId(seed.nodeId()) + "]";
            result.add(new Device(seed.nodeId(), seed.name(), display, seed.local(), seed.online(), seed.active()));
        }
        result.sort(Comparator.comparing(device -> device.displayName().toLowerCase(Locale.ROOT)));
        return List.copyOf(result);
    }

    private Device requireDevice(String displayName) throws IOException {
        for (Device device : devices()) if (device.displayName().equals(displayName)) return device;
        throw new NoSuchFileException(displayName);
    }

    private List<ReferenceRootInfo> referenceRoots(Device device) throws IOException {
        if (device.local()) {
            return client.listReferences().stream().map(row -> new ReferenceRootInfo(
                    stringUnchecked(row, "id"), "", stringUnchecked(row, "name"), false, 0,
                    optionalString(row, "registeredAt"))).toList();
        }
        List<Map<String, Object>> rows = cachedList("references:" + device.nodeId(), () -> client.listRemoteNetworkReferences(device.nodeId()));
        List<ReferenceRootInfo> result = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String grantId = optionalString(row, "grantId");
            String kind = optionalString(row, "kind");
            boolean file = "FILE".equalsIgnoreCase(kind);
            String label = file ? optionalString(row, "name") : optionalString(row, "rootName");
            if (label.isBlank()) label = file ? "Shared file" : "Shared folder";
            result.add(new ReferenceRootInfo(optionalString(row, "referenceId"), grantId, label, file,
                    numberOrZero(row, "size"), optionalString(row, "modified")));
        }
        return disambiguateRoots(result);
    }

    private static List<ReferenceRootInfo> disambiguateRoots(List<ReferenceRootInfo> roots) {
        Map<String, Long> counts = roots.stream().collect(java.util.stream.Collectors.groupingBy(
                root -> root.displayName().toLowerCase(Locale.ROOT), java.util.stream.Collectors.counting()));
        List<ReferenceRootInfo> result = new ArrayList<>();
        for (ReferenceRootInfo root : roots) {
            String name = root.displayName();
            if (counts.getOrDefault(name.toLowerCase(Locale.ROOT), 0L) > 1) name += " [" + shortId(root.grantId()) + "]";
            result.add(new ReferenceRootInfo(root.referenceId(), root.grantId(), name, root.file(), root.size(), root.modified()));
        }
        return List.copyOf(result);
    }

    private ReferenceRootInfo requireReferenceRoot(Device device, String displayName) throws IOException {
        for (ReferenceRootInfo root : referenceRoots(device)) if (root.displayName().equals(displayName)) return root;
        throw new NoSuchFileException(displayName);
    }

    private List<Map<String, Object>> referenceEntries(Device device, ReferenceRootInfo root, String relative) throws IOException {
        if (device.local()) return client.listEntries(root.referenceId(), relative);
        String key = "reference-entries:" + device.nodeId() + ":" + root.grantId() + ":" + relative;
        return cachedList(key, () -> client.browseRemoteNetworkReference(device.nodeId(), root.grantId(), relative));
    }

    private Map<String, Object> referenceStat(Device device, ReferenceRootInfo root, String relative) throws IOException {
        if (device.local()) return client.stat(root.referenceId(), relative);
        String key = "reference-stat:" + device.nodeId() + ":" + root.grantId() + ":" + relative;
        Map<String, Object> cached = cachedMap(key);
        if (!device.online() && cached != null) return cached;
        try {
            Map<String, Object> live = client.statRemoteNetworkReference(device.nodeId(), root.grantId(), relative);
            putCache(key, live);
            return live;
        } catch (IOException unavailable) {
            if (cached != null) return cached;
            throw unavailable;
        }
    }

    private List<Map<String, Object>> managedFiles(Device device) throws IOException {
        if (device.local()) return client.listLocalManagedFiles();
        return cachedList("managed:" + device.nodeId(), () -> client.listRemoteManagedFiles(device.nodeId()));
    }

    private List<String> managedChildren(Device device, String relativeDirectory) throws IOException {
        String prefix = relativeDirectory.isBlank() ? "" : relativeDirectory + "/";
        Map<String, Boolean> names = new LinkedHashMap<>();
        for (Map<String, Object> file : managedFiles(device)) {
            String path = optionalString(file, "path");
            if (!path.startsWith(prefix) || path.equals(relativeDirectory)) continue;
            String remainder = path.substring(prefix.length());
            if (remainder.isBlank()) continue;
            int separator = remainder.indexOf('/');
            names.put(separator < 0 ? remainder : remainder.substring(0, separator), separator >= 0);
        }
        return names.keySet().stream().sorted(String.CASE_INSENSITIVE_ORDER).toList();
    }

    private boolean hasManagedDescendant(Device device, String relativeDirectory) throws IOException {
        String prefix = relativeDirectory + "/";
        for (Map<String, Object> file : managedFiles(device)) {
            String path = optionalString(file, "path");
            if (path.startsWith(prefix)) return true;
        }
        return false;
    }

    private Map<String, Object> findManagedFile(Device device, String relativePath) throws IOException {
        for (Map<String, Object> file : managedFiles(device)) {
            if (relativePath.equals(optionalString(file, "path"))) return file;
        }
        return null;
    }

    private synchronized List<Map<String, Object>> cachedList(String key, ListLoader loader) throws IOException {
        try {
            List<Map<String, Object>> live = loader.load();
            putCache(key, live);
            return live;
        } catch (IOException failure) {
            List<Map<String, Object>> stale = cacheList(key);
            if (stale != null) return stale;
            throw failure;
        }
    }

    @FunctionalInterface private interface ListLoader { List<Map<String, Object>> load() throws IOException; }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> cacheList(String key) {
        Object value = cache.get(key);
        if (!(value instanceof List<?> list)) return null;
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object row : list) if (row instanceof Map<?, ?> map) {
            Map<String, Object> typed = new LinkedHashMap<>();
            map.forEach((name, field) -> typed.put(String.valueOf(name), field));
            result.add(typed);
        }
        return List.copyOf(result);
    }

    private Map<String, Object> cachedMap(String key) {
        Object value = cache.get(key);
        if (!(value instanceof Map<?, ?> map)) return null;
        Map<String, Object> result = new LinkedHashMap<>();
        map.forEach((name, field) -> result.put(String.valueOf(name), field));
        return result;
    }

    private synchronized void putCache(String key, Object value) throws IOException {
        cache.put(key, value);
        Files.createDirectories(cacheFile.getParent());
        Path temporary = Files.createTempFile(cacheFile.getParent(), ".filesystem-cache-", ".part");
        try {
            Files.writeString(temporary, Json.stringify(cache), StandardOpenOption.TRUNCATE_EXISTING);
            try { Files.move(temporary, cacheFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, cacheFile, StandardCopyOption.REPLACE_EXISTING);
            }
            try { Files.setPosixFilePermissions(cacheFile, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); }
            catch (UnsupportedOperationException ignored) { }
        } finally { Files.deleteIfExists(temporary); }
    }

    private Map<String, Object> loadCache() {
        try {
            if (!Files.isRegularFile(cacheFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(cacheFile)) return new LinkedHashMap<>();
            Map<String, Object> loaded = Json.object(Files.readString(cacheFile));
            return new LinkedHashMap<>(loaded);
        } catch (Exception invalidOrUnavailable) { return new LinkedHashMap<>(); }
    }

    private static List<String> segments(String path) throws NoSuchFileException {
        if (path == null || path.isBlank() || "/".equals(path)) return List.of();
        if (!path.startsWith("/")) throw new NoSuchFileException(path);
        String[] raw = path.substring(1).split("/", -1);
        List<String> result = new ArrayList<>();
        for (String item : raw) {
            if (item.isEmpty()) continue;
            if (item.equals(".") || item.equals("..") || item.indexOf('\0') >= 0 || item.indexOf('\\') >= 0) throw new NoSuchFileException(path);
            result.add(item);
        }
        return List.copyOf(result);
    }

    private static String string(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof String text)) throw new IOException("Filesystem metadata omitted field '" + key + "'.");
        return text;
    }
    private static String stringUnchecked(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value instanceof String text ? text : "";
    }
    private static String optionalString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value instanceof String text ? text : "";
    }
    private static long number(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof Number number)) throw new IOException("Filesystem metadata omitted numeric field '" + key + "'.");
        return number.longValue();
    }
    private static long numberOrZero(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value instanceof Number number ? number.longValue() : 0L;
    }
    private static String firstNonBlank(String first, String second, String fallback) {
        if (first != null && !first.isBlank()) return first;
        if (second != null && !second.isBlank()) return second;
        return fallback;
    }
    private static String shortId(String id) {
        if (id == null || id.isBlank()) return "unknown";
        String compact = id.replaceAll("[^A-Za-z0-9]", "");
        return compact.substring(0, Math.min(8, compact.length()));
    }

    public record Attributes(boolean directory, long sizeBytes, String modifiedAt, boolean available) {
        public Attributes(boolean directory, long sizeBytes, String modifiedAt) { this(directory, sizeBytes, modifiedAt, true); }
    }
    private record DeviceSeed(String nodeId, String name, boolean local, boolean online, boolean active) { }
    private record Device(String nodeId, String name, String displayName, boolean local, boolean online, boolean active) { }
    private record ReferenceRootInfo(String referenceId, String grantId, String displayName, boolean file,
                                     long size, String modified) { }
}
