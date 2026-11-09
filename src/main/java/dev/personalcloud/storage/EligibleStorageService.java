package dev.personalcloud.storage;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.SecretFiles;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.policy.ApprovalRequiredException;
import dev.personalcloud.policy.FilesystemPolicyService;
import dev.personalcloud.policy.PolicyDecision;
import dev.personalcloud.policy.PolicyOperation;
import dev.personalcloud.policy.ProtectionApprovalService;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Default broad filesystem access to owner-authorized roots, with source-side
 * privacy/protection enforcement and safe atomic writes.
 *
 * <p>Broad access is disabled until the owner records one-time consent. This
 * prevents an upgrade from silently exposing existing files.</p>
 */
public final class EligibleStorageService {
    private static final String CONSENT_KEY = "filesystem.consent";
    private static final List<String> SYSTEM_PREFIXES = List.of(
            "/proc", "/sys", "/dev", "/run", "/etc", "/var", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/root");
    private static final List<String> CREDENTIAL_PATHS = List.of(
            ".ssh", ".gnupg", ".pki", ".password-store", ".local/share/keyrings", ".aws", ".azure", ".kube",
            ".docker/config.json", ".config/gh", ".config/glab-cli", ".config/google-chrome", ".config/chromium",
            ".config/BraveSoftware", ".config/microsoft-edge", ".mozilla", ".netrc", ".git-credentials", ".npmrc");

    private final AppConfig config;
    private final StateStore state;
    private final FilesystemPolicyService policy;
    private final ProtectionApprovalService approvals;
    private final List<EligibleRoot> roots;
    private final List<Path> excluded;

    public EligibleStorageService(AppConfig config, StateStore state, FilesystemPolicyService policy,
                                  ProtectionApprovalService approvals) {
        this(config, state, policy, approvals, configuredRoots());
    }

    public EligibleStorageService(AppConfig config, StateStore state, FilesystemPolicyService policy,
                                  ProtectionApprovalService approvals, List<Path> suppliedRoots) {
        this.config = config;
        this.state = state;
        this.policy = policy;
        this.approvals = approvals;
        this.roots = buildRoots(suppliedRoots);
        this.excluded = buildExclusions();
    }

    public boolean consentGranted() {
        String value = state.get(CONSENT_KEY);
        return value != null && !value.isBlank();
    }

    /** Records explicit owner consent before broad filesystem access is exposed. */
    public synchronized Map<String, Object> grantConsent() throws Exception {
        state.put(CONSENT_KEY, Instant.now().toString());
        return status();
    }

    /** Immediately disables broad filesystem access without deleting any user files. */
    public synchronized Map<String, Object> revokeConsent() throws Exception {
        state.remove(CONSENT_KEY);
        return status();
    }

    public Map<String, Object> status() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("consentGranted", consentGranted());
        result.put("roots", rootsForOwner());
        result.put("epoch", policy.epoch());
        result.put("excludedCount", excluded.size());
        return result;
    }

    public List<Map<String, Object>> rootsForOwner() {
        return roots.stream().map(EligibleRoot::toOwnerMap).toList();
    }

    public List<Map<String, Object>> rootsForMember() {
        requireConsent();
        return roots.stream().map(EligibleRoot::toRemoteMap).toList();
    }

    public List<Map<String, Object>> list(String memberId, String rootId, String relativePath) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        authorize(memberId, root, path, PolicyOperation.LIST, null);
        Path directory = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, directory);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The requested path is not a directory.");
        }
        List<Map<String, Object>> entries = new ArrayList<>();
        try (var children = Files.list(directory)) {
            for (Path child : children.sorted(Comparator.comparing(item -> item.getFileName().toString())).toList()) {
                String childRelative = path.isEmpty() ? child.getFileName().toString() : path + "/" + child.getFileName();
                if (Files.isSymbolicLink(child) || !policy.isVisible(root.id(), childRelative)) continue;
                BasicFileAttributes attributes;
                try {
                    attributes = Files.readAttributes(child, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                } catch (Exception unavailable) {
                    continue;
                }
                if (!attributes.isRegularFile() && !attributes.isDirectory()) continue;
                if (isExcluded(child)) continue;
                entries.add(entry(root, childRelative, child.getFileName().toString(), attributes));
            }
        }
        return List.copyOf(entries);
    }

    public Map<String, Object> stat(String memberId, String rootId, String relativePath) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        authorize(memberId, root, path, PolicyOperation.STAT, null);
        Path target = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, target);
        BasicFileAttributes attributes = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() && !attributes.isDirectory()) {
            throw new IllegalArgumentException("Only regular files and directories are accessible.");
        }
        return entry(root, path, path.isEmpty() ? root.name() : target.getFileName().toString(), attributes);
    }

    public InputStream open(String memberId, String rootId, String relativePath) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        authorize(memberId, root, path, PolicyOperation.READ, null);
        Path target = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, target);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The requested path is not a regular file.");
        }
        return Files.newInputStream(target, LinkOption.NOFOLLOW_LINKS);
    }

    public String sha256(String memberId, String rootId, String relativePath) throws Exception {
        try (InputStream input = open(memberId, rootId, relativePath)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
            return HexFormat.of().formatHex(digest.digest());
        }
    }

    public Map<String, Object> write(String memberId, String rootId, String relativePath, InputStream content,
                                     long declaredSize, String declaredSha256, boolean overwrite,
                                     String approvalId) throws Exception {
        return writeInternal(memberId, rootId, relativePath, content, declaredSize, declaredSha256,
                overwrite, approvalId, false);
    }

    /**
     * Publishes a coordinated destination after the destination has already
     * authorized the ticket. The authorization record is durable, so a retry
     * after a crash or lost response is idempotent and does not consume a new
     * owner approval.
     */
    public Map<String, Object> writeCoordinated(String requesterId, String rootId, String relativePath,
                                                InputStream content, long declaredSize, String declaredSha256,
                                                boolean overwrite, String approvalId, String ticketId) throws Exception {
        authorizeCoordinatedWrite(requesterId, rootId, relativePath, overwrite,
                approvalId, ticketId, declaredSize, declaredSha256);
        return writeInternal(requesterId, rootId, relativePath, content, declaredSize, declaredSha256,
                overwrite, "", true);
    }

    private Map<String, Object> writeInternal(String memberId, String rootId, String relativePath,
                                              InputStream content, long declaredSize, String declaredSha256,
                                              boolean overwrite, String approvalId,
                                              boolean coordinated) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        if (path.isEmpty()) throw new IllegalArgumentException("A file path is required.");
        if (declaredSize < 0 || declaredSize > config.maxFileBytes()) {
            throw new IllegalArgumentException("The declared file size is outside the permitted limit.");
        }
        Path target = resolve(root, path, false);
        boolean exists = Files.exists(target, LinkOption.NOFOLLOW_LINKS);
        BasicFileAttributes before = null;
        if (exists) {
            if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("The destination is not a regular file.");
            }
            if (coordinated && declaredSha256 != null && !declaredSha256.isBlank()
                    && Files.size(target) == declaredSize
                    && digest(target).equalsIgnoreCase(declaredSha256)) {
                BasicFileAttributes existing = Files.readAttributes(target, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                Map<String, Object> result = entry(root, path, target.getFileName().toString(), existing);
                result.put("sha256", declaredSha256.toLowerCase(java.util.Locale.ROOT));
                return result;
            }
            if (!overwrite) throw new IllegalStateException("The destination already exists; overwrite was not authorized.");
            if (!coordinated) authorize(memberId, root, path, PolicyOperation.WRITE, approvalId);
            before = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } else {
            if (!coordinated) authorize(memberId, root, path, PolicyOperation.CREATE, approvalId);
        }

        Path parent = target.getParent();
        Path realParent = parent.toRealPath();
        Path realTarget = realParent.resolve(target.getFileName());
        if (!realParent.startsWith(root.realPath()) || isExcluded(realTarget)) {
            throw new SecurityException("The destination is outside eligible storage.");
        }
        if (exists) {
            if (!target.toRealPath().equals(realTarget)) {
                throw new SecurityException("The destination changed while the upload was being prepared.");
            }
        } else if (Files.exists(realTarget, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("The destination appeared while the upload was being prepared.");
        }
        Path temporary = Files.createTempFile(realParent, ".personalcloud-fs-upload-", ".part");
        SecretFiles.restrict(temporary);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            byte[] buffer = new byte[128 * 1024];
            try (OutputStream output = Files.newOutputStream(temporary, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                int read;
                while ((read = content.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > declaredSize || copied > config.maxFileBytes()) {
                        throw new IllegalArgumentException("The upload exceeded its declared or permitted size.");
                    }
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
                output.flush();
            }
            if (copied != declaredSize) throw new IllegalArgumentException("The upload did not match its declared size.");
            String actualHash = HexFormat.of().formatHex(digest.digest());
            if (declaredSha256 != null && !declaredSha256.isBlank()
                    && !MessageDigest.isEqual(declaredSha256.toLowerCase(java.util.Locale.ROOT)
                    .getBytes(StandardCharsets.US_ASCII), actualHash.getBytes(StandardCharsets.US_ASCII))) {
                throw new SecurityException("The upload failed SHA-256 integrity verification.");
            }
            if (before != null && sourceChanged(realTarget, before)) {
                throw new SecurityException("The destination changed while the upload was in progress.");
            }
            if (exists) {
                try {
                    Files.move(temporary, realTarget, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException fallback) {
                    Files.move(temporary, realTarget, StandardCopyOption.REPLACE_EXISTING);
                }
            } else {
                try {
                    // createLink is atomic create-if-absent; Files.move may replace a
                    // racing destination on some providers.
                    Files.createLink(realTarget, temporary);
                } catch (FileAlreadyExistsException raced) {
                    throw new IllegalStateException("The destination appeared during the upload; nothing was overwritten.", raced);
                }
                Files.deleteIfExists(temporary);
            }
            BasicFileAttributes after = Files.readAttributes(realTarget, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Map<String, Object> result = entry(root, path, realTarget.getFileName().toString(), after);
            result.put("sha256", actualHash);
            return result;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    public Map<String, Object> createDirectory(String memberId, String rootId, String relativePath) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        if (path.isEmpty()) throw new IllegalArgumentException("A directory path is required.");
        Path target = resolve(root, path, false);
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("The destination already exists.");
        }
        authorize(memberId, root, path, PolicyOperation.CREATE, null);
        Path parent = target.getParent();
        Path realParent = parent.toRealPath();
        Path realTarget = realParent.resolve(target.getFileName());
        if (!realParent.startsWith(root.realPath()) || isExcluded(realTarget)) {
            throw new SecurityException("The destination is outside eligible storage.");
        }
        Files.createDirectory(realTarget);
        BasicFileAttributes attributes = Files.readAttributes(realTarget, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return entry(root, path, target.getFileName().toString(), attributes);
    }

    public Map<String, Object> move(String memberId, String rootId, String fromPath, String toPath,
                                    boolean overwrite, String approvalId) throws Exception {
        return move(memberId, rootId, fromPath, toPath, overwrite, approvalId, "");
    }

    /**
     * Moves an entry and requires separate approvals for the source move and a
     * protected destination overwrite. The two approvals are bound to different
     * paths, so one approval can never authorize both legs.
     */
    public Map<String, Object> move(String memberId, String rootId, String fromPath, String toPath,
                                    boolean overwrite, String sourceApprovalId,
                                    String destinationApprovalId) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String from = normalizeRelative(fromPath);
        String to = normalizeRelative(toPath);
        if (from.isEmpty() || to.isEmpty()) throw new IllegalArgumentException("Both source and destination paths are required.");
        Path source = resolve(root, from, true).toRealPath();
        requireWithinRoot(root, source);
        Path destination = resolve(root, to, false);
        if (source.equals(root.realPath())) throw new SecurityException("The eligible root itself cannot be moved.");
        Path parent = destination.getParent();
        Path realParent = parent.toRealPath();
        Path realDestination = realParent.resolve(destination.getFileName());
        if (!realParent.startsWith(root.realPath()) || isExcluded(realDestination)) {
            throw new SecurityException("The destination is outside eligible storage.");
        }
        if (source.equals(realDestination)) {
            throw new IllegalArgumentException("Source and destination must differ.");
        }
        if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS) && realDestination.startsWith(source)) {
            throw new IllegalArgumentException("A directory cannot be moved inside itself.");
        }
        boolean destinationExists = Files.exists(realDestination, LinkOption.NOFOLLOW_LINKS);
        if (destinationExists && Files.isSymbolicLink(realDestination)) {
            throw new SecurityException("Symbolic links are not accessible through PersonalCloud.");
        }
        if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
            ensureNoSensitiveDescendants(root, source, from);
        }
        if (destinationExists && !overwrite) {
            throw new IllegalStateException("The destination already exists; overwrite was not authorized.");
        }
        PolicyOperation destinationOperation = destinationExists ? PolicyOperation.WRITE : PolicyOperation.CREATE;
        PolicyDecision sourceDecision = decide(memberId, root, from, PolicyOperation.MOVE);
        PolicyDecision destinationDecision = decide(memberId, root, to, destinationOperation);
        if (sourceDecision == PolicyDecision.REQUIRE_APPROVAL && isBlank(sourceApprovalId)) {
            throw new ApprovalRequiredException(root.id(), from, PolicyOperation.MOVE);
        }
        if (destinationDecision == PolicyDecision.REQUIRE_APPROVAL && isBlank(destinationApprovalId)) {
            throw new ApprovalRequiredException(root.id(), to, destinationOperation);
        }
        consumeApproval(memberId, root, from, PolicyOperation.MOVE, sourceDecision, sourceApprovalId);
        consumeApproval(memberId, root, to, destinationOperation, destinationDecision, destinationApprovalId);
        try {
            if (destinationExists) {
                Files.move(source, realDestination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } else {
                Files.move(source, realDestination, StandardCopyOption.ATOMIC_MOVE);
            }
        } catch (AtomicMoveNotSupportedException fallback) {
            if (destinationExists) Files.move(source, realDestination, StandardCopyOption.REPLACE_EXISTING);
            else Files.move(source, realDestination);
        }
        BasicFileAttributes attributes = Files.readAttributes(realDestination, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Map<String, Object> result = entry(root, to, realDestination.getFileName().toString(), attributes);
        result.put("from", from);
        return result;
    }

    public Map<String, Object> delete(String memberId, String rootId, String relativePath,
                                      boolean recursive, String approvalId) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        if (path.isEmpty()) throw new SecurityException("The eligible root itself cannot be deleted.");
        Path target = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, target);
        if (target.equals(root.realPath())) throw new SecurityException("The eligible root itself cannot be deleted.");
        PolicyOperation operation = recursive ? PolicyOperation.BULK_DELETE : PolicyOperation.DELETE;
        authorize(memberId, root, path, operation, approvalId);
        boolean directory = Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS);
        if (recursive && directory) {
            ensureNoSensitiveDescendants(root, target, path);
            try (var paths = Files.walk(target)) {
                for (Path item : paths.sorted(Comparator.reverseOrder()).toList()) {
                    if (item.equals(target)) continue;
                    Files.deleteIfExists(item);
                }
            }
        }
        Files.delete(target);
        return Map.of("ok", true, "rootId", root.id(), "path", path, "deleted", true, "recursive", recursive);
    }

    public Map<String, Object> requestApproval(String memberId, String rootId, String relativePath,
                                               PolicyOperation operation, long ttlSeconds) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        resolve(root, path, true);
        PolicyDecision decision = policy.evaluate(root.id(), path, operation);
        if (decision == PolicyDecision.DENY) {
            throw new SecurityException("This resource is private and cannot be accessed remotely.");
        }
        if (decision != PolicyDecision.REQUIRE_APPROVAL) {
            throw new IllegalArgumentException("This operation does not require owner approval.");
        }
        return approvals.request(memberId, root.id(), path, operation, ttlSeconds);
    }

    public Map<String, Object> approvalStatus(String memberId, String approvalId) {
        Map<String, Object> approval = approvals.status(approvalId);
        if (!memberId.equals(String.valueOf(approval.get("memberId")))) {
            throw new SecurityException("The approval belongs to a different member.");
        }
        return approval;
    }

    /** Source metadata for a coordinated ticket: size, SHA-256 and an opaque version binding. */
    public Map<String, Object> transferMetadata(String memberId, String rootId, String relativePath) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        authorize(memberId, root, path, PolicyOperation.READ, null);
        Path target = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, target);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The requested path is not a regular file.");
        }
        return sourceMetadata(root, path, target);
    }

    /** Destination existence, operation and approval requirement for planning a coordinated transfer. */
    public Map<String, Object> destinationMetadata(String memberId, String rootId, String relativePath) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        if (path.isEmpty()) throw new IllegalArgumentException("A destination file path is required.");
        Path target = resolve(root, path, false);
        boolean exists = Files.exists(target, LinkOption.NOFOLLOW_LINKS);
        PolicyOperation operation = exists ? PolicyOperation.WRITE : PolicyOperation.CREATE;
        PolicyDecision decision = policy.evaluate(root.id(), path, operation);
        if (decision == PolicyDecision.DENY) {
            throw new SecurityException("This resource is private and cannot be accessed remotely.");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rootId", root.id());
        result.put("path", path);
        result.put("exists", exists);
        result.put("operation", operation.name());
        result.put("approvalRequired", decision == PolicyDecision.REQUIRE_APPROVAL);
        if (exists) {
            if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("The destination is not a regular file.");
            }
            BasicFileAttributes attributes = Files.readAttributes(target, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            result.put("size", attributes.size());
            result.put("sha256", digest(target));
            result.put("modified", attributes.lastModifiedTime().toInstant().toString());
        }
        return result;
    }

    public record CoordinatedSource(Path path, Map<String, Object> metadata) { }

    /**
     * Verifies that the ticket's source binding still matches the owner's file
     * and durably records the source authorization. A retry with the same
     * ticket reuses the record instead of consuming another owner approval.
     */
    public CoordinatedSource authorizeCoordinatedSource(String requesterId, String rootId, String relativePath,
                                                        String operation, String approvalId, String ticketId,
                                                        long expectedSize, String expectedSha256,
                                                        String expectedVersion) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        if (path.isEmpty()) throw new IllegalArgumentException("A source file path is required.");
        String normalizedOperation = operation == null ? "" : operation.toUpperCase(java.util.Locale.ROOT);
        if (!normalizedOperation.equals("COPY") && !normalizedOperation.equals("MOVE")) {
            throw new IllegalArgumentException("Coordinated source operation must be COPY or MOVE.");
        }
        PolicyOperation policyOperation = normalizedOperation.equals("MOVE")
                ? PolicyOperation.MOVE : PolicyOperation.READ;
        Path target = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, target);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The coordinated source is not a regular file.");
        }
        Map<String, Object> metadata = sourceMetadata(root, path, target);
        verifyMetadata(metadata, expectedSize, expectedSha256, expectedVersion);
        String recordId = requireText(ticketId, "Ticket ID") + "-source";
        Map<String, String> existing = state.getRecord(COORDINATED_AUTHORIZATION, recordId);
        if (existing != null) {
            verifyAuthorizationRecord(existing, requesterId, root.id(), path, policyOperation);
            return new CoordinatedSource(target, metadata);
        }
        PolicyDecision decision = decide(requesterId, root, path, policyOperation);
        if (decision == PolicyDecision.REQUIRE_APPROVAL) {
            if (isBlank(approvalId)) throw new ApprovalRequiredException(root.id(), path, policyOperation);
            if (!approvals.consume(approvalId, requesterId, root.id(), path, policyOperation)) {
                throw new SecurityException("The supplied owner approval is invalid, expired, already used, or bound to a different operation.");
            }
        }
        persistAuthorization(recordId, "SOURCE", requesterId, root.id(), path, policyOperation,
                false, expectedSize, expectedSha256, expectedVersion);
        return new CoordinatedSource(target, metadata);
    }

    /** Revalidates the source binding immediately before any source deletion. */
    public Map<String, Object> verifyCoordinatedSourceUnchanged(String requesterId, String rootId,
                                                                String relativePath, String operation,
                                                                String ticketId, long expectedSize,
                                                                String expectedSha256, String expectedVersion) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        String normalizedOperation = operation == null ? "" : operation.toUpperCase(java.util.Locale.ROOT);
        PolicyOperation policyOperation = normalizedOperation.equals("MOVE")
                ? PolicyOperation.MOVE : PolicyOperation.READ;
        Map<String, String> authorization = state.getRecord(COORDINATED_AUTHORIZATION,
                requireText(ticketId, "Ticket ID") + "-source");
        if (authorization == null) throw new SecurityException("No durable source authorization exists for this ticket.");
        verifyAuthorizationRecord(authorization, requesterId, root.id(), path, policyOperation);
        if (policy.evaluate(root.id(), path, policyOperation) == PolicyDecision.DENY) {
            throw new SecurityException("This resource is private and cannot be accessed remotely.");
        }
        Path target = resolve(root, path, true).toRealPath();
        requireWithinRoot(root, target);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("The coordinated source is no longer a regular file.");
        }
        Map<String, Object> metadata = sourceMetadata(root, path, target);
        verifyMetadata(metadata, expectedSize, expectedSha256, expectedVersion);
        return metadata;
    }

    /**
     * Deletes a coordinated MOVE source only after the destination committed
     * and the source was revalidated. The durable source authorization covers
     * the move; no second destructive approval is consumed.
     */
    public Map<String, Object> deleteCoordinatedSource(String requesterId, String rootId, String relativePath,
                                                       String ticketId, long expectedSize,
                                                       String expectedSha256, String expectedVersion) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        Map<String, String> authorization = state.getRecord(COORDINATED_AUTHORIZATION,
                requireText(ticketId, "Ticket ID") + "-source");
        if (authorization == null) throw new SecurityException("No durable source authorization exists for this ticket.");
        verifyAuthorizationRecord(authorization, requesterId, root.id(), path, PolicyOperation.MOVE);
        Path target = resolve(root, path, false);
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            return Map.of("deleted", false, "alreadyAbsent", true, "rootId", root.id(), "path", path);
        }
        target = target.toRealPath();
        requireWithinRoot(root, target);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("The coordinated source is no longer a regular file.");
        }
        if (policy.evaluate(root.id(), path, PolicyOperation.MOVE) == PolicyDecision.DENY) {
            throw new SecurityException("This resource is private and cannot be accessed remotely.");
        }
        Map<String, Object> metadata = sourceMetadata(root, path, target);
        verifyMetadata(metadata, expectedSize, expectedSha256, expectedVersion);
        Files.delete(target);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("deleted", true);
        result.put("rootId", root.id());
        result.put("path", path);
        result.put("size", expectedSize);
        result.put("sha256", String.valueOf(metadata.get("sha256")));
        return result;
    }

    /**
     * Authorizes a coordinated destination write and durably records it. The
     * approval is bound to the coordinating member, not the source uploader.
     */
    public Map<String, Object> authorizeCoordinatedWrite(String requesterId, String rootId, String relativePath,
                                                         boolean overwrite, String approvalId, String ticketId,
                                                         long expectedSize, String expectedSha256) throws Exception {
        requireConsent();
        EligibleRoot root = root(rootId);
        String path = normalizeRelative(relativePath);
        if (path.isEmpty()) throw new IllegalArgumentException("A destination file path is required.");
        if (expectedSize < 0 || expectedSize > config.maxFileBytes()) {
            throw new IllegalArgumentException("The declared file size is outside the permitted limit.");
        }
        Path target = resolve(root, path, false);
        boolean exists = Files.exists(target, LinkOption.NOFOLLOW_LINKS);
        if (exists && !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The destination is not a regular file.");
        }
        boolean identical = exists && expectedSha256 != null && !expectedSha256.isBlank()
                && Files.size(target) == expectedSize
                && digest(target).equalsIgnoreCase(expectedSha256);
        if (exists && !overwrite && !identical) {
            throw new IllegalStateException("The destination already exists; overwrite was not authorized.");
        }
        PolicyOperation operation = exists ? PolicyOperation.WRITE : PolicyOperation.CREATE;
        String recordId = requireText(ticketId, "Ticket ID") + "-destination";
        Map<String, String> existing = state.getRecord(COORDINATED_AUTHORIZATION, recordId);
        if (existing != null) {
            boolean sameBinding = requesterId.equals(existing.get("memberId"))
                    && root.id().equals(existing.get("rootId"))
                    && path.equals(existing.get("path"));
            // A retry after a successful commit may observe the newly created
            // destination as an existing file. Accept it only when its bytes
            // exactly match the ticket, so re-authorization stays idempotent.
            boolean sameOperation = operation.name().equals(existing.get("operation"));
            if (!sameBinding || (!sameOperation && !identical)) {
                throw new SecurityException("The coordinated authorization is bound to a different member, resource or operation.");
            }
            return Map.of("rootId", root.id(), "path", path, "operation", operation.name(),
                    "overwrite", overwrite, "authorized", true);
        }
        PolicyDecision decision = decide(requesterId, root, path, operation);
        if (decision == PolicyDecision.REQUIRE_APPROVAL) {
            if (isBlank(approvalId)) throw new ApprovalRequiredException(root.id(), path, operation);
            if (!approvals.consume(approvalId, requesterId, root.id(), path, operation)) {
                throw new SecurityException("The supplied owner approval is invalid, expired, already used, or bound to a different operation.");
            }
        }
        persistAuthorization(recordId, "DESTINATION", requesterId, root.id(), path, operation,
                overwrite, expectedSize, expectedSha256, "");
        return Map.of("rootId", root.id(), "path", path, "operation", operation.name(),
                "overwrite", overwrite, "authorized", true);
    }

    private static final String COORDINATED_AUTHORIZATION = "coordinatedAuthorization";

    private void persistAuthorization(String recordId, String role, String memberId, String rootId, String path,
                                      PolicyOperation operation, boolean overwrite, long size, String sha256,
                                      String version) throws Exception {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("role", role);
        row.put("memberId", memberId);
        row.put("rootId", rootId);
        row.put("path", path);
        row.put("operation", operation.name());
        row.put("overwrite", Boolean.toString(overwrite));
        row.put("size", Long.toString(size));
        row.put("sha256", sha256 == null ? "" : sha256.toLowerCase(java.util.Locale.ROOT));
        row.put("version", version == null ? "" : version);
        row.put("authorizedAt", Instant.now().toString());
        state.putRecord(COORDINATED_AUTHORIZATION, recordId, row);
    }

    private static void verifyAuthorizationRecord(Map<String, String> row, String memberId, String rootId,
                                                  String path, PolicyOperation operation) {
        boolean matches = memberId.equals(row.get("memberId"))
                && rootId.equals(row.get("rootId"))
                && path.equals(row.get("path"))
                && operation.name().equals(row.get("operation"));
        if (!matches) {
            throw new SecurityException("The coordinated authorization is bound to a different member, resource or operation.");
        }
    }

    private static void verifyMetadata(Map<String, Object> metadata, long expectedSize, String expectedSha256,
                                       String expectedVersion) {
        long actualSize = ((Number) metadata.get("size")).longValue();
        String actualSha = String.valueOf(metadata.get("sha256"));
        String actualVersion = String.valueOf(metadata.get("version"));
        boolean matches = actualSize == expectedSize
                && expectedSha256 != null && actualSha.equalsIgnoreCase(expectedSha256)
                && expectedVersion != null && actualVersion.equals(expectedVersion);
        if (!matches) {
            throw new SecurityException("The coordinated source changed after its ticket was issued.");
        }
    }

    private Map<String, Object> sourceMetadata(EligibleRoot root, String path, Path target) throws Exception {
        BasicFileAttributes attributes = Files.readAttributes(target, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rootId", root.id());
        result.put("path", path);
        result.put("name", target.getFileName().toString());
        result.put("kind", "FILE");
        result.put("size", attributes.size());
        result.put("modified", attributes.lastModifiedTime().toInstant().toString());
        result.put("sha256", digest(target));
        result.put("version", version(attributes));
        return result;
    }

    private static String version(BasicFileAttributes attributes) throws Exception {
        String binding = attributes.size() + "|" + attributes.lastModifiedTime().toMillis()
                + "|" + String.valueOf(attributes.fileKey());
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(binding.getBytes(StandardCharsets.UTF_8)));
    }

    private static String digest(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required.");
        return value;
    }

    private void authorize(String memberId, EligibleRoot root, String path, PolicyOperation operation,
                           String approvalId) throws Exception {
        PolicyDecision decision = decide(memberId, root, path, operation);
        consumeApproval(memberId, root, path, operation, decision, approvalId);
    }

    private PolicyDecision decide(String memberId, EligibleRoot root, String path, PolicyOperation operation) {
        if (memberId == null || memberId.isBlank()) throw new SecurityException("An authenticated member is required.");
        PolicyDecision decision = policy.evaluate(root.id(), path, operation);
        if (decision == PolicyDecision.DENY) {
            throw new SecurityException("This resource is private and cannot be accessed remotely.");
        }
        return decision;
    }

    private void consumeApproval(String memberId, EligibleRoot root, String path, PolicyOperation operation,
                                 PolicyDecision decision, String approvalId) throws Exception {
        if (decision != PolicyDecision.REQUIRE_APPROVAL) return;
        if (isBlank(approvalId)) throw new ApprovalRequiredException(root.id(), path, operation);
        if (!approvals.consume(approvalId, memberId, root.id(), path, operation)) {
            throw new SecurityException("The supplied owner approval is invalid, expired, already used, or bound to a different operation.");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void requireConsent() {
        if (!consentGranted()) {
            throw new SecurityException("The device owner has not confirmed broad filesystem access. Run the local 'filesystem consent' command on the owning device.");
        }
    }

    private EligibleRoot root(String rootId) {
        if (rootId == null || rootId.isBlank()) throw new IllegalArgumentException("An eligible root ID is required.");
        for (EligibleRoot root : roots) if (root.id().equals(rootId)) return root;
        throw new IllegalArgumentException("Eligible filesystem root was not found.");
    }

    private void requireWithinRoot(EligibleRoot root, Path realPath) {
        if (!realPath.startsWith(root.realPath()) || isExcluded(realPath)) {
            throw new SecurityException("Path escapes eligible storage.");
        }
    }

    private Path resolve(EligibleRoot root, String relativePath, boolean mustExist) throws Exception {
        if (!isOwnedByCurrentUser(root.realPath())) {
            throw new SecurityException("The eligible root is no longer owned by this device's OS user.");
        }
        String relative = normalizeRelative(relativePath);
        Path current = root.path();
        if (!relative.isEmpty()) {
            for (String segment : relative.split("/", -1)) {
                if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                    throw new IllegalArgumentException("Path contains an invalid segment.");
                }
                current = current.resolve(segment).normalize();
                if (!current.startsWith(root.path())) throw new SecurityException("Path escapes the eligible root.");
                if (Files.isSymbolicLink(current)) throw new SecurityException("Symbolic links are not accessible through PersonalCloud.");
            }
        }
        if (!current.startsWith(root.path())) throw new SecurityException("Path escapes the eligible root.");
        if (mustExist && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The requested path does not exist.");
        }
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(current)) throw new SecurityException("Symbolic links are not accessible through PersonalCloud.");
            Path real = current.toRealPath();
            if (!real.startsWith(root.realPath())) throw new SecurityException("Path escapes the eligible root.");
            if (isExcluded(real)) throw new SecurityException("This path is excluded from automatic network exposure.");
        } else {
            Path parent = current.getParent();
            if (parent == null || Files.isSymbolicLink(parent) || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("The destination parent directory does not exist.");
            }
            Path realParent = parent.toRealPath();
            if (!realParent.startsWith(root.realPath())) throw new SecurityException("Path escapes the eligible root.");
            if (isExcluded(realParent.resolve(current.getFileName()))) {
                throw new SecurityException("This path is excluded from automatic network exposure.");
            }
        }
        return current;
    }

    private void ensureNoSensitiveDescendants(EligibleRoot root, Path realTarget, String relativePath) throws Exception {
        for (Map<String, Object> rule : policy.list()) {
            if (!root.id().equals(String.valueOf(rule.get("rootId")))) continue;
            String rulePath = String.valueOf(rule.get("path"));
            if (rulePath.isEmpty() || rulePath.equals(relativePath)) continue;
            if (rulePath.startsWith(relativePath + "/")) {
                throw new SecurityException("This directory contains owner-protected or private descendants; operate on those paths explicitly.");
            }
        }
        try (var paths = Files.walk(realTarget)) {
            for (Path item : paths.toList()) {
                if (item.equals(realTarget)) continue;
                if (isExcluded(item)) {
                    throw new SecurityException("This directory contains excluded system or credential paths and cannot be modified recursively.");
                }
            }
        }
    }

    private boolean sourceChanged(Path target, BasicFileAttributes before) {
        try {
            BasicFileAttributes after = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || (before.fileKey() != null && !before.fileKey().equals(after.fileKey()));
        } catch (Exception unavailable) {
            return true;
        }
    }

    private Map<String, Object> entry(EligibleRoot root, String relativePath, String name,
                                      BasicFileAttributes attributes) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rootId", root.id());
        result.put("path", relativePath);
        result.put("name", name);
        result.put("kind", attributes.isDirectory() ? "DIRECTORY" : "FILE");
        result.put("size", attributes.isDirectory() ? 0 : attributes.size());
        result.put("modified", attributes.lastModifiedTime().toInstant().toString());
        return result;
    }

    private boolean isExcluded(Path absolute) {
        Path normalized = absolute.toAbsolutePath().normalize();
        Path real;
        try {
            real = Files.exists(normalized, LinkOption.NOFOLLOW_LINKS) ? normalized.toRealPath() : normalized;
        } catch (Exception unavailable) {
            real = normalized;
        }
        for (String prefix : SYSTEM_PREFIXES) {
            Path system = Path.of(prefix);
            if (normalized.startsWith(system) || real.startsWith(system)) return true;
        }
        for (Path excludedPath : excluded) {
            if (normalized.startsWith(excludedPath) || real.startsWith(excludedPath)) return true;
        }
        return false;
    }

    private List<Path> buildExclusions() {
        Set<Path> result = new HashSet<>();
        addExcluded(result, config.dataDirectory());
        addExcluded(result, config.storageRoot());
        Path home = homeDirectory();
        for (String relative : CREDENTIAL_PATHS) addExcluded(result, home.resolve(relative));
        // Credential stores are excluded at the top of every eligible root, not
        // only under the default home root.
        for (EligibleRoot root : roots) {
            for (String relative : CREDENTIAL_PATHS) addExcluded(result, root.path().resolve(relative));
        }
        return List.copyOf(result);
    }

    private static void addExcluded(Set<Path> result, Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        result.add(normalized);
        try {
            if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) result.add(normalized.toRealPath());
        } catch (Exception ignored) {
            // A missing exclusion path still blocks future creation at that location.
        }
    }

    private List<EligibleRoot> buildRoots(List<Path> supplied) {
        List<EligibleRoot> result = new ArrayList<>();
        Set<Path> seen = new HashSet<>();
        Path home = homeDirectory();
        Path dataReal = canonical(config.dataDirectory());
        Path storageReal = canonical(config.storageRoot());
        for (Path candidate : supplied) {
            if (candidate == null) continue;
            Path absolute = candidate.toAbsolutePath().normalize();
            if (Files.isSymbolicLink(absolute) || !Files.isDirectory(absolute, LinkOption.NOFOLLOW_LINKS)) continue;
            Path real;
            try { real = absolute.toRealPath(); } catch (Exception unavailable) { continue; }
            // Never expose another OS user's private storage. Explicit roots must be
            // owned by the same OS user as the home directory and must not contain
            // shared home parents such as /home or /Users.
            if (!isSafeRootLocation(real, canonical(home)) || !isOwnedByCurrentUser(real)) continue;
            if (real.getParent() == null || real.startsWith(Path.of("/proc")) || real.startsWith(Path.of("/sys"))
                    || real.startsWith(Path.of("/dev")) || real.startsWith(Path.of("/etc"))
                    || real.startsWith(Path.of("/var")) || real.startsWith(Path.of("/boot"))
                    || real.startsWith(Path.of("/usr")) || real.startsWith(Path.of("/bin"))
                    || real.startsWith(Path.of("/sbin")) || real.startsWith(Path.of("/lib"))
                    || real.startsWith(Path.of("/run"))) continue;
            if (dataReal != null && (real.equals(dataReal) || real.startsWith(dataReal))) continue;
            if (storageReal != null && (real.equals(storageReal) || real.startsWith(storageReal))) continue;
            if (!seen.add(real)) continue;
            String id = real.equals(canonical(home)) ? "home" : "root-" + hash(real.toString());
            String name = real.equals(canonical(home)) ? "Home" : real.getFileName().toString();
            result.add(new EligibleRoot(id, name, absolute, real));
        }
        return List.copyOf(result);
    }

    private static List<Path> configuredRoots() {
        String value = System.getenv("PERSONALCLOUD_ELIGIBLE_ROOTS");
        if (value == null || value.isBlank()) return List.of(homeDirectory());
        List<Path> result = new ArrayList<>();
        for (String item : value.split(java.io.File.pathSeparator)) {
            if (!item.isBlank()) result.add(Path.of(item.strip()));
        }
        return result.isEmpty() ? List.of(homeDirectory()) : List.copyOf(result);
    }

    private static Path homeDirectory() {
        return Path.of(System.getProperty("user.home", ".")).toAbsolutePath().normalize();
    }

    /**
     * Rejects roots that contain another OS user's home directory or the whole
     * filesystem. A root equal to the current user's home, or a descendant of it,
     * is allowed; a shared parent such as {@code /home}, {@code /Users}, or
     * {@code /} is not.
     */
    static boolean isSafeRootLocation(Path root, Path home) {
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path normalizedHome = home.toAbsolutePath().normalize();
        Path homeParent = normalizedHome.getParent();
        if (homeParent == null) return false;
        return !normalizedRoot.equals(homeParent) && !homeParent.startsWith(normalizedRoot);
    }

    /**
     * Accepts only paths owned by the same OS user as the home directory. The
     * check fails closed when ownership cannot be established.
     */
    static boolean isOwnedByCurrentUser(Path root) {
        Path home = canonical(homeDirectory());
        Path candidate = root.toAbsolutePath().normalize();
        try {
            Object homeUid = Files.getAttribute(home, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            Object rootUid = Files.getAttribute(candidate, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            if (homeUid != null && rootUid != null) return homeUid.equals(rootUid);
        } catch (Exception unsupported) {
            // Fall through to the portable owner-name comparison.
        }
        try {
            return Files.getOwner(candidate).equals(Files.getOwner(home));
        } catch (Exception unavailable) {
            return false;
        }
    }

    private static Path canonical(Path path) {
        try { return path.toAbsolutePath().normalize().toRealPath(); }
        catch (Exception unavailable) { return path.toAbsolutePath().normalize(); }
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8))).substring(0, 12);
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 is unavailable.", impossible);
        }
    }

    /** Normalizes a root-relative path and rejects absolute paths, traversal and platform escapes. */
    public static String normalizeRelative(String path) {
        String value = path == null ? "" : path;
        if (value.indexOf('\0') >= 0 || value.startsWith("/") || value.startsWith("\\") || value.matches("^[A-Za-z]:.*")) {
            throw new IllegalArgumentException("Only root-relative paths are accepted.");
        }
        value = value.replace('\\', '/').strip();
        while (value.startsWith("/")) value = value.substring(1);
        while (value.endsWith("/") && !value.isEmpty()) value = value.substring(0, value.length() - 1);
        if (value.isEmpty()) return "";
        for (String segment : value.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("Path contains an invalid segment.");
            }
        }
        return value;
    }
}
