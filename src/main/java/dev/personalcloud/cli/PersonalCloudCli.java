package dev.personalcloud.cli;

import dev.personalcloud.control.LocalControlClient;
import dev.personalcloud.net.Json;
import dev.personalcloud.network.DirectConnectivityDiagnostics;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Minimal Java-only local administration interface over the owner-only Unix socket. */
public final class PersonalCloudCli {
    private PersonalCloudCli() { }

    public static void main(String[] args) {
        try { run(args); }
        catch (Exception failure) {
            System.err.println("PersonalCloud: " + safeMessage(failure));
            System.exit(2);
        }
    }

    public static void run(String[] supplied) throws Exception {
        String[] args = supplied == null ? new String[0] : supplied;
        Path socket = defaultSocket();
        int start = 0;
        if (args.length >= 2 && "--socket".equals(args[0])) {
            socket = Path.of(args[1]).toAbsolutePath().normalize();
            start = 2;
        }
        if (start >= args.length || "help".equals(args[start]) || "--help".equals(args[start])) {
            usage();
            return;
        }

        if ("network".equals(args[start]) && args.length > start + 1 && "diagnostics".equals(args[start + 1])) {
            networkDiagnostics(args, start + 2);
            return;
        }

        LocalControlClient client = new LocalControlClient(socket);
        String command = args[start++];
        switch (command) {
            case "status" -> print(client.ping());
            case "references" -> references(client, args, start);
            case "browse" -> {
                requireCount(args, start, 1, 2, "browse <reference-id> [relative-directory]");
                client.listEntries(args[start], args.length > start + 1 ? args[start + 1] : "").forEach(PersonalCloudCli::print);
            }
            case "search" -> {
                requireCount(args, start, 1, 2, "search <query> [limit]");
                int limit = args.length > start + 1 ? Integer.parseInt(args[start + 1]) : 50;
                client.search(args[start], limit).forEach(PersonalCloudCli::print);
            }
            case "stat" -> {
                requireCount(args, start, 2, 2, "stat <reference-id> <relative-file-path>");
                print(client.stat(args[start], args[start + 1]));
            }
            case "download" -> {
                requireCount(args, start, 3, 3, "download <reference-id> <relative-file-path> <new-destination>");
                LocalControlClient.DownloadResult result = client.download(args[start], args[start + 1], Path.of(args[start + 2]));
                print(Map.of("path", result.path().toString(), "size", result.sizeBytes(), "sha256", result.sha256()));
            }
            case "invite" -> {
                requireCount(args, start, 1, 1, "invite create");
                if (!"create".equals(args[start])) throw new IllegalArgumentException("Usage: invite create");
                print(client.createInvitation());
            }
            case "peers" -> peers(client, args, start);
            case "grants" -> grants(client, args, start);
            case "remote" -> remote(client, args, start);
            case "network" -> network(client, args, start);
            case "reference-grants" -> referenceGrants(client, args, start);
            case "reference-snapshots" -> referenceSnapshots(client, args, start);
            case "managed" -> managed(client, args, start);
            case "coordinated" -> coordinated(client, args, start);
            case "policy" -> policy(client, args, start);
            case "filesystem" -> filesystem(client, args, start);
            case "audit" -> audit(client, args, start);
            default -> throw new IllegalArgumentException("Unknown command: " + command);
        }
    }

    private static void references(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected references list, add, locate or remove.");
        switch (args[start++]) {
            case "list" -> client.listReferences().forEach(PersonalCloudCli::print);
            case "add" -> {
                requireCount(args, start, 2, 2, "references add <display-name> <absolute-directory>");
                print(client.registerReference(args[start], Path.of(args[start + 1])));
            }
            case "locate" -> {
                requireCount(args, start, 1, 1, "references locate <absolute-file>");
                print(client.locateReferenceFile(Path.of(args[start])));
            }
            case "remove" -> {
                requireCount(args, start, 1, 1, "references remove <reference-id>");
                print(client.unregisterReference(args[start]));
            }
            default -> throw new IllegalArgumentException("Unknown references command.");
        }
    }

    private static void peers(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected peers list, add or remove.");
        switch (args[start++]) {
            case "list" -> client.listPeers().forEach(PersonalCloudCli::print);
            case "add" -> {
                requireCount(args, start, 2, 2, "peers add <https-peer-url> <one-time-invitation-code>");
                print(client.addPeer(args[start], args[start + 1]));
            }
            case "remove" -> {
                requireCount(args, start, 2, 2, "peers remove <node-id> <INCOMING|OUTGOING>");
                print(client.removePeer(args[start], args[start + 1]));
            }
            default -> throw new IllegalArgumentException("Unknown peers command.");
        }
    }

    private static void grants(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected grants list, create or revoke.");
        switch (args[start++]) {
            case "list" -> client.listGrants().forEach(PersonalCloudCli::print);
            case "create" -> {
                requireCount(args, start, 3, 3, "grants create <peer-node-id> <relative-file-or-folder-path> <DOWNLOAD|DOWNLOAD+DELETE>");
                print(client.createGrant(args[start], args[start + 1], args[start + 2]));
            }
            case "revoke" -> {
                requireCount(args, start, 1, 1, "grants revoke <grant-id>");
                print(client.revokeGrant(args[start]));
            }
            default -> throw new IllegalArgumentException("Unknown grants command.");
        }
    }

    private static void managed(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected managed local-list, place, transfers, transfer-status, resume, abort, remote-list, remote-download or remote-delete.");
        switch (args[start++]) {
            case "local-list" -> client.listLocalManagedFiles().forEach(PersonalCloudCli::print);
            case "place" -> {
                requireCount(args, start, 3, 3, "managed place <destination-node-id> <source-file> <destination-relative-path>");
                print(client.placeManagedFile(args[start], Path.of(args[start + 1]), args[start + 2]));
            }
            case "transfers" -> client.listOutboundTransfers().forEach(PersonalCloudCli::print);
            case "transfer-status" -> {
                requireCount(args, start, 1, 1, "managed transfer-status <job-id>");
                print(client.outboundTransferStatus(args[start]));
            }
            case "resume" -> {
                requireCount(args, start, 1, 1, "managed resume <job-id>");
                print(client.resumeOutboundTransfer(args[start]));
            }
            case "abort" -> {
                requireCount(args, start, 1, 1, "managed abort <job-id>");
                print(client.abortOutboundTransfer(args[start]));
            }
            case "remote-list" -> {
                requireCount(args, start, 1, 1, "managed remote-list <storage-node-id>");
                client.listRemoteManagedFiles(args[start]).forEach(PersonalCloudCli::print);
            }
            case "remote-download" -> {
                requireCount(args, start, 3, 3, "managed remote-download <storage-node-id> <file-id> <new-destination>");
                LocalControlClient.DownloadResult result = client.downloadRemoteManagedFile(args[start], args[start + 1], Path.of(args[start + 2]));
                print(Map.of("path", result.path().toString(), "size", result.sizeBytes(), "sha256", result.sha256()));
            }
            case "remote-delete" -> {
                requireCount(args, start, 2, 2, "managed remote-delete <storage-node-id> <file-id>");
                print(client.deleteRemoteManagedFile(args[start], args[start + 1]));
            }
            default -> throw new IllegalArgumentException("Unknown managed-storage command.");
        }
    }

    private static void referenceSnapshots(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length || "list".equals(args[start])) {
            client.listReferenceSnapshots().forEach(PersonalCloudCli::print);
            return;
        }
        if ("restore".equals(args[start])) {
            requireCount(args, start + 1, 1, 1, "reference-snapshots restore <snapshot-id>");
            print(client.restoreReferenceSnapshot(args[start + 1]));
            return;
        }
        throw new IllegalArgumentException("Usage: reference-snapshots [list|restore <snapshot-id>]");
    }

    private static void referenceGrants(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected reference-grants list, create or revoke.");
        switch (args[start++]) {
            case "list" -> client.listReferenceGrants().forEach(PersonalCloudCli::print);
            case "create" -> {
                requireCount(args, start, 4, 4, "reference-grants create <member-node-id> <reference-id> <relative-path-or-.> <DOWNLOAD|DOWNLOAD+DELETE>");
                print(client.createReferenceGrant(args[start], args[start + 1], args[start + 2], args[start + 3]));
            }
            case "revoke" -> {
                requireCount(args, start, 1, 1, "reference-grants revoke <grant-id>");
                print(client.revokeReferenceGrant(args[start]));
            }
            default -> throw new IllegalArgumentException("Unknown reference-grants command.");
        }
    }

    private static void policy(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected policy list, set, remove, epoch or approvals.");
        switch (args[start++]) {
            case "list" -> client.listPolicies().forEach(PersonalCloudCli::print);
            case "set" -> {
                requireCount(args, start, 3, 3, "policy set <eligible-root-id> <relative-path-or-.> <NORMAL|PRIVATE|PROTECTED>");
                print(client.setPolicy(args[start], policyPath(args[start + 1]), args[start + 2]));
            }
            case "remove" -> {
                requireCount(args, start, 2, 2, "policy remove <eligible-root-id> <relative-path-or-.>");
                print(client.removePolicy(args[start], policyPath(args[start + 1])));
            }
            case "epoch" -> print(client.policyEpoch());
            case "approvals" -> policyApprovals(client, args, start);
            default -> throw new IllegalArgumentException("Unknown policy command.");
        }
    }

    private static void policyApprovals(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected policy approvals list, request, approve, deny or status.");
        switch (args[start++]) {
            case "list" -> client.listProtectionApprovals().forEach(PersonalCloudCli::print);
            case "request" -> {
                requireCount(args, start, 4, 5, "policy approvals request <member-id> <eligible-root-id> <relative-path-or-.> <OPERATION> [ttl-seconds]");
                long ttl = args.length > start + 4 ? Long.parseLong(args[start + 4]) : 0;
                print(client.requestProtectionApproval(args[start], args[start + 1], policyPath(args[start + 2]),
                        args[start + 3], ttl));
            }
            case "approve" -> {
                requireCount(args, start, 1, 1, "policy approvals approve <approval-id>");
                print(client.approveProtection(args[start]));
            }
            case "deny" -> {
                requireCount(args, start, 1, 1, "policy approvals deny <approval-id>");
                print(client.denyProtection(args[start]));
            }
            case "status" -> {
                requireCount(args, start, 1, 1, "policy approvals status <approval-id>");
                print(client.protectionStatus(args[start]));
            }
            default -> throw new IllegalArgumentException("Unknown policy approvals command.");
        }
    }

    private static String policyPath(String value) {
        return ".".equals(value) ? "" : value;
    }

    private static void coordinated(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) {
            throw new IllegalArgumentException("Expected coordinated plan, prepare, transfer, status, retry or list.");
        }
        switch (args[start++]) {
            case "plan" -> {
                requireCount(args, start, 6, 6,
                        "coordinated plan <source-node-id> <source-root-id> <source-path> <destination-node-id> <destination-root-id> <destination-path>");
                print(asMap(client.planCoordinatedTransfer(args[start], args[start + 1], args[start + 2],
                        args[start + 3], args[start + 4], args[start + 5]).get("plan")));
            }
            case "prepare" -> {
                requireCount(args, start, 7, Integer.MAX_VALUE,
                        "coordinated prepare <source-node-id> <source-root-id> <source-path> <destination-node-id> <destination-root-id> <destination-path> <COPY|MOVE> [--overwrite] [--source-approval ID] [--destination-approval ID] [--ttl-seconds N]");
                CoordinatedOptions options = coordinatedOptions(args, start + 7);
                print(client.prepareCoordinatedTransfer(args[start], args[start + 1], args[start + 2],
                        args[start + 3], args[start + 4], args[start + 5], args[start + 6],
                        options.overwrite, options.sourceApprovalId, options.destinationApprovalId,
                        options.ttlSeconds));
            }
            case "transfer" -> {
                requireCount(args, start, 7, Integer.MAX_VALUE,
                        "coordinated transfer <source-node-id> <source-root-id> <source-path> <destination-node-id> <destination-root-id> <destination-path> <COPY|MOVE> [--overwrite] [--source-approval ID] [--destination-approval ID] [--ttl-seconds N]");
                CoordinatedOptions options = coordinatedOptions(args, start + 7);
                print(asMap(client.coordinateTransfer(args[start], args[start + 1], args[start + 2],
                        args[start + 3], args[start + 4], args[start + 5], args[start + 6],
                        options.overwrite, options.sourceApprovalId, options.destinationApprovalId,
                        options.ttlSeconds).get("transfer")));
            }
            case "status" -> {
                requireCount(args, start, 1, 1, "coordinated status <request-id>");
                print(asMap(client.coordinatedTransferStatus(args[start]).get("status")));
            }
            case "retry" -> {
                requireCount(args, start, 1, 1, "coordinated retry <request-id>");
                print(asMap(client.retryCoordinatedTransfer(args[start]).get("transfer")));
            }
            case "list" -> client.listCoordinatedTransfers().forEach(PersonalCloudCli::print);
            default -> throw new IllegalArgumentException("Unknown coordinated transfer command.");
        }
    }

    private static CoordinatedOptions coordinatedOptions(String[] args, int start) {
        CoordinatedOptions options = new CoordinatedOptions();
        for (int index = start; index < args.length; index++) {
            switch (args[index]) {
                case "--overwrite" -> options.overwrite = true;
                case "--source-approval" -> {
                    if (++index >= args.length) throw new IllegalArgumentException("Missing value after --source-approval.");
                    options.sourceApprovalId = args[index];
                }
                case "--destination-approval" -> {
                    if (++index >= args.length) throw new IllegalArgumentException("Missing value after --destination-approval.");
                    options.destinationApprovalId = args[index];
                }
                case "--ttl-seconds" -> {
                    if (++index >= args.length) throw new IllegalArgumentException("Missing value after --ttl-seconds.");
                    options.ttlSeconds = Long.parseLong(args[index]);
                }
                default -> throw new IllegalArgumentException("Unknown coordinated transfer option: " + args[index]);
            }
        }
        return options;
    }

    private static final class CoordinatedOptions {
        private boolean overwrite;
        private String sourceApprovalId = "";
        private String destinationApprovalId = "";
        private long ttlSeconds;
    }

    private static void filesystem(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected filesystem status, roots, consent, revoke-consent, budgets, budget, budget-set or budget-clear.");
        switch (args[start++]) {
            case "status" -> print(client.filesystemStatus());
            case "roots" -> client.filesystemRoots().forEach(PersonalCloudCli::print);
            case "consent" -> print(client.grantFilesystemConsent());
            case "revoke-consent" -> print(client.revokeFilesystemConsent());
            case "budgets" -> client.listFilesystemBudgets().forEach(PersonalCloudCli::print);
            case "budget" -> {
                requireCount(args, start, 1, 1, "filesystem budget <member-id>");
                print(client.filesystemBudget(args[start]));
            }
            case "budget-set" -> {
                requireCount(args, start, 3, 3, "filesystem budget-set <member-id> <write-bytes-per-day> <delete-entries-per-day>");
                print(client.setFilesystemBudget(args[start], Long.parseLong(args[start + 1]),
                        Long.parseLong(args[start + 2])));
            }
            case "budget-clear" -> {
                requireCount(args, start, 1, 1, "filesystem budget-clear <member-id>");
                print(client.clearFilesystemBudget(args[start]));
            }
            default -> throw new IllegalArgumentException("Unknown filesystem command.");
        }
    }

    private static void audit(LocalControlClient client, String[] args, int start) throws Exception {
        int index = start;
        if (index < args.length && "list".equals(args[index])) index++;
        int limit = 50;
        if (index < args.length) {
            if (index + 1 != args.length) throw new IllegalArgumentException("Usage: audit [list] [limit]");
            limit = Integer.parseInt(args[index]);
        }
        client.listAuditEvents(limit).forEach(PersonalCloudCli::print);
    }

    private static void network(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected network diagnostics, status, bootstrap, join, requests, approve, reject, members or revoke.");
        switch (args[start++]) {
            case "diagnostics" -> networkDiagnostics(args, start);
            case "status" -> print(asMap(client.networkStatus().get("network")));
            case "search" -> {
                requireCount(args, start, 1, 2, "network search <query> [limit]");
                int limit = args.length > start + 1 ? Integer.parseInt(args[start + 1]) : 50;
                client.networkSearch(args[start], limit).forEach(PersonalCloudCli::print);
            }
            case "bootstrap" -> {
                requireCount(args, start, 2, 2, "network bootstrap <network-name> <account-name>");
                char[] password = promptPassword("Create network password: ");
                try {
                    char[] confirmation = promptPassword("Confirm network password: ");
                    try {
                        if (!java.security.MessageDigest.isEqual(new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                                new String(confirmation).getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                            throw new IllegalArgumentException("The passwords do not match.");
                        }
                    } finally { java.util.Arrays.fill(confirmation, '\0'); }
                    print(asMap(client.networkBootstrap(args[start], args[start + 1], password).get("network")));
                } finally { java.util.Arrays.fill(password, '\0'); }
            }
            case "join" -> {
                requireCount(args, start, 1, 3, "network join <https-peer-url> [account-name] [--consent]");
                String account = "";
                boolean consent = false;
                for (int index = start + 1; index < args.length; index++) {
                    if ("--consent".equals(args[index])) consent = true;
                    else if (account.isEmpty()) account = args[index];
                    else throw new IllegalArgumentException("Unknown network join option: " + args[index]);
                }
                char[] password = promptPassword("Network password: ");
                try {
                    print(asMap(client.networkJoin(args[start], account, password, consent).get("network")));
                } finally { java.util.Arrays.fill(password, '\0'); }
            }
            case "requests" -> client.networkRequests().forEach(PersonalCloudCli::print);
            case "approve" -> {
                requireCount(args, start, 1, 1, "network approve <request-id>");
                print(client.networkApprove(args[start]));
            }
            case "reject" -> {
                requireCount(args, start, 1, 2, "network reject <request-id> [reason]");
                print(client.networkReject(args[start], args.length > start + 1 ? args[start + 1] : ""));
            }
            case "members" -> client.networkMembers().forEach(PersonalCloudCli::print);
            case "set-endpoint" -> {
                requireCount(args, start, 2, 2, "network set-endpoint <node-id> <https-peer-url>");
                print(client.networkSetEndpoint(args[start], args[start + 1]));
            }
            case "sync" -> print(client.networkSync());
            case "revoke" -> {
                requireCount(args, start, 1, 1, "network revoke <node-id>");
                print(client.networkRevoke(args[start]));
            }
            default -> throw new IllegalArgumentException("Unknown network command.");
        }
    }


    /** Runs without a daemon connection: this is a local, read-only network probe. */
    private static void networkDiagnostics(String[] args, int start) throws Exception {
        int timeout = 1200;
        String serversValue = System.getenv("PERSONALCLOUD_STUN_SERVERS");
        for (int index = start; index < args.length; index++) {
            switch (args[index]) {
                case "--timeout-ms" -> {
                    if (++index >= args.length) throw new IllegalArgumentException("Missing value after --timeout-ms.");
                    timeout = Integer.parseInt(args[index]);
                }
                case "--servers" -> {
                    if (++index >= args.length) throw new IllegalArgumentException("Missing value after --servers.");
                    serversValue = args[index];
                }
                default -> throw new IllegalArgumentException("Unknown network diagnostics option: " + args[index]);
            }
        }
        String bind = System.getenv().getOrDefault("PERSONALCLOUD_BIND_ADDRESS", "127.0.0.1");
        int port = Integer.parseInt(System.getenv().getOrDefault("PERSONALCLOUD_PORT", "8787"));
        String keyStore = System.getenv("PERSONALCLOUD_TLS_KEYSTORE");
        if (keyStore == null || keyStore.isBlank()) {
            String tlsDir = System.getenv().getOrDefault("PERSONALCLOUD_TLS_DIR",
                    Path.of(System.getProperty("user.home"), ".local", "share", "personalcloud-android-peer-tls").toString());
            Path defaultIdentity = Path.of(tlsDir).toAbsolutePath().normalize().resolve("desktop-server.p12");
            if (Files.isRegularFile(defaultIdentity, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(defaultIdentity)) {
                keyStore = defaultIdentity.toString();
            }
        }
        String keyPassword = System.getenv("PERSONALCLOUD_TLS_KEYSTORE_PASSWORD");
        char[] tlsPassword = keyPassword == null || keyPassword.isBlank() ? null : keyPassword.toCharArray();
        String tlsIdentityStatus;
        boolean identityFilePresent = keyStore != null && Files.isRegularFile(Path.of(keyStore), LinkOption.NOFOLLOW_LINKS)
                && !Files.isSymbolicLink(Path.of(keyStore));
        if (!identityFilePresent) {
            tlsIdentityStatus = "NOT_FOUND";
        } else {
            if (tlsPassword == null) {
                java.io.Console console = System.console();
                if (console != null) tlsPassword = console.readPassword("Desktop TLS identity password for diagnostics: ");
            }
            if (tlsPassword == null || tlsPassword.length == 0) {
                tlsIdentityStatus = "PASSWORD_REQUIRED";
            } else {
                tlsIdentityStatus = DirectConnectivityDiagnostics.hasUsableTlsIdentity(keyStore, tlsPassword)
                        ? "VALID" : "INVALID_OR_UNREADABLE";
            }
        }
        boolean tlsConfigured = "VALID".equals(tlsIdentityStatus);
        if (tlsPassword != null) Arrays.fill(tlsPassword, '\0');
        Map<String, Object> result = DirectConnectivityDiagnostics.diagnose(bind, port, tlsConfigured,
                DirectConnectivityDiagnostics.parseServers(serversValue), timeout);
        result.put("tlsIdentityStatus", tlsIdentityStatus);
        if ("PASSWORD_REQUIRED".equals(tlsIdentityStatus) && !"NOT_PEER_REACHABLE".equals(result.get("assessment"))) {
            result.put("assessment", "TLS_IDENTITY_UNVERIFIED");
            result.put("guidance", "A desktop TLS identity file exists, but its password was not supplied. Run diagnostics in an interactive terminal or set PERSONALCLOUD_TLS_KEYSTORE_PASSWORD for this command.");
        } else if ("INVALID_OR_UNREADABLE".equals(tlsIdentityStatus) && !"NOT_PEER_REACHABLE".equals(result.get("assessment"))) {
            result.put("assessment", "TLS_IDENTITY_INVALID");
            result.put("guidance", "The configured desktop TLS identity could not be validated. Check its PKCS#12 password, file permissions and certificate validity before exposing the listener.");
        }
        print(result);
    }

    private static char[] promptPassword(String prompt) {
        java.io.Console console = System.console();
        if (console == null) throw new IllegalStateException("A secure terminal is required for network password entry. Run this command directly in Konsole, not through a pipe or script.");
        char[] password = console.readPassword("%s", prompt);
        if (password == null) throw new IllegalStateException("Password input was cancelled.");
        return password;
    }

    private static void remote(LocalControlClient client, String[] args, int start) throws Exception {
        if (start >= args.length) throw new IllegalArgumentException("Expected remote shares, download or delete.");
        switch (args[start++]) {
            case "shares" -> {
                requireCount(args, start, 1, 1, "remote shares <outgoing-peer-node-id>");
                client.listRemoteShares(args[start]).forEach(PersonalCloudCli::print);
            }
            case "download" -> {
                requireCount(args, start, 3, 3, "remote download <peer-node-id> <share-id> <new-destination>");
                LocalControlClient.DownloadResult result = client.downloadRemoteShare(args[start], args[start + 1], Path.of(args[start + 2]));
                print(Map.of("path", result.path().toString(), "size", result.sizeBytes(), "sha256", result.sha256()));
            }
            case "delete" -> {
                requireCount(args, start, 2, 2, "remote delete <peer-node-id> <share-id>");
                print(client.deleteRemoteShare(args[start], args[start + 1]));
            }
            case "references" -> {
                requireCount(args, start, 1, 1, "remote references <member-node-id>");
                client.listRemoteNetworkReferences(args[start]).forEach(PersonalCloudCli::print);
            }
            case "browse" -> {
                requireCount(args, start, 2, 3, "remote browse <member-node-id> <reference-grant-id> [relative-directory]");
                client.browseRemoteNetworkReference(args[start], args[start + 1], args.length > start + 2 ? args[start + 2] : "")
                        .forEach(PersonalCloudCli::print);
            }
            case "stat" -> {
                requireCount(args, start, 2, 3, "remote stat <member-node-id> <reference-grant-id> [relative-file-path]");
                print(client.statRemoteNetworkReference(args[start], args[start + 1], args.length > start + 2 ? args[start + 2] : ""));
            }
            case "reference-download" -> {
                requireCount(args, start, 4, 4, "remote reference-download <member-node-id> <reference-grant-id> <relative-file-path-or-.> <new-destination>");
                String relative = ".".equals(args[start + 2]) ? "" : args[start + 2];
                LocalControlClient.DownloadResult result = client.downloadRemoteNetworkReference(args[start], args[start + 1], relative, Path.of(args[start + 3]));
                print(Map.of("path", result.path().toString(), "size", result.sizeBytes(), "sha256", result.sha256()));
            }
            case "reference-delete" -> {
                requireCount(args, start, 3, 3, "remote reference-delete <member-node-id> <reference-grant-id> <relative-file-path-or-.>");
                String relative = ".".equals(args[start + 2]) ? "" : args[start + 2];
                print(client.deleteRemoteNetworkReference(args[start], args[start + 1], relative));
            }
            default -> throw new IllegalArgumentException("Unknown remote command.");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, ?> asMap(Object value) {
        if (!(value instanceof Map<?, ?>)) throw new IllegalStateException("The control server returned an invalid object.");
        return (Map<String, ?>) value;
    }

    private static void print(Map<String, ?> value) { System.out.println(Json.stringify(value)); }

    private static Path defaultSocket() {
        String explicit = System.getenv("PERSONALCLOUD_CONTROL_SOCKET");
        if (explicit != null && !explicit.isBlank()) return Path.of(explicit).toAbsolutePath().normalize();
        String data = System.getenv().getOrDefault("PERSONALCLOUD_DATA_DIR", "./data");
        return Path.of(data).toAbsolutePath().normalize().resolve("control.sock");
    }

    private static void requireCount(String[] args, int start, int minimum, int maximum, String syntax) {
        int count = args.length - start;
        if (count < minimum || count > maximum) throw new IllegalArgumentException("Usage: " + syntax);
    }

    private static String safeMessage(Exception failure) {
        return failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage();
    }

    private static void usage() {
        System.out.println("PersonalCloud local control (Java)\n"
                + "Usage: ./personalcloudctl COMMAND [ARGS...]\n\n"
                + "Node and network:\n"
                + "  status\n"
                + "  invite create\n"
                + "  peers list\n"
                + "  peers add <https-peer-url> <invitation-code>\n"
                + "  peers remove <node-id> <INCOMING|OUTGOING>\n\n"
                + "Private network membership:\n"
                + "  network diagnostics [--timeout-ms N] [--servers host:port,...] (works without a running node)\n"
                + "  network status\n"
                + "  network search <query> [limit]\n"
                + "  network bootstrap <network-name> <account-name>\n"
                + "  network join <https-peer-url> [account-name]\n"
                + "  network requests\n"
                + "  network approve <request-id>\n"
                + "  network reject <request-id> [reason]\n"
                + "  network members\n"
                + "  network sync\n"
                + "  network revoke <node-id>\n\n"
                + "Eligible filesystem and member budgets:\n"
                + "  filesystem status\n"
                + "  filesystem roots\n"
                + "  filesystem consent\n"
                + "  filesystem revoke-consent\n"
                + "  filesystem budgets\n"
                + "  filesystem budget <member-id>\n"
                + "  filesystem budget-set <member-id> <write-bytes-per-day> <delete-entries-per-day>\n"
                + "  filesystem budget-clear <member-id>\n\n"
                + "Owner audit history:\n"
                + "  audit [list] [limit]\n\n"
                + "Referenced storage permissions:\n"
                + "  reference-grants list\n"
                + "  reference-grants create <member-node-id> <reference-id> <relative-path-or-.> <DOWNLOAD|DOWNLOAD+DELETE>\n"
                + "  reference-grants revoke <grant-id>\n"
                + "  reference-snapshots list\n"
                + "  reference-snapshots restore <snapshot-id>\n\n"
                + "Distributed managed storage:\n"
                + "  managed local-list\n"
                + "  managed place <destination-node-id> <source-file> <destination-relative-path>\n"
                + "  managed transfers\n"
                + "  managed transfer-status <job-id>\n"
                + "  managed resume <job-id>\n"
                + "  managed abort <job-id>\n"
                + "  managed remote-list <storage-node-id>\n"
                + "  managed remote-download <storage-node-id> <file-id> <new-destination>\n"
                + "  managed remote-delete <storage-node-id> <file-id>\n\n"
                + "Three-peer coordinated transfers (Z coordinates, X sends directly to Y):\n"
                + "  coordinated plan <source-node-id> <source-root-id> <source-path> <destination-node-id> <destination-root-id> <destination-path>\n"
                + "  coordinated prepare <source-node-id> <source-root-id> <source-path> <destination-node-id> <destination-root-id> <destination-path> <COPY|MOVE> [--overwrite] [--source-approval ID] [--destination-approval ID] [--ttl-seconds N]\n"
                + "  coordinated transfer <source-node-id> <source-root-id> <source-path> <destination-node-id> <destination-root-id> <destination-path> <COPY|MOVE> [--overwrite] [--source-approval ID] [--destination-approval ID] [--ttl-seconds N]\n"
                + "  coordinated status <request-id>\n"
                + "  coordinated retry <request-id>\n"
                + "  coordinated list\n\n"
                + "Permissions (DOWNLOAD or DOWNLOAD+DELETE):\n"
                + "  grants list\n"
                + "  grants create <peer-node-id> <relative-path> <permission>\n"
                + "  grants revoke <grant-id>\n\n"
                + "Remote files:\n"
                + "  remote shares <peer-node-id>\n"
                + "  remote download <peer-node-id> <share-id> <new-destination>\n"
                + "  remote delete <peer-node-id> <share-id>\n"
                + "  remote references <member-node-id>\n"
                + "  remote browse <member-node-id> <reference-grant-id> [relative-directory]\n"
                + "  remote stat <member-node-id> <reference-grant-id> [relative-file-path]\n"
                + "  remote reference-download <member-node-id> <reference-grant-id> <relative-file-path-or-.> <new-destination>\n"
                + "  remote reference-delete <member-node-id> <reference-grant-id> <relative-file-path-or-.>\n\n"
                + "Existing files (reference in place):\n"
                + "  references list\n"
                + "  references add <name> <absolute-directory>\n"
                + "  references remove <reference-id>\n"
                + "  browse <reference-id> [relative-directory]\n"
                + "  search <query> [limit]\n"
                + "  stat <reference-id> <relative-file-path>\n"
                + "  download <reference-id> <relative-file-path> <new-destination>\n\n"
                + "Local administration uses an owner-only Unix-domain socket; no browser dashboard is included.");
    }
}
