package dev.personalcloud.linux.fuse;

import dev.personalcloud.control.LocalControlClient;
import dev.personalcloud.storage.ReferenceFileSystemModel;

import java.nio.file.Files;
import java.nio.file.Path;

/** Standalone entry point for the optional Linux FUSE adapter. */
public final class FuseMountMain {
    private FuseMountMain() { }

    public static void main(String[] args) throws Exception {
        if (args.length > 1 || (args.length == 1 && ("--help".equals(args[0]) || "-h".equals(args[0])))) {
            System.out.println("Usage: personalcloud-mount [empty-mountpoint]\nMounts the /Devices virtual namespace; remote eligible storage is writable.");
            return;
        }
        Path mountPoint = (args.length == 1 ? Path.of(args[0]) : Path.of(System.getProperty("user.home"), "PersonalCloud"))
                .toAbsolutePath().normalize();
        Files.createDirectories(mountPoint);
        if (!Files.isDirectory(mountPoint)) throw new IllegalArgumentException("Mount point must be a directory: " + mountPoint);
        try (var entries = Files.list(mountPoint)) {
            if (entries.findAny().isPresent()) throw new IllegalArgumentException("Mount point must be empty; refusing to hide existing files: " + mountPoint);
        }
        String configuredSocket = System.getenv("PERSONALCLOUD_CONTROL_SOCKET");
        Path socket;
        if (configuredSocket != null && !configuredSocket.isBlank()) socket = Path.of(configuredSocket);
        else socket = Path.of(System.getenv().getOrDefault("PERSONALCLOUD_DATA_DIR", "./data")).resolve("control.sock");
        socket = socket.toAbsolutePath().normalize();
        LocalControlClient client = new LocalControlClient(socket);
        client.ping();
        ReferenceFileSystemModel model = new ReferenceFileSystemModel(client);
        PersonalCloudFuse filesystem = new PersonalCloudFuse(model, client);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { filesystem.umount(); } catch (RuntimeException ignored) { }
        }, "personalcloud-fuse-unmount"));
        System.out.println("PersonalCloud filesystem mounted at " + mountPoint);
        System.out.println("Namespace: /Devices/<device>/References, /Devices/<device>/Distributed-Storage and writable /Devices/<device>/Filesystem");
        System.out.println("Press Ctrl+C to unmount.");
        filesystem.mount(mountPoint, true, false,
                new String[]{"-o", "default_permissions,nodev,nosuid,noexec"});
    }
}
