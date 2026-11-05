package dev.personalcloud.core;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Watches the owned storage tree. Revision changes let native adapters detect storage changes without rescanning constantly. */
public final class StorageWatcher implements AutoCloseable {
    private final Path root;
    private final WatchService service;
    private final Map<WatchKey, Path> directories = new HashMap<>();
    private final AtomicLong revision = new AtomicLong(1);
    private final Thread thread;
    private volatile boolean running = true;

    public StorageWatcher(Path storageRoot) throws IOException {
        this.root = storageRoot.toRealPath();
        this.service = FileSystems.getDefault().newWatchService();
        registerTree(this.root);
        this.thread = new Thread(this::watchLoop, "personalcloud-storage-watcher");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public long revision() { return revision.get(); }

    private void registerTree(Path start) throws IOException {
        try (var paths = Files.walk(start)) {
            for (Path path : paths.filter(p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS))
                    .filter(p -> !Files.isSymbolicLink(p)).toList()) {
                Path real = path.toRealPath();
                if (!real.startsWith(root)) continue;
                WatchKey key = path.register(service,
                        StandardWatchEventKinds.ENTRY_CREATE,
                        StandardWatchEventKinds.ENTRY_DELETE,
                        StandardWatchEventKinds.ENTRY_MODIFY);
                synchronized (directories) { directories.put(key, path); }
            }
        }
    }

    private void watchLoop() {
        while (running) {
            WatchKey key;
            try { key = service.take(); }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            } catch (java.nio.file.ClosedWatchServiceException closed) { return; }
            Path directory;
            synchronized (directories) { directory = directories.get(key); }
            if (directory == null) {
                key.reset();
                continue;
            }
            for (WatchEvent<?> event : key.pollEvents()) {
                revision.incrementAndGet();
                if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;
                if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE && event.context() instanceof Path child) {
                    Path created = directory.resolve(child).normalize();
                    try {
                        if (created.startsWith(root) && Files.isDirectory(created, LinkOption.NOFOLLOW_LINKS)
                                && !Files.isSymbolicLink(created)) registerTree(created);
                    } catch (IOException ignored) {
                        // The directory may be removed or become inaccessible during registration.
                    }
                }
            }
            if (!key.reset()) {
                synchronized (directories) { directories.remove(key); }
                revision.incrementAndGet();
            }
        }
    }

    @Override public void close() {
        running = false;
        try { service.close(); } catch (IOException ignored) { }
        thread.interrupt();
        try { thread.join(1500); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
    }
}
