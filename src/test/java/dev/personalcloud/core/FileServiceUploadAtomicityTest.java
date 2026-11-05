package dev.personalcloud.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class FileServiceUploadAtomicityTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-upload-atomicity-");
        Path storage = Files.createDirectory(base.resolve("storage"));
        try (FileService files = new FileService(storage)) {
            byte[] original = "first complete payload".getBytes(StandardCharsets.UTF_8);
            long uploaded = files.upload("same.bin", new ByteArrayInputStream(original), 1024);
            check(uploaded == original.length, "upload reports exact byte count");
            check(java.util.Arrays.equals(Files.readAllBytes(storage.resolve("same.bin")), original), "uploaded bytes match");

            boolean overwriteRejected = false;
            try {
                files.upload("same.bin", new ByteArrayInputStream("replacement".getBytes(StandardCharsets.UTF_8)), 1024);
            } catch (IllegalArgumentException expected) {
                overwriteRejected = true;
            }
            check(overwriteRejected, "existing destination is rejected");
            check(java.util.Arrays.equals(Files.readAllBytes(storage.resolve("same.bin")), original), "rejected overwrite preserves original bytes");

            boolean streamFailureObserved = false;
            try {
                files.upload("interrupted.bin", new InputStream() {
                    private int position;
                    private final byte[] prefix = "partial".getBytes(StandardCharsets.UTF_8);
                    @Override public int read() throws IOException {
                        if (position < prefix.length) return prefix[position++];
                        throw new IOException("injected stream failure");
                    }
                }, 1024);
            } catch (IOException expected) {
                streamFailureObserved = true;
            }
            check(streamFailureObserved, "injected source failure is propagated");
            check(!Files.exists(storage.resolve("interrupted.bin")), "failed upload never publishes final path");

            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger successes = new AtomicInteger();
            AtomicInteger rejected = new AtomicInteger();
            AtomicReference<Throwable> unexpected = new AtomicReference<>();
            Thread a = contender(files, "concurrent-A", ready, start, successes, rejected, unexpected);
            Thread b = contender(files, "concurrent-B", ready, start, successes, rejected, unexpected);
            a.start(); b.start();
            ready.await(); start.countDown();
            a.join(); b.join();
            check(unexpected.get() == null, "concurrent upload had no unexpected failure: " + unexpected.get());
            check(successes.get() == 1 && rejected.get() == 1,
                    "exactly one concurrent upload commits without replacing the other");
            String concurrent = Files.readString(storage.resolve("concurrent.bin"));
            check(concurrent.equals("concurrent-A") || concurrent.equals("concurrent-B"),
                    "concurrent winner is a complete payload");

            try (var entries = Files.list(storage)) {
                check(entries.noneMatch(path -> path.getFileName().toString().startsWith(".personalcloud-upload-")),
                        "all upload staging files are cleaned up");
            }
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: uploads stage privately, never overwrite existing destinations, survive concurrent commit races, and clean failed staging files.");
    }

    private static Thread contender(FileService files, String payload, CountDownLatch ready, CountDownLatch start,
                                    AtomicInteger successes, AtomicInteger rejected, AtomicReference<Throwable> unexpected) {
        return new Thread(() -> {
            ready.countDown();
            try {
                start.await();
                files.upload("concurrent.bin", new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)), 1024);
                successes.incrementAndGet();
            } catch (java.nio.file.FileAlreadyExistsException | IllegalArgumentException expected) {
                // The destination may be discovered during initial validation or at the final no-replace move.
                rejected.incrementAndGet();
            } catch (Throwable failure) {
                unexpected.compareAndSet(null, failure);
            }
        });
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
