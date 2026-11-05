package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Verifies the state file lock prevents lost updates between independent JVMs. */
public final class StateStoreMultiProcessTest {
    private static final int WORKERS = 4;
    private static final int WRITES_PER_WORKER = 40;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--worker".equals(args[0])) {
            worker(Path.of(args[1]), args[2], Integer.parseInt(args[3]));
            return;
        }
        Path directory = Files.createTempDirectory("personalcloud-state-multiprocess-");
        try {
            StateStore observer = new StateStore(directory);
            Process[] workers = new Process[WORKERS];
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            for (int i = 0; i < WORKERS; i++) {
                workers[i] = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                        StateStoreMultiProcessTest.class.getName(), "--worker", directory.toString(),
                        "worker-" + i, Integer.toString(WRITES_PER_WORKER)).inheritIO().start();
            }
            for (Process worker : workers) {
                if (!worker.waitFor(30, TimeUnit.SECONDS)) {
                    worker.destroyForcibly();
                    throw new AssertionError("StateStore writer process timed out.");
                }
                if (worker.exitValue() != 0) throw new AssertionError("StateStore writer process failed with exit " + worker.exitValue());
            }
            int observed = 0;
            for (int worker = 0; worker < WORKERS; worker++) {
                for (int item = 0; item < WRITES_PER_WORKER; item++) {
                    String key = "worker-" + worker + ".key-" + item;
                    check(("value-" + item).equals(observer.get(key)), "lost or stale cross-process key: " + key);
                    Map<String, String> record = observer.getRecord("multi", "worker-" + worker + "-" + item);
                    check(record != null && ("record-" + item).equals(record.get("value")),
                            "lost or stale cross-process record: " + worker + "/" + item);
                    observed++;
                }
            }
            check(observed == WORKERS * WRITES_PER_WORKER, "not all concurrent state writes were observed");
        } finally {
            try (var paths = Files.walk(directory)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: StateStore serializes independent JVM writers and refreshes stale readers without losing keys or records.");
    }

    private static void worker(Path directory, String worker, int count) throws Exception {
        StateStore store = new StateStore(directory);
        for (int i = 0; i < count; i++) {
            store.put(worker + ".key-" + i, "value-" + i);
            store.putRecord("multi", worker + "-" + i, Map.of("value", "record-" + i));
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
