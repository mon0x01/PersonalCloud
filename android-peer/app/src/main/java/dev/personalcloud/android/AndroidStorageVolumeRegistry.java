package dev.personalcloud.android;

import android.annotation.TargetApi;
import android.app.usage.StorageStatsManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.text.format.Formatter;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Read-only inventory of Android storage volumes.
 *
 * Discovery is intentionally separate from file access:
 * - getExternalFilesDirs() identifies app-owned writable locations.
 * - removable volumes without such a directory require user-authorized SAF access.
 * - no absolute volume paths or access grants are persisted here.
 */
public final class AndroidStorageVolumeRegistry implements AutoCloseable {

    public interface Listener {
        void onVolumesChanged(Snapshot snapshot);
    }

    public static final class Volume {
        public final String id;
        public final String label;
        public final String kind;
        public final String state;
        public final String accessMode;
        public final boolean primary;
        public final boolean removable;
        public final boolean emulated;
        public final boolean mounted;
        public final boolean writable;
        public final boolean appSpecificDirectoryAvailable;
        public final long totalBytes;
        public final long freeBytes;

        private Volume(
                String id,
                String label,
                String kind,
                String state,
                String accessMode,
                boolean primary,
                boolean removable,
                boolean emulated,
                boolean mounted,
                boolean writable,
                boolean appSpecificDirectoryAvailable,
                long totalBytes,
                long freeBytes) {
            this.id = id;
            this.label = label;
            this.kind = kind;
            this.state = state;
            this.accessMode = accessMode;
            this.primary = primary;
            this.removable = removable;
            this.emulated = emulated;
            this.mounted = mounted;
            this.writable = writable;
            this.appSpecificDirectoryAvailable = appSpecificDirectoryAvailable;
            this.totalBytes = totalBytes;
            this.freeBytes = freeBytes;
        }
    }

    public static final class Snapshot {
        public final List<Volume> volumes;
        public final String generatedAt;
        public final String error;

        private Snapshot(List<Volume> volumes, String error) {
            this.volumes = Collections.unmodifiableList(new ArrayList<>(volumes));
            this.generatedAt = java.time.Instant.now().toString();
            this.error = error;
        }

        private static Snapshot failure(Exception error) {
            String message = error.getMessage();
            if (message == null || message.isBlank()) {
                message = error.getClass().getSimpleName();
            }
            return new Snapshot(Collections.emptyList(), message);
        }

        public String toDisplayText(Context context) {
            if (error != null) {
                return "Storage inventory unavailable: " + error;
            }

            StringBuilder output = new StringBuilder();
            output.append("Storage inventory · ")
                    .append(volumes.size())
                    .append(" volumes\n")
                    .append("Updated: ")
                    .append(generatedAt)
                    .append("\n\n");

            for (Volume volume : volumes) {
                output.append(volume.label)
                        .append("\n")
                        .append("  Type: ").append(volume.kind).append("\n")
                        .append("  State: ").append(volume.state).append("\n")
                        .append("  Access: ").append(volume.accessMode).append("\n");

                if (volume.totalBytes >= 0) {
                    output.append("  Capacity: ")
                            .append(Formatter.formatFileSize(context, volume.totalBytes))
                            .append("\n");
                } else {
                    output.append("  Capacity: unavailable\n");
                }

                if (volume.freeBytes >= 0) {
                    output.append("  Free: ")
                            .append(Formatter.formatFileSize(context, volume.freeBytes))
                            .append(" (platform estimate)\n");
                } else {
                    output.append("  Free: unavailable\n");
                }

                if (volume.removable && !volume.appSpecificDirectoryAvailable
                        && volume.mounted) {
                    output.append("  Note: choose a folder through Android's system picker.\n");
                }

                output.append("\n");
            }

            output.append(
                    "Current node storage remains app-private. No files were moved. "
                    + "A detected volume is not automatically available for PersonalCloud writes."
            );

            return output.toString();
        }
    }

    private final Context context;
    private final StorageManager storageManager;
    private final Listener listener;
    private final ExecutorService worker;
    private volatile boolean closed;
    private boolean started;
    private boolean legacyReceiverRegistered;
    private boolean modernCallbackRegistered;
    private BroadcastReceiver legacyReceiver;
    private Object modernCallback;

    public AndroidStorageVolumeRegistry(Context context, Listener listener) {
        this.context = context.getApplicationContext();
        this.listener = listener;
        this.storageManager = this.context.getSystemService(StorageManager.class);

        if (storageManager == null) {
            throw new IllegalStateException("Android StorageManager is unavailable.");
        }

        this.worker = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "personalcloud-storage-inventory");
            thread.setDaemon(true);
            return thread;
        });
    }

    public synchronized void start() {
        if (started) return;
        started = true;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            registerModernCallback();
        } else {
            registerLegacyReceiver();
        }

        scheduleRefresh();
    }

    private void scheduleRefresh() {
        if (closed) return;

        try {
            worker.execute(() -> {
                if (closed) return;

                Snapshot snapshot;
                try {
                    snapshot = inspect(context);
                } catch (Exception error) {
                    snapshot = Snapshot.failure(error);
                }

                if (!closed && listener != null) {
                    listener.onVolumesChanged(snapshot);
                }
            });
        } catch (RejectedExecutionException ignored) {
            // The activity may have stopped while an event was being delivered.
        }
    }

    public static Snapshot inspect(Context context) throws Exception {
        Context app = context.getApplicationContext();
        StorageManager manager = app.getSystemService(StorageManager.class);
        StorageStatsManager stats = app.getSystemService(StorageStatsManager.class);

        if (manager == null) {
            throw new IllegalStateException("Android StorageManager is unavailable.");
        }

        List<Volume> result = new ArrayList<>();

        // This is the current managed node's private storage, not shared storage.
        long[] privateCapacity = statCapacity(app.getFilesDir());
        result.add(new Volume(
                "app-private",
                "App-private internal storage",
                "APP_PRIVATE",
                Environment.MEDIA_MOUNTED,
                "DIRECT_PRIVATE_APP_STORAGE · current node storage",
                true,
                false,
                false,
                true,
                true,
                true,
                privateCapacity[0],
                privateCapacity[1]
        ));

        // Map Android-provided app-specific directories back to their owning volumes.
        // Android excludes transient USB flash drives from this list.
        Map<String, File> appDirectories = new HashMap<>();
        File[] externalDirectories = app.getExternalFilesDirs(null);

        if (externalDirectories != null) {
            for (File directory : externalDirectories) {
                if (directory == null) continue;

                try {
                    StorageVolume owner = manager.getStorageVolume(directory);
                    if (owner != null) {
                        appDirectories.put(volumeId(app, owner), directory);
                    }
                } catch (RuntimeException ignored) {
                    // An unavailable or concurrently detached volume is reported
                    // without granting it an assumed writable path.
                }
            }
        }

        List<StorageVolume> attached = manager.getStorageVolumes();

        for (StorageVolume volume : attached) {
            String id = volumeId(app, volume);
            String label = volume.getDescription(app);
            String state = volume.getState();

            boolean mounted = Environment.MEDIA_MOUNTED.equals(state)
                    || Environment.MEDIA_MOUNTED_READ_ONLY.equals(state);

            boolean writable = Environment.MEDIA_MOUNTED.equals(state);

            File appDirectory = appDirectories.get(id);
            boolean appSpecific = appDirectory != null && writable;

            String access;
            if (appSpecific) {
                access = "APP_SPECIFIC_WRITABLE · removed when app is uninstalled";
            } else if (Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)) {
                access = "READ_ONLY";
            } else if (mounted) {
                access = "SAF_REQUIRED · user-selected folder";
            } else {
                access = "UNAVAILABLE";
            }

            String kind;
            if (volume.isRemovable()) {
                kind = "REMOVABLE_VOLUME · SD / USB";
            } else if (volume.isPrimary()) {
                kind = "PRIMARY_SHARED_STORAGE";
            } else if (volume.isEmulated()) {
                kind = "EMULATED_SHARED_STORAGE";
            } else {
                kind = "FIXED_SHARED_STORAGE";
            }

            long[] capacity = statVolumeCapacity(stats, volume);

            result.add(new Volume(
                    id,
                    label == null || label.isBlank() ? "Android storage volume" : label,
                    kind,
                    state,
                    access,
                    volume.isPrimary(),
                    volume.isRemovable(),
                    volume.isEmulated(),
                    mounted,
                    writable,
                    appSpecific,
                    capacity[0],
                    capacity[1]
            ));
        }

        return new Snapshot(result, null);
    }

    private static String volumeId(Context context, StorageVolume volume) {
        if (volume.isPrimary()) return "primary";

        String uuid = volume.getUuid();
        if (uuid != null && !uuid.isBlank()) {
            return "uuid:" + uuid.toLowerCase(Locale.ROOT);
        }

        // A volume without a filesystem UUID receives a session identity.
        // It is deliberately not suitable for persistent placement configuration.
        String description = volume.getDescription(context);
        String identity = String.valueOf(description)
                + "|" + volume.isRemovable()
                + "|" + volume.isEmulated();

        return "session:" + Integer.toHexString(identity.hashCode());
    }

    private static long[] statCapacity(File directory) {
        try {
            StatFs stats = new StatFs(directory.getAbsolutePath());
            return new long[] { stats.getTotalBytes(), stats.getAvailableBytes() };
        } catch (RuntimeException unavailable) {
            return new long[] { -1L, -1L };
        }
    }

    private static long[] statVolumeCapacity(
            StorageStatsManager stats,
            StorageVolume volume) {
        if (stats == null) return new long[] { -1L, -1L };

        try {
            UUID storageUuid;

            if (volume.isPrimary()) {
                storageUuid = StorageManager.UUID_DEFAULT;
            } else {
                String value = volume.getUuid();
                if (value == null || value.isBlank()) {
                    return new long[] { -1L, -1L };
                }
                storageUuid = UUID.fromString(value);
            }

            return new long[] {
                    stats.getTotalBytes(storageUuid),
                    stats.getFreeBytes(storageUuid)
            };
        } catch (Exception unavailable) {
            return new long[] { -1L, -1L };
        }
    }

    @TargetApi(Build.VERSION_CODES.R)
    private void registerModernCallback() {
        StorageManager.StorageVolumeCallback callback =
                new StorageManager.StorageVolumeCallback() {
                    @Override
                    public void onStateChanged(StorageVolume volume) {
                        scheduleRefresh();
                    }
                };

        modernCallback = callback;
        storageManager.registerStorageVolumeCallback(worker, callback);
        modernCallbackRegistered = true;
    }

    @TargetApi(Build.VERSION_CODES.R)
    private void unregisterModernCallback() {
        if (!modernCallbackRegistered || modernCallback == null) return;

        storageManager.unregisterStorageVolumeCallback(
                (StorageManager.StorageVolumeCallback) modernCallback);

        modernCallbackRegistered = false;
        modernCallback = null;
    }

    private void registerLegacyReceiver() {
        legacyReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context receiverContext, Intent intent) {
                scheduleRefresh();
            }
        };

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_MEDIA_MOUNTED);
        filter.addAction(Intent.ACTION_MEDIA_UNMOUNTED);
        filter.addAction(Intent.ACTION_MEDIA_EJECT);
        filter.addAction(Intent.ACTION_MEDIA_REMOVED);
        filter.addAction(Intent.ACTION_MEDIA_BAD_REMOVAL);
        filter.addAction(Intent.ACTION_MEDIA_CHECKING);
        filter.addAction(Intent.ACTION_MEDIA_NOFS);
        filter.addAction(Intent.ACTION_MEDIA_UNMOUNTABLE);
        filter.addDataScheme("file");

        context.registerReceiver(legacyReceiver, filter);
        legacyReceiverRegistered = true;
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                unregisterModernCallback();
            }

            if (legacyReceiverRegistered && legacyReceiver != null) {
                context.unregisterReceiver(legacyReceiver);
                legacyReceiverRegistered = false;
            }
        } catch (RuntimeException ignored) {
            // The activity may already be detached during process shutdown.
        }

        worker.shutdownNow();
    }
}
