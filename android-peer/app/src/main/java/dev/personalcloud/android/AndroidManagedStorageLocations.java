package dev.personalcloud.android;

import android.content.Context;
import android.os.Environment;
import android.os.StatFs;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.text.format.Formatter;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Resolves stable Android app-specific managed-placement roots.
 * Absolute mount paths are intentionally not persisted; only a volume identity is stored.
 */
public final class AndroidManagedStorageLocations {
    public static final String CONFIG_KEY = "managed_storage_volume_id";
    public static final String APP_PRIVATE_ID = "app-private";

    public static final class Location {
        public final String id;
        public final String label;
        public final String kind;
        public final String state;
        public final boolean removable;
        public final boolean writable;
        public final long totalBytes;
        public final long freeBytes;
        final File baseDirectory;

        private Location(String id, String label, String kind, String state,
                         boolean removable, boolean writable, long totalBytes,
                         long freeBytes, File baseDirectory) {
            this.id = id;
            this.label = label;
            this.kind = kind;
            this.state = state;
            this.removable = removable;
            this.writable = writable;
            this.totalBytes = totalBytes;
            this.freeBytes = freeBytes;
            this.baseDirectory = baseDirectory;
        }

        public String display(Context context) {
            String type = removable ? "REMOVABLE" : kind;
            String capacity = totalBytes < 0 ? "capacity unavailable"
                    : Formatter.formatFileSize(context, freeBytes) + " free / "
                    + Formatter.formatFileSize(context, totalBytes);
            String lifetime = removable || id.startsWith("external-")
                    ? " · app-specific data (may be removed on app uninstall)" : " · app-private data";
            return label + " · " + type + " · " + state + " · " + capacity + lifetime;
        }
    }

    private AndroidManagedStorageLocations() { }

    public static List<Location> available(Context context) {
        Context app = context.getApplicationContext();
        List<Location> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        File privateRoot = app.getFilesDir();
        long[] privateCapacity = capacity(privateRoot);
        result.add(new Location(APP_PRIVATE_ID, "App-private internal storage",
                "APP_PRIVATE", "AVAILABLE", false, true,
                privateCapacity[0], privateCapacity[1], privateRoot));
        seen.add(APP_PRIVATE_ID);

        StorageManager manager = app.getSystemService(StorageManager.class);
        if (manager == null) return Collections.unmodifiableList(result);

        File[] appSpecificDirectories = app.getExternalFilesDirs(null);
        if (appSpecificDirectories == null) return Collections.unmodifiableList(result);

        for (File directory : appSpecificDirectories) {
            if (directory == null) continue;
            try {
                StorageVolume volume = manager.getStorageVolume(directory);
                if (volume == null) continue;

                String id;
                if (volume.isPrimary()) {
                    id = "external-primary";
                } else {
                    String uuid = volume.getUuid();
                    // A non-primary volume without a filesystem UUID cannot be safely
                    // rebound after reconnect. Do not persist a path-derived identity.
                    if (uuid == null || uuid.isBlank()) continue;
                    id = "external-uuid:" + uuid.toLowerCase(Locale.ROOT);
                }
                if (!seen.add(id)) continue;

                String state;
                try {
                    state = Environment.getExternalStorageState(directory);
                } catch (RuntimeException unavailable) {
                    state = "unknown";
                }
                boolean writable = Environment.MEDIA_MOUNTED.equals(state);
                String label = volume.getDescription(app);
                long[] capacity = capacity(directory);

                result.add(new Location(id,
                        label == null || label.isBlank() ? "External Android storage" : label,
                        volume.isEmulated() ? "EMULATED_EXTERNAL" : "EXTERNAL",
                        state, volume.isRemovable(), writable,
                        capacity[0], capacity[1], directory));
            } catch (RuntimeException unavailable) {
                // A removable volume can disappear while the inventory is being read.
                // The service will re-resolve and fail closed when it starts.
            }
        }
        return Collections.unmodifiableList(result);
    }

    public static Path resolveManagedRoot(Context context, String requestedId) throws Exception {
        String selected = requestedId == null || requestedId.isBlank()
                ? APP_PRIVATE_ID : requestedId;
        Location chosen = null;
        for (Location location : available(context)) {
            if (selected.equals(location.id)) {
                chosen = location;
                break;
            }
        }

        if (chosen == null) {
            throw new IllegalStateException("Selected managed-storage volume '" + selected
                    + "' is unavailable. Reconnect it or choose another volume; PersonalCloud will not silently use internal storage.");
        }
        if (!chosen.writable) {
            throw new IllegalStateException("Selected managed-storage volume '" + selected
                    + "' is not mounted read-write (state: " + chosen.state + ").");
        }

        File base = chosen.baseDirectory;
        if (!base.isDirectory() && !base.mkdirs() && !base.isDirectory()) {
            throw new IllegalStateException("Cannot create the Android app-specific directory on selected volume '" + selected + "'.");
        }
        if (!base.canWrite()) {
            throw new IllegalStateException("Android does not currently permit writes to selected volume '" + selected + "'.");
        }

        File target = new File(base, "distributed-storage");
        if (Files.isSymbolicLink(target.toPath())) {
            throw new SecurityException("Managed storage root cannot be a symbolic link.");
        }
        if (!target.isDirectory() && !target.mkdirs() && !target.isDirectory()) {
            throw new IllegalStateException("Cannot create the PersonalCloud managed-storage directory on selected volume.");
        }
        if (!target.canWrite() || !Files.isDirectory(target.toPath())) {
            throw new IllegalStateException("Selected PersonalCloud managed-storage directory is not writable.");
        }

        Path canonicalBase = base.getCanonicalFile().toPath();
        Path canonicalTarget = target.getCanonicalFile().toPath();
        if (!canonicalTarget.startsWith(canonicalBase) || canonicalTarget.equals(canonicalBase)) {
            throw new SecurityException("Selected managed-storage directory escaped its Android volume.");
        }
        return canonicalTarget;
    }

    private static long[] capacity(File directory) {
        try {
            File probe = directory.exists() ? directory : directory.getParentFile();
            if (probe == null) return new long[] {-1L, -1L};
            StatFs stats = new StatFs(probe.getAbsolutePath());
            return new long[] {stats.getTotalBytes(), stats.getAvailableBytes()};
        } catch (RuntimeException unavailable) {
            return new long[] {-1L, -1L};
        }
    }
}
