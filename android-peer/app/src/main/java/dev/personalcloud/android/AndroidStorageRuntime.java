package dev.personalcloud.android;

import android.content.Context;

import java.nio.file.Path;

/**
 * Process-wide owner of the Android SAF reference registry. The foreground peer service and
 * DocumentsProvider must share one instance so grants and recovery state cannot diverge in
 * memory when Android starts the provider independently of the activity/service.
 */
public final class AndroidStorageRuntime {
    private static AndroidSafReferenceStore references;

    private AndroidStorageRuntime() { }

    public static synchronized AndroidSafReferenceStore references(Context context) throws Exception {
        if (references == null) {
            Context app = context.getApplicationContext();
            AndroidStateStore stateStore = new AndroidStateStore(app);
            references = new AndroidSafReferenceStore(app, stateStore,
                    java.nio.file.Paths.get(app.getFilesDir().getAbsolutePath()));
        }
        return references;
    }
}
