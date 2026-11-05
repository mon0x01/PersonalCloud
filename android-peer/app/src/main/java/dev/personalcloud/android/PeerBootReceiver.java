package dev.personalcloud.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.UserManager;
import android.util.Log;

public final class PeerBootReceiver extends BroadcastReceiver {
    private static final String TAG = "PersonalCloudBoot";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            return;
        }

        try {
            if (Build.VERSION.SDK_INT >= 24) {
                UserManager users = context.getSystemService(UserManager.class);
                if (users != null && !users.isUserUnlocked()) {
                    Log.i(TAG, "Waiting for user unlock before reading peer configuration.");
                    return;
                }
            }

            AndroidStateStore store = new AndroidStateStore(context.getApplicationContext());
            if (!"true".equalsIgnoreCase(store.getConfig("peer_autostart"))) {
                Log.i(TAG, "Peer auto-start is disabled.");
                return;
            }

            PeerRuntime.lastStatus = "Device boot detected; requesting peer startup.";
            Intent service = new Intent(context, PeerService.class);
            service.setAction(PeerService.ACTION_START);
            context.startForegroundService(service);
            Log.i(TAG, "Peer startup requested after BOOT_COMPLETED.");
        } catch (Exception error) {
            PeerRuntime.lastStatus = "Boot startup failed: "
                    + (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
            Log.e(TAG, PeerRuntime.lastStatus, error);
        }
    }
}
