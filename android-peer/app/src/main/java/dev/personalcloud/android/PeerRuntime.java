package dev.personalcloud.android;

import dev.personalcloud.android.core.NetworkMembershipClient;
import dev.personalcloud.android.core.PeerNode;
import dev.personalcloud.android.core.OutboundTransferQueue;

/** Process-wide handles owned by the foreground PeerService. */
public final class PeerRuntime {
    public static volatile PeerNode node;
    public static volatile NetworkMembershipClient membership;
    public static volatile OutboundTransferQueue outboundTransfers;
    public static volatile String lastStatus = "Node stopped";
    private PeerRuntime() { }
}
