# Android peer service lifecycle

## User control

- Starting the Android peer stores `peer_autostart=true` in encrypted app configuration.
- Stopping the peer stores `peer_autostart=false`.
- The boot receiver restarts the service only when the saved preference is enabled.
- The receiver uses `BOOT_COMPLETED`, not `LOCKED_BOOT_COMPLETED`, because peer configuration and TLS identity are credential-protected.

## Foreground service

The LAN peer listener uses Android's `connectedDevice` foreground-service type. The manifest declares `FOREGROUND_SERVICE_CONNECTED_DEVICE` and `CHANGE_NETWORK_STATE`, a documented connected-device prerequisite.

The listener is not a bounded data-sync job. Android 15 disallows starting a `dataSync` foreground service from a boot receiver and also limits its background runtime. The same foreground service owns the durable outbound transfer queue; its recovery executor retries a bounded number of due jobs independently of catalogue synchronization, so a large transfer does not block membership heartbeats. Catalogue synchronization fans out across at most four peer workers. The peer-core takes short synchronized snapshots/commits but does not hold its membership monitor during outbound HTTPS, so inbound member authentication and local controls remain responsive while another device is slow or unavailable.

## Network readiness

At startup, the service waits up to 90 seconds for an IPv4 address matching an IP SAN in the imported PKCS#12 certificate. This can handle Wi-Fi becoming available shortly after boot. It cannot fix a changed DHCP address; the imported certificate must contain the phone's current address.

Startup failures are written to Logcat and shown in a non-ongoing notification. The normal `Node stopped` state no longer overwrites the startup error.

## Network change handling

The foreground peer service registers a default-network callback and reevaluates its advertised listener endpoint when the active network or link properties change. The candidate address is taken from the active network and must exactly match an IPv4 IP subject-alternative-name in the imported server certificate. When it matches, the Android membership client persists the new mutable endpoint and updates only its own catalogue row; the signed Ed25519 membership certificate is never rewritten. The next catalogue/heartbeat pass publishes the new endpoint to other members.

If the active IPv4 address is not covered by the imported certificate, the service keeps the last verified endpoint and reports that the TLS identity must be renewed. It does not advertise an address that would fail TLS hostname verification. The current listener binds an IPv4 wildcard socket; IPv6 listener operation, DNS-SD/mDNS discovery, DHCP-independent host identity, NAT traversal and relay fallback are not implemented by this callback. A certificate with only one IP SAN therefore cannot follow an arbitrary DHCP address change automatically.

The network callback is unregistered with the service and all callback work runs on a dedicated single-thread executor so network events do not block the Android main thread or membership synchronization.

## Durable outbound transfer source retention

A managed placement selection is opened with `ACTION_OPEN_DOCUMENT` and a persistable read grant. The encrypted Android state domain stores the document URI, size, SHA-256, destination and stable transfer UUID—not a second copy of the file. The service retains the URI permission while any job is nonterminal, reopens and rehashes the source before retrying, and refuses to send changed content. Terminal jobs release the picker permission when no SAF reference or recovery snapshot still depends on it.

## Limitations

- A force-stopped app will not receive its boot broadcast until launched again by the user.
- OEM auto-start and battery policies may still suppress startup.
- A simulated boot broadcast does not replace a physical reboot test.

## Presence freshness

Member online state is backed by a direct heartbeat and expires after 90 seconds without a fresh observation. A persisted `online=true` flag is not trusted indefinitely after restart or network loss, and stale catalogue snapshots do not supersede a newer local heartbeat.
