# Desktop TLS identity and peer truststore routing

PersonalCloud has two distinct TLS directions on the desktop node:

- The desktop's **server identity** is presented to incoming Android peers. Current default: `~/.local/share/personalcloud-desktop-peer-tls/desktop-server.p12`.
- The desktop's **peer truststore** validates Android HTTPS server certificates when the desktop makes outbound requests. Current default: `~/.local/share/personalcloud-android-peer-tls/desktop-truststore.p12`.

These files belong in different directories because they are produced by different provisioning steps. `scripts/start-node.sh` now discovers them independently and prompts for each password separately. No password is written to a config file or command line.

## Start on the local Wi-Fi interface

Use a literal address that is currently assigned to the desktop and is present in the desktop server certificate SANs:

```bash
PERSONALCLOUD_BIND_ADDRESS=10.239.151.215 bash ./scripts/start-node.sh
```

The server identity password is requested first. The Android peer truststore password is requested second, if that truststore exists. `PERSONALCLOUD_PORT` defaults to `8787`.

## Override paths

- `PERSONALCLOUD_TLS_IDENTITY_DIR`: directory containing `desktop-server.p12`.
- `PERSONALCLOUD_TLS_TRUSTSTORE_DIR`: directory containing `desktop-truststore.p12`.
- `PERSONALCLOUD_TLS_KEYSTORE` and `PERSONALCLOUD_TLS_TRUSTSTORE`: explicit file overrides.
- `PERSONALCLOUD_TLS_DIR`: legacy compatibility override; when supplied, it remains the default for both files unless one of the role-specific directory overrides is supplied.

The desktop identity defaults to `~/.local/share/personalcloud-desktop-peer-tls`. If it is absent, startup falls back to the older desktop identity under `~/.local/share/personalcloud-android-peer-tls`.

## Android trust direction

To let Android validate the desktop HTTPS server, import the public `desktop-ca.crt` using the Android app's **Import trusted peer CA (.crt / .pem)** action. The app stores this as its `peer_ca`. The desktop must separately retain the Android CA in its `desktop-truststore.p12` to validate the phone when it connects back to Android.

Only the public `desktop-ca.crt` is transferred to Android. Never transfer `desktop-ca.key` or `desktop-server.p12` to the phone. The server PKCS#12 contains the desktop private identity.

## Important security distinction

This is reciprocal certificate trust for HTTPS server authentication, combined with PersonalCloud's application-level signed member identity and authorization. The current HTTP servers do not request TLS client certificates, so this is **not mutual TLS (mTLS)**. Do not describe it as mTLS.

Binding to a LAN address does not configure the firewall or prove remote reachability. Keep the first test on the same trusted Wi-Fi network. The wrapper warns when a non-loopback bind is requested without the Android peer truststore because outbound desktop-to-Android HTTPS will not be able to validate the phone CA.
