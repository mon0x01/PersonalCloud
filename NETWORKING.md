# PersonalCloud V1 networking guide

## Current model

Each node runs its own HTTP/HTTPS endpoint. Peers connect directly to the endpoint stored during pairing. There is no cloud file server, rendezvous service, NAT traversal, STUN/ICE/TURN, or relay in V1.

A peer must be able to reach the other peer's address and port. Localhost works for one-machine testing. A trusted LAN works when devices can route to each other and TLS certificates match their URLs. Different networks generally require a separately configured VPN such as WireGuard or Tailscale; this project does not install or manage a VPN.

## HTTPS requirements

- Non-loopback listeners require `PERSONALCLOUD_TLS_KEYSTORE` and its password.
- Use a PKCS#12 keystore.
- The certificate SAN must contain the exact hostname/IP used in the peer URL.
- The connecting node must trust the issuer/certificate through the JVM trust store or `PERSONALCLOUD_TLS_TRUSTSTORE`.
- Hostname verification remains enabled.
- The browser/OS must trust the server certificate as well.

## Example topology

```text
Laptop A (PersonalCloud node A)
  HTTPS endpoint: https://pc-a.vpn.example:8787
  local storage:  /home/user/PersonalCloud/storage
  |
  | trusted VPN route + TLS + paired peer token
  |
Laptop B (PersonalCloud node B)
  HTTPS endpoint: https://pc-b.vpn.example:8787
  local storage:  /home/user/PersonalCloud/storage
```

Pairing B to A allows B to request A's granted content. Pairing A to B separately allows A to request B's granted content. A grant is still required for each file/folder and peer.

## What V1 does not do

- No automatic device discovery or public endpoint registration.
- No ICE candidate exchange or STUN-based public address discovery.
- No TURN server or relay fallback.
- No automatic reconnection strategy beyond retrying peer health/API requests.
- No application-level end-to-end file-content encryption. HTTPS protects the hop; both endpoints can read the data.

Do not attempt to make arbitrary residential/mobile NATs work by forwarding the application port publicly. A future networking milestone needs a rendezvous protocol, ICE/STUN candidate gathering, optional TURN-like relay, device identity verification, and cross-network integration tests.
