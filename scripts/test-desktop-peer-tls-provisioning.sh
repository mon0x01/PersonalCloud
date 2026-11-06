#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
OUT="$TMP/tls"
PASS='PersonalCloud-Test-Password-2026'

printf '%s\n%s\n' "$PASS" "$PASS" | \
  PERSONALCLOUD_TLS_DIR="$OUT" \
  PERSONALCLOUD_TLS_SAN_IPS='10.23.4.5,2401:4900:ae45:7fcb::5,10.23.4.5' \
  bash "$ROOT/scripts/create-desktop-peer-tls.sh" > "$TMP/create.log"

test -s "$OUT/desktop-ca.key"
test -s "$OUT/desktop-ca.crt"
test -s "$OUT/desktop-server.crt"
test -s "$OUT/desktop-server.p12"
test ! -e "$OUT/desktop-server.key"
test ! -e "$OUT/.desktop-tls-pass."*
[[ "$(stat -c '%a' "$OUT/desktop-ca.key")" == 600 ]]
[[ "$(stat -c '%a' "$OUT/desktop-server.p12")" == 600 ]]
openssl verify -CAfile "$OUT/desktop-ca.crt" "$OUT/desktop-server.crt" >/dev/null
openssl x509 -in "$OUT/desktop-server.crt" -noout -checkip 127.0.0.1 >/dev/null
openssl x509 -in "$OUT/desktop-server.crt" -noout -checkip ::1 >/dev/null
openssl x509 -in "$OUT/desktop-server.crt" -noout -checkip 10.23.4.5 >/dev/null
openssl x509 -in "$OUT/desktop-server.crt" -noout -checkip 2401:4900:ae45:7fcb::5 >/dev/null
openssl pkcs12 -in "$OUT/desktop-server.p12" -noout -passin "pass:$PASS" >/dev/null 2>&1

# The standalone diagnostics command must discover the same default TLS directory
# used by start-node.sh, and validate the identity when its password is supplied.
DIAGNOSTICS="$(PERSONALCLOUD_TLS_DIR="$OUT" PERSONALCLOUD_TLS_KEYSTORE_PASSWORD="$PASS" \
  PERSONALCLOUD_BIND_ADDRESS=127.0.0.1 \
  "$ROOT/integrations/linux/personalcloudctl" network diagnostics \
  --servers 127.0.0.1:9 --timeout-ms 100)"
[[ -n "$DIAGNOSTICS" ]] || { echo "FAIL: network diagnostics returned empty output." >&2; exit 1; }
printf '%s\n' "$DIAGNOSTICS" | python3 -c '
import json, sys
try:
    value = json.load(sys.stdin)
except json.JSONDecodeError as error:
    raise SystemExit(f"FAIL: network diagnostics did not return valid JSON: {error}")
assert value["tlsConfigured"] is True, value
assert value["tlsIdentityStatus"] == "VALID", value
'
DIAGNOSTICS_NO_PASSWORD="$(env -u PERSONALCLOUD_TLS_KEYSTORE_PASSWORD \
  PERSONALCLOUD_TLS_DIR="$OUT" PERSONALCLOUD_BIND_ADDRESS=127.0.0.1 \
  "$ROOT/integrations/linux/personalcloudctl" network diagnostics \
  --servers 127.0.0.1:9 --timeout-ms 100)"
[[ -n "$DIAGNOSTICS_NO_PASSWORD" ]] || { echo "FAIL: password-free diagnostics returned empty output." >&2; exit 1; }
printf '%s\n' "$DIAGNOSTICS_NO_PASSWORD" | python3 -c '
import json, sys
try:
    value = json.load(sys.stdin)
except json.JSONDecodeError as error:
    raise SystemExit(f"FAIL: password-free diagnostics did not return valid JSON: {error}")
assert value["tlsConfigured"] is False, value
assert value["tlsIdentityStatus"] == "PASSWORD_REQUIRED", value
'

if printf '%s\n%s\n' "$PASS" "$PASS" | \
  PERSONALCLOUD_TLS_DIR="$OUT" \
  PERSONALCLOUD_TLS_SAN_IPS='10.23.4.5' \
  bash "$ROOT/scripts/create-desktop-peer-tls.sh" >/dev/null 2>&1; then
  echo "FAIL: TLS generator overwrote an existing identity." >&2
  exit 1
fi

INVALID_OUT="$TMP/invalid"
if printf '%s\n%s\n' "$PASS" "$PASS" | \
  PERSONALCLOUD_TLS_DIR="$INVALID_OUT" \
  PERSONALCLOUD_TLS_SAN_IPS='not-an-ip' \
  bash "$ROOT/scripts/create-desktop-peer-tls.sh" >/dev/null 2>&1; then
  echo "FAIL: TLS generator accepted an invalid SAN address." >&2
  exit 1
fi
if find "$INVALID_OUT" -type f -print -quit 2>/dev/null | grep -q .; then
  echo "FAIL: Invalid SAN input left generated artifacts behind." >&2
  exit 1
fi

echo "PASS: desktop TLS CA/server identity generation, IPv4/IPv6 SAN validation, protected private key, no-overwrite and invalid-input cleanup."
