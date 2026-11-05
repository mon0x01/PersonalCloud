#!/usr/bin/env bash
set -Eeuo pipefail

# Creates a desktop TLS identity and a private CA that Android can explicitly trust.
# This script never edits firewall/router settings or starts/binds the node.
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${PERSONALCLOUD_TLS_DIR:-$HOME/.local/share/personalcloud-android-peer-tls}"
mkdir -p "$OUT"
chmod 700 "$OUT"

for name in desktop-ca.key desktop-ca.crt desktop-server.key desktop-server.csr \
            desktop-server.crt desktop-server.p12 desktop-server.ext desktop-ca.srl; do
  if [[ -e "$OUT/$name" || -L "$OUT/$name" ]]; then
    echo "Refusing to overwrite existing desktop TLS material: $OUT/$name" >&2
    echo "Choose a new PERSONALCLOUD_TLS_DIR, or back up and rotate the existing identity deliberately." >&2
    exit 1
  fi
done

for command in openssl ip python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 1
  }
done

RAW_ADDRESSES=()
if [[ -n "${PERSONALCLOUD_TLS_SAN_IPS:-}" ]]; then
  IFS=',' read -r -a RAW_ADDRESSES <<< "$PERSONALCLOUD_TLS_SAN_IPS"
else
  while IFS= read -r address; do [[ -n "$address" ]] && RAW_ADDRESSES+=("$address"); done \
    < <(ip -o -4 addr show up scope global | awk '{split($4,a,"/"); print a[1]}')
  # Prefer stable IPv6 addresses. Temporary, deprecated and tentative addresses can
  # change or are not yet usable, so do not bake them into the certificate.
  while IFS= read -r address; do [[ -n "$address" ]] && RAW_ADDRESSES+=("$address"); done \
    < <(ip -o -6 addr show up scope global | awk '!/ temporary| deprecated| tentative| dadfailed/ {split($4,a,"/"); print a[1]}')
fi

ADDRESS_FILE="$(mktemp "$OUT/.desktop-tls-addresses.XXXXXX")"
trap 'rm -f "$ADDRESS_FILE"' EXIT
printf '%s\n' "${RAW_ADDRESSES[@]}" | python3 -c '
import ipaddress, sys
seen = set()
for line in sys.stdin:
    value = line.strip().split("%", 1)[0]
    if not value:
        continue
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        print("Invalid IP address supplied for TLS SAN: " + value, file=sys.stderr)
        sys.exit(2)
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        continue
    normalized = str(address)
    if normalized not in seen:
        seen.add(normalized)
        print(normalized)
' > "$ADDRESS_FILE"
mapfile -t SAN_IPS < "$ADDRESS_FILE"
rm -f "$ADDRESS_FILE"
trap - EXIT

if ((${#SAN_IPS[@]} == 0)); then
  echo "No usable non-loopback interface addresses were found." >&2
  echo "Connect to your network, or set PERSONALCLOUD_TLS_SAN_IPS to comma-separated interface IPs." >&2
  exit 1
fi

printf 'Desktop TLS certificate will cover these interface addresses:\n'
printf '  %s\n' "${SAN_IPS[@]}"

read -r -s -p "Choose a strong password for the desktop TLS identity and private CA (16+ characters): " TLS_PASSWORD
printf '\n'
read -r -s -p "Confirm password: " TLS_PASSWORD_CONFIRM
printf '\n'
if [[ ${#TLS_PASSWORD} -lt 16 || "$TLS_PASSWORD" != "$TLS_PASSWORD_CONFIRM" ]]; then
  unset TLS_PASSWORD TLS_PASSWORD_CONFIRM
  echo "Password must be at least 16 characters and both entries must match." >&2
  exit 1
fi
unset TLS_PASSWORD_CONFIRM

PASS_FILE="$(mktemp "$OUT/.desktop-tls-pass.XXXXXX")"
chmod 600 "$PASS_FILE"
printf '%s' "$TLS_PASSWORD" > "$PASS_FILE"
unset TLS_PASSWORD
TMP_KEY="$OUT/.desktop-server-key.tmp"
TMP_CSR="$OUT/.desktop-server.csr.tmp"
cleanup() {
  rm -f "$PASS_FILE" "$TMP_KEY" "$TMP_CSR"
}
trap cleanup EXIT

# Root CA key is encrypted at rest. The leaf key is imported into the password-
# protected PKCS#12 identity and its temporary PEM copy is then removed.
openssl genpkey -algorithm RSA -aes-256-cbc -pass file:"$PASS_FILE" \
  -pkeyopt rsa_keygen_bits:3072 -out "$OUT/desktop-ca.key" >/dev/null 2>&1
chmod 600 "$OUT/desktop-ca.key"
openssl req -x509 -new -key "$OUT/desktop-ca.key" -passin file:"$PASS_FILE" \
  -sha256 -days 1825 -out "$OUT/desktop-ca.crt" \
  -subj "/CN=PersonalCloud Desktop Peer CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$TMP_KEY" >/dev/null 2>&1
chmod 600 "$TMP_KEY"
openssl req -new -key "$TMP_KEY" -out "$TMP_CSR" -subj "/CN=PersonalCloud Desktop Peer"

{
  printf '%s\n' '[server_ext]' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid,issuer' \
    'subjectAltName=@san' \
    '' '[san]' \
    'DNS.1=localhost' \
    'IP.1=127.0.0.1' \
    'IP.2=::1'
  index=3
  for address in "${SAN_IPS[@]}"; do
    printf 'IP.%s=%s\n' "$index" "$address"
    ((index += 1))
  done
} > "$OUT/desktop-server.ext"

openssl x509 -req -in "$TMP_CSR" -CA "$OUT/desktop-ca.crt" \
  -CAkey "$OUT/desktop-ca.key" -passin file:"$PASS_FILE" -CAcreateserial \
  -out "$OUT/desktop-server.crt" -days 397 -sha256 -extfile "$OUT/desktop-server.ext" \
  -extensions server_ext >/dev/null 2>&1
openssl pkcs12 -export -name personalcloud-desktop-peer -inkey "$TMP_KEY" \
  -in "$OUT/desktop-server.crt" -certfile "$OUT/desktop-ca.crt" \
  -out "$OUT/desktop-server.p12" -passout file:"$PASS_FILE"

openssl verify -CAfile "$OUT/desktop-ca.crt" "$OUT/desktop-server.crt" >/dev/null
for address in 127.0.0.1 ::1 "${SAN_IPS[@]}"; do
  openssl x509 -in "$OUT/desktop-server.crt" -noout -checkip "$address" >/dev/null
done
openssl pkcs12 -in "$OUT/desktop-server.p12" -noout -passin file:"$PASS_FILE" >/dev/null 2>&1

rm -f "$TMP_KEY" "$TMP_CSR" "$PASS_FILE"
trap - EXIT
chmod 600 "$OUT/desktop-ca.key" "$OUT/desktop-server.p12"
chmod 644 "$OUT/desktop-ca.crt" "$OUT/desktop-server.crt"
chmod 600 "$OUT/desktop-server.ext"

printf '\nCreated desktop TLS identity in: %s\n' "$OUT"
printf 'Server identity: %s\n' "$OUT/desktop-server.p12"
printf 'Trusted CA to import into Android: %s\n' "$OUT/desktop-ca.crt"
printf 'Encrypted CA signing key (keep private): %s\n' "$OUT/desktop-ca.key"
printf '\nThe node remains loopback-bound until you explicitly choose a bind address.\n'
printf 'For a later direct-listener test, use one of the listed addresses as PERSONALCLOUD_BIND_ADDRESS.\n'
printf 'The matching certificate SAN is included; firewall and remote reachability still require separate validation.\n'
