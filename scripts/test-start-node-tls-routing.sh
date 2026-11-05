#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START="$ROOT/scripts/start-node.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

make_fixture() {
  local home="$1"
  mkdir -p "$home/project/scripts"
  cp "$START" "$home/project/scripts/start-node.sh"
  cat > "$home/project/run.sh" <<'RUN'
#!/usr/bin/env bash
printf 'KEYSTORE=%s\n' "${PERSONALCLOUD_TLS_KEYSTORE:-}"
printf 'TRUSTSTORE=%s\n' "${PERSONALCLOUD_TLS_TRUSTSTORE:-}"
printf 'KEYPASS=%s\n' "${PERSONALCLOUD_TLS_KEYSTORE_PASSWORD:-}"
printf 'TRUSTPASS=%s\n' "${PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD:-}"
printf 'BIND=%s\n' "${PERSONALCLOUD_BIND_ADDRESS:-}"
RUN
  chmod +x "$home/project/run.sh"
}

# Current default: separate desktop identity and Android truststore directories.
HOME1="$TMP/home-default"
make_fixture "$HOME1"
mkdir -p "$HOME1/.local/share/personalcloud-desktop-peer-tls" "$HOME1/.local/share/personalcloud-android-peer-tls"
printf x > "$HOME1/.local/share/personalcloud-desktop-peer-tls/desktop-server.p12"
printf x > "$HOME1/.local/share/personalcloud-android-peer-tls/desktop-truststore.p12"
OUTPUT="$(cd "$HOME1/project" && env HOME="$HOME1" \
  PERSONALCLOUD_TLS_KEYSTORE_PASSWORD=identity-secret \
  PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD=trust-secret \
  PERSONALCLOUD_BIND_ADDRESS=192.0.2.10 bash scripts/start-node.sh)"
grep -Fq "KEYSTORE=$HOME1/.local/share/personalcloud-desktop-peer-tls/desktop-server.p12" <<< "$OUTPUT" || fail "desktop identity did not resolve from desktop TLS directory"
grep -Fq "TRUSTSTORE=$HOME1/.local/share/personalcloud-android-peer-tls/desktop-truststore.p12" <<< "$OUTPUT" || fail "Android truststore did not resolve from Android TLS directory"

# Legacy shared directory override remains supported.
HOME2="$TMP/home-legacy"
make_fixture "$HOME2"
mkdir -p "$HOME2/custom-tls"
printf x > "$HOME2/custom-tls/desktop-server.p12"
printf x > "$HOME2/custom-tls/desktop-truststore.p12"
OUTPUT="$(cd "$HOME2/project" && env HOME="$HOME2" PERSONALCLOUD_TLS_DIR="$HOME2/custom-tls" \
  PERSONALCLOUD_TLS_KEYSTORE_PASSWORD=identity-secret \
  PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD=trust-secret bash scripts/start-node.sh)"
grep -Fq "KEYSTORE=$HOME2/custom-tls/desktop-server.p12" <<< "$OUTPUT" || fail "legacy identity override failed"
grep -Fq "TRUSTSTORE=$HOME2/custom-tls/desktop-truststore.p12" <<< "$OUTPUT" || fail "legacy truststore override failed"

# Role-specific directory overrides can point at independently selected locations.
HOME_ROLE="$TMP/home-role"
make_fixture "$HOME_ROLE"
mkdir -p "$HOME_ROLE/custom-identity" "$HOME_ROLE/custom-trust"
printf x > "$HOME_ROLE/custom-identity/desktop-server.p12"
printf x > "$HOME_ROLE/custom-trust/desktop-truststore.p12"
OUTPUT="$(cd "$HOME_ROLE/project" && env HOME="$HOME_ROLE" \
  PERSONALCLOUD_TLS_IDENTITY_DIR="$HOME_ROLE/custom-identity" \
  PERSONALCLOUD_TLS_TRUSTSTORE_DIR="$HOME_ROLE/custom-trust" \
  PERSONALCLOUD_TLS_KEYSTORE_PASSWORD=identity-secret \
  PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD=trust-secret bash scripts/start-node.sh)"
grep -Fq "KEYSTORE=$HOME_ROLE/custom-identity/desktop-server.p12" <<< "$OUTPUT" || fail "role-specific identity directory override failed"
grep -Fq "TRUSTSTORE=$HOME_ROLE/custom-trust/desktop-truststore.p12" <<< "$OUTPUT" || fail "role-specific truststore directory override failed"

# Explicit file overrides must take precedence.
HOME3="$TMP/home-explicit"
make_fixture "$HOME3"
mkdir -p "$HOME3/explicit"
printf x > "$HOME3/explicit/identity.p12"
printf x > "$HOME3/explicit/truststore.p12"
OUTPUT="$(cd "$HOME3/project" && env HOME="$HOME3" \
  PERSONALCLOUD_TLS_KEYSTORE="$HOME3/explicit/identity.p12" \
  PERSONALCLOUD_TLS_TRUSTSTORE="$HOME3/explicit/truststore.p12" \
  PERSONALCLOUD_TLS_KEYSTORE_PASSWORD=identity-secret \
  PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD=trust-secret \
  bash scripts/start-node.sh)"
grep -Fq "KEYSTORE=$HOME3/explicit/identity.p12" <<< "$OUTPUT" || fail "explicit identity override was ignored"
grep -Fq "TRUSTSTORE=$HOME3/explicit/truststore.p12" <<< "$OUTPUT" || fail "explicit truststore override was ignored"

# Invalid bind input fails closed before launching the node.
set +e
OUTPUT="$(cd "$HOME1/project" && env HOME="$HOME1" PERSONALCLOUD_TLS_KEYSTORE_PASSWORD=identity-secret PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD=trust-secret PERSONALCLOUD_BIND_ADDRESS=not-an-ip bash scripts/start-node.sh 2>&1)"
STATUS=$?
set -e
[[ $STATUS -eq 2 ]] || fail "invalid bind address did not fail with status 2"
grep -Fq 'must be a literal IPv4 or IPv6 address' <<< "$OUTPUT" || fail "invalid bind address error is unclear"

echo "PASS: desktop identity and Android truststore resolve independently; role-specific, legacy and explicit overrides work; invalid bind addresses fail closed."
