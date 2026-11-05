#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Older releases used one directory for both the local server identity and the
# truststore used by outbound desktop -> Android connections. Keep that override
# compatible, but default to the two independent directories used by current setup.
LEGACY_TLS_DIR="${PERSONALCLOUD_TLS_DIR:-}"
if [[ -n "$LEGACY_TLS_DIR" ]]; then
  DEFAULT_IDENTITY_DIR="$LEGACY_TLS_DIR"
  DEFAULT_TRUSTSTORE_DIR="$LEGACY_TLS_DIR"
else
  DEFAULT_IDENTITY_DIR="$HOME/.local/share/personalcloud-desktop-peer-tls"
  DEFAULT_TRUSTSTORE_DIR="$HOME/.local/share/personalcloud-android-peer-tls"
  # Backward compatibility for machines that have not created the new desktop
  # identity yet, but still have the older desktop-server.p12 in the Android dir.
  if [[ ! -s "$DEFAULT_IDENTITY_DIR/desktop-server.p12" \
        && -s "$DEFAULT_TRUSTSTORE_DIR/desktop-server.p12" ]]; then
    DEFAULT_IDENTITY_DIR="$DEFAULT_TRUSTSTORE_DIR"
  fi
fi

IDENTITY_DIR="${PERSONALCLOUD_TLS_IDENTITY_DIR:-$DEFAULT_IDENTITY_DIR}"
TRUSTSTORE_DIR="${PERSONALCLOUD_TLS_TRUSTSTORE_DIR:-$DEFAULT_TRUSTSTORE_DIR}"

prompt_secret() {
  local prompt="$1"
  local variable="$2"
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    echo "Cannot prompt for $prompt without an interactive terminal." >&2
    return 1
  fi
  local value
  IFS= read -r -s -p "$prompt" value </dev/tty
  printf '\n' >/dev/tty
  printf -v "$variable" '%s' "$value"
  unset value
}

if [[ -z "${PERSONALCLOUD_TLS_KEYSTORE:-}" ]]; then
  if [[ -s "$IDENTITY_DIR/desktop-server.p12" ]]; then
    export PERSONALCLOUD_TLS_KEYSTORE="$IDENTITY_DIR/desktop-server.p12"
  fi
fi
if [[ -n "${PERSONALCLOUD_TLS_KEYSTORE:-}" ]]; then
  if [[ ! -f "$PERSONALCLOUD_TLS_KEYSTORE" || -L "$PERSONALCLOUD_TLS_KEYSTORE" ]]; then
    echo "Desktop TLS identity must be a regular, non-symlink file: $PERSONALCLOUD_TLS_KEYSTORE" >&2
    exit 2
  fi
  if [[ -z "${PERSONALCLOUD_TLS_KEYSTORE_PASSWORD:-}" ]]; then
    prompt_secret "Desktop TLS identity password: " PERSONALCLOUD_TLS_KEYSTORE_PASSWORD
    export PERSONALCLOUD_TLS_KEYSTORE_PASSWORD
  fi
  echo "Using desktop TLS identity: $PERSONALCLOUD_TLS_KEYSTORE"
fi

if [[ -z "${PERSONALCLOUD_TLS_TRUSTSTORE:-}" && -s "$TRUSTSTORE_DIR/desktop-truststore.p12" ]]; then
  export PERSONALCLOUD_TLS_TRUSTSTORE="$TRUSTSTORE_DIR/desktop-truststore.p12"
fi
if [[ -n "${PERSONALCLOUD_TLS_TRUSTSTORE:-}" ]]; then
  if [[ ! -f "$PERSONALCLOUD_TLS_TRUSTSTORE" || -L "$PERSONALCLOUD_TLS_TRUSTSTORE" ]]; then
    echo "Android peer truststore must be a regular, non-symlink file: $PERSONALCLOUD_TLS_TRUSTSTORE" >&2
    exit 2
  fi
  if [[ -z "${PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD:-}" ]]; then
    prompt_secret "Android peer truststore password: " PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD
    export PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD
  fi
  echo "Using Android peer truststore: $PERSONALCLOUD_TLS_TRUSTSTORE"
fi

if [[ -z "${PERSONALCLOUD_BIND_ADDRESS:-}" ]]; then
  echo "Bind address defaults to localhost for safety. Set PERSONALCLOUD_BIND_ADDRESS to a LAN interface IP for direct peer access."
fi
if [[ -n "${PERSONALCLOUD_BIND_ADDRESS:-}" ]] \
   && ! python3 - "$PERSONALCLOUD_BIND_ADDRESS" <<'PY'
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
then
  echo "PERSONALCLOUD_BIND_ADDRESS must be a literal IPv4 or IPv6 address." >&2
  exit 2
fi

if [[ -n "${PERSONALCLOUD_BIND_ADDRESS:-}" ]] \
   && [[ -z "${PERSONALCLOUD_TLS_TRUSTSTORE:-}" ]]; then
  echo "WARNING: no Android peer truststore is configured. Incoming TLS can work, but outbound desktop-to-Android HTTPS will not trust the Android peer CA." >&2
  echo "Expected by default: $TRUSTSTORE_DIR/desktop-truststore.p12" >&2
fi

exec ./run.sh
