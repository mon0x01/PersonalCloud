#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT_A="${PERSONALCLOUD_BROWSER_PORT_A:-19877}"
PORT_B="${PERSONALCLOUD_BROWSER_PORT_B:-19878}"
TMP="$(mktemp -d)"
PID_A=""
PID_B=""
cleanup() {
  for pid in "$PID_A" "$PID_B"; do [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true; done
  sleep 1
  for pid in "$PID_A" "$PID_B"; do
    [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

command -v python3 >/dev/null || { echo 'python3 is required.' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
python3 -c 'import playwright' 2>/dev/null || {
  echo 'Python Playwright is required for browser tests.' >&2
  echo 'Install with: python3 -m pip install --user playwright && python3 -m playwright install chromium' >&2
  exit 1
}
"$ROOT/build.sh"
mkdir -p "$TMP/data-a" "$TMP/data-b" "$TMP/storage-a" "$TMP/storage-b"
printf 'Browser test content from owner node\n' > "$TMP/storage-a/hello.txt"
printf 'Disposable modify test\n' > "$TMP/storage-a/modify-me.txt"
mkdir -p "$TMP/storage-a/shared-docs/nested"
printf 'folder shared content\n' > "$TMP/storage-a/shared-docs/nested/brief.txt"
printf 'Peer B local file\n' > "$TMP/storage-b/from-b.txt"
PERSONALCLOUD_NAME=Browser-A PERSONALCLOUD_PORT="$PORT_A" PERSONALCLOUD_DATA_DIR="$TMP/data-a" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-a" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/a.log" 2>&1 & PID_A=$!
PERSONALCLOUD_NAME=Browser-B PERSONALCLOUD_PORT="$PORT_B" PERSONALCLOUD_DATA_DIR="$TMP/data-b" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-b" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/b.log" 2>&1 & PID_B=$!
READY=0
for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:$PORT_A/node/info" >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$PORT_B/node/info" >/dev/null 2>&1; then READY=1; break; fi
  sleep 0.25
done
if [[ "$READY" != "1" ]]; then cat "$TMP/a.log" "$TMP/b.log" >&2; echo 'Test nodes failed to start. Check port availability.' >&2; exit 1; fi
export PC_TEST_ROOT="$TMP"
export PC_PASS_A="$(sed -n 's/^First-run password: //p' "$TMP/a.log")"
export PC_PASS_B="$(sed -n 's/^First-run password: //p' "$TMP/b.log")"
export PC_BASE_A="http://127.0.0.1:$PORT_A"
export PC_BASE_B="http://127.0.0.1:$PORT_B"
[[ -n "$PC_PASS_A" && -n "$PC_PASS_B" ]] || { echo 'Could not read generated test credentials.' >&2; exit 1; }
python3 "$ROOT/scripts/browser_test.py"
