#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
PORT_A=19787
PORT_B=19788
PID_A=""
PID_B=""
cleanup() {
  [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null || true
  [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/data-a" "$TMP/data-b" "$TMP/storage-a" "$TMP/storage-b"
printf 'PersonalCloud direct-transfer smoke test\n' > "$TMP/storage-a/sample.txt"
printf 'outside root\n' > "$TMP/outside.txt"
ln -s "$TMP/outside.txt" "$TMP/storage-a/escape-link.txt"
PERSONALCLOUD_NAME=Smoke-A PERSONALCLOUD_PORT=$PORT_A PERSONALCLOUD_DATA_DIR="$TMP/data-a" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-a" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/a.log" 2>&1 & PID_A=$!
PERSONALCLOUD_NAME=Smoke-B PERSONALCLOUD_PORT=$PORT_B PERSONALCLOUD_DATA_DIR="$TMP/data-b" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-b" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/b.log" 2>&1 & PID_B=$!

for i in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$PORT_A/node/info" >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$PORT_B/node/info" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
PASS_A=$(cat "$TMP/data-a/admin-password.txt")
PASS_B=$(cat "$TMP/data-b/admin-password.txt")
NODE_A=$(cat "$TMP/data-a/node-id.txt")
NODE_B=$(cat "$TMP/data-b/node-id.txt")

INVITE=$(curl -fsS -u "admin:$PASS_A" -X POST "http://127.0.0.1:$PORT_A/api/invites")
CODE=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' <<< "$INVITE")
curl -fsS -u "admin:$PASS_B" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "baseUrl=http://127.0.0.1:$PORT_A" --data-urlencode "code=$CODE" \
  "http://127.0.0.1:$PORT_B/api/peers" >/dev/null
REPLAY_STATUS=$(curl -sS -o "$TMP/replay.json" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "code=$CODE" \
  --data-urlencode "nodeId=$NODE_B" --data-urlencode 'nodeName=Replay' \
  "http://127.0.0.1:$PORT_A/node/pair")
[[ "$REPLAY_STATUS" == "400" ]]
INVALID_TOKEN_STATUS=$(curl -sS -o "$TMP/invalid-token.json" -w '%{http_code}' \
  -H 'Authorization: Bearer not-a-valid-token' "http://127.0.0.1:$PORT_A/node/shares")
[[ "$INVALID_TOKEN_STATUS" == "401" ]]
CROSS_ORIGIN_STATUS=$(curl -sS -o "$TMP/cross-origin.json" -w '%{http_code}' -u "admin:$PASS_A" \
  -H 'Origin: https://untrusted.example' -X POST "http://127.0.0.1:$PORT_A/api/invites")
[[ "$CROSS_ORIGIN_STATUS" == "403" ]]
curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/" | grep -q 'PersonalCloud'
curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/app.js" | grep -q 'refreshAll'

curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=sample.txt' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants" >/dev/null
REMOTE=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-shares?peerId=$NODE_A")
SHARE_ID=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["shares"][0]["shareId"])' <<< "$REMOTE")
curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-download/$NODE_A/$SHARE_ID" -o "$TMP/downloaded.txt"
cmp "$TMP/storage-a/sample.txt" "$TMP/downloaded.txt"

DELETE_STATUS=$(curl -sS -o "$TMP/delete.json" -w '%{http_code}' -u "admin:$PASS_B" -X DELETE \
  "http://127.0.0.1:$PORT_B/api/remote-shares/$NODE_A/$SHARE_ID")
[[ "$DELETE_STATUS" == "403" ]]

TRAVERSAL_STATUS=$(curl -sS -o "$TMP/traversal.json" -w '%{http_code}' -u "admin:$PASS_A" -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "peerId=$NODE_B" \
  --data-urlencode 'path=../outside.txt' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants")
[[ "$TRAVERSAL_STATUS" == "400" ]]
SYMLINK_STATUS=$(curl -sS -o "$TMP/symlink.json" -w '%{http_code}' -u "admin:$PASS_A" -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "peerId=$NODE_B" \
  --data-urlencode 'path=escape-link.txt' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants")
[[ "$SYMLINK_STATUS" == "400" ]]

# Replace the VIEW grant with MODIFY, then prove a remote delete removes the original.
curl -fsS -u "admin:$PASS_A" -X DELETE "http://127.0.0.1:$PORT_A/api/grants/$SHARE_ID" >/dev/null
MODIFY=$(curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=sample.txt' --data-urlencode 'permission=MODIFY' \
  "http://127.0.0.1:$PORT_A/api/grants")
MODIFY_ID=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])' <<< "$MODIFY")
curl -fsS -u "admin:$PASS_B" -X DELETE "http://127.0.0.1:$PORT_B/api/remote-shares/$NODE_A/$MODIFY_ID" >/dev/null
[[ ! -e "$TMP/storage-a/sample.txt" ]]
# Removing an outgoing pairing must also revoke the matching trust record on the remote node.
curl -fsS -u "admin:$PASS_B" -X DELETE "http://127.0.0.1:$PORT_B/api/peers/$NODE_A?direction=OUTGOING" >/dev/null
PEER_COUNT=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/peers" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["peers"]))')
[[ "$PEER_COUNT" == "0" ]]

UNAUTH_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_A/api/files")
[[ "$UNAUTH_STATUS" == "401" ]]

echo "PASS: pairing, per-peer grant, remote listing, streamed download, VIEW delete denial, path traversal and symlink rejection, MODIFY delete, remote pairing revocation, cross-origin mutation rejection, single-use pairing codes, invalid-token rejection, and admin authentication."
