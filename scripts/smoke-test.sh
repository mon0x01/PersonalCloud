#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
PORT_A=19787
PORT_B=19788
PID_A=""
PID_B=""
PID_C=""
PID_D=""
PID_E=""
PID_F=""
PID_G=""
PID_H=""
cleanup() {
  local pid
  for pid in "$PID_A" "$PID_B" "$PID_C" "$PID_D" "$PID_E" "$PID_F" "$PID_G" "$PID_H"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  # Give shutdown hooks time to stop HttpServer and WatchService cleanly, then
  # force-stop any test process that failed to exit so CI never hangs at teardown.
  sleep 1
  for pid in "$PID_A" "$PID_B" "$PID_C" "$PID_D" "$PID_E" "$PID_F" "$PID_G" "$PID_H"; do
    [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP"
  echo "Smoke-test teardown complete." >&2
}
trap cleanup EXIT

mkdir -p "$TMP/data-a" "$TMP/data-b" "$TMP/storage-a" "$TMP/storage-b" "$TMP/outside-dir"
printf 'PersonalCloud direct-transfer smoke test\n' > "$TMP/storage-a/sample.txt"
printf 'outside root\n' > "$TMP/outside.txt"
ln -s "$TMP/outside.txt" "$TMP/storage-a/escape-link.txt"
ln -s "$TMP/outside-dir" "$TMP/storage-a/escape-dir"
printf 'unfinished upload' > "$TMP/storage-a/.personalcloud-upload-abandoned.tmp"
PERSONALCLOUD_NAME=Smoke-A PERSONALCLOUD_PORT=$PORT_A PERSONALCLOUD_DATA_DIR="$TMP/data-a" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-a" PERSONALCLOUD_MAX_UPLOAD_BYTES=1024 \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/a.log" 2>&1 & PID_A=$!
PERSONALCLOUD_NAME=Smoke-B PERSONALCLOUD_PORT=$PORT_B PERSONALCLOUD_DATA_DIR="$TMP/data-b" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-b" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/b.log" 2>&1 & PID_B=$!

for i in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$PORT_A/node/info" >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$PORT_B/node/info" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
PASS_A=$(sed -n 's/^First-run password: //p' "$TMP/a.log")
PASS_B=$(sed -n 's/^First-run password: //p' "$TMP/b.log")
NODE_A=$(cat "$TMP/data-a/node-id.txt")
NODE_B=$(cat "$TMP/data-b/node-id.txt")

INVITE=$(curl -fsS -u "admin:$PASS_A" -X POST "http://127.0.0.1:$PORT_A/api/invites")
CODE=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' <<< "$INVITE")
curl -fsS -u "admin:$PASS_B" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "baseUrl=http://127.0.0.1:$PORT_A" --data-urlencode "code=$CODE" \
  "http://127.0.0.1:$PORT_B/api/peers" >/dev/null
grep -qF 'accessToken=v1\:' "$TMP/data-b/state.properties"
HEALTH=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/peers/health")
grep -q 'ONLINE' <<< "$HEALTH"
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
curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/app.js" | grep -q 'renderLocalFiles'
LOCAL_FILES_JSON=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/files")
! grep -q 'abandoned.tmp' <<< "$LOCAL_FILES_JSON"

# Folder creation and bounded binary uploads.
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'path=uploads' "http://127.0.0.1:$PORT_A/api/folders" >/dev/null
FOLDER_LIST=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/folders")
grep -q 'uploads' <<< "$FOLDER_LIST"
printf 'uploaded payload\n' > "$TMP/upload.txt"
curl -fsS -u "admin:$PASS_A" -X POST --data-binary "@$TMP/upload.txt" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=uploads%2Ftransfer.txt" >/dev/null
cmp "$TMP/upload.txt" "$TMP/storage-a/uploads/transfer.txt"

# Directory-preserving upload creates safe parent directories, while previews remain plain text.
printf 'nested folder upload\n' > "$TMP/nested-upload.txt"
curl -fsS -u "admin:$PASS_A" -X POST --data-binary "@$TMP/nested-upload.txt" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=browser-folder%2Fsub%2Fnested.txt&createParents=true" >/dev/null
cmp "$TMP/nested-upload.txt" "$TMP/storage-a/browser-folder/sub/nested.txt"
FOLDER_LIST=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/folders")
grep -q 'browser-folder/sub' <<< "$FOLDER_LIST"
curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/files/preview?path=sample.txt" > "$TMP/preview.txt"
cmp "$TMP/storage-a/sample.txt" "$TMP/preview.txt"
dd if=/dev/zero of="$TMP/storage-a/binary.bin" bs=64 count=1 status=none
PREVIEW_BINARY=$(curl -sS -o "$TMP/preview-binary.json" -w '%{http_code}' -u "admin:$PASS_A" \
  "http://127.0.0.1:$PORT_A/api/files/preview?path=binary.bin")
[[ "$PREVIEW_BINARY" == "400" ]]

# Snapshot, deletion, integrity verification, and restore to a new destination.
printf 'version history content\n' > "$TMP/storage-a/versioned.txt"
cp "$TMP/storage-a/versioned.txt" "$TMP/versioned.expected"
VERSION=$(curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'path=versioned.txt' "http://127.0.0.1:$PORT_A/api/versions")
VERSION_ID=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])' <<< "$VERSION")
curl -fsS -u "admin:$PASS_A" -X DELETE "http://127.0.0.1:$PORT_A/api/files?path=versioned.txt" >/dev/null
[[ ! -e "$TMP/storage-a/versioned.txt" ]]
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'destination=versioned-restored.txt' \
  "http://127.0.0.1:$PORT_A/api/versions/$VERSION_ID/restore" >/dev/null
cmp "$TMP/versioned.expected" "$TMP/storage-a/versioned-restored.txt"
AUTO_VERSION=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/versions?path=versioned.txt")
[[ $(python3 -c 'import json,sys;print(len(json.load(sys.stdin)["versions"]))' <<< "$AUTO_VERSION") -ge 2 ]]

# Move/rename keeps a grant attached to the new path.
printf 'move with grant\n' > "$TMP/storage-a/move-me.txt"
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=move-me.txt' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants" >/dev/null
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'source=move-me.txt' --data-urlencode 'destination=moved-to.txt' \
  "http://127.0.0.1:$PORT_A/api/files/move" >/dev/null
MOVED_REMOTE=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-shares?peerId=$NODE_A")
grep -q 'moved-to.txt' <<< "$MOVED_REMOTE"
mkdir -p "$TMP/storage-a/folder-move-source"
printf 'folder move keeps child access\n' > "$TMP/storage-a/folder-move-source/child.txt"
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=folder-move-source' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants" >/dev/null
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'source=folder-move-source' --data-urlencode 'destination=folder-moved' \
  "http://127.0.0.1:$PORT_A/api/files/move" >/dev/null
FOLDER_MOVED_REMOTE=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-shares?peerId=$NODE_A")
grep -q 'folder-moved/child.txt' <<< "$FOLDER_MOVED_REMOTE"

# Nested folder shares expose descendants individually and never expose outside paths.
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'path=shared-folder' "http://127.0.0.1:$PORT_A/api/folders" >/dev/null
curl -fsS -u "admin:$PASS_A" -X POST --data-binary "@$TMP/upload.txt" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=shared-folder%2Finside.txt" >/dev/null
printf 'archive path safety\n' > "$TMP/storage-a/shared-folder/..\\evil.txt"
FOLDER_GRANT=$(curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=shared-folder' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants")
grep -q 'FOLDER' <<< "$FOLDER_GRANT"
FOLDER_REMOTE=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-shares?peerId=$NODE_A")
FOLDER_SHARE_ID=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["shareId"] for x in d["shares"] if x.get("path")=="shared-folder/inside.txt"))' <<< "$FOLDER_REMOTE")
curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-download/$NODE_A/$FOLDER_SHARE_ID" -o "$TMP/folder-download.txt"
cmp "$TMP/upload.txt" "$TMP/folder-download.txt"
FOLDER_GRANT_ID=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])' <<< "$FOLDER_GRANT")
curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-folder-download/$NODE_A/$FOLDER_GRANT_ID" -o "$TMP/shared-folder.zip"
unzip -p "$TMP/shared-folder.zip" inside.txt > "$TMP/folder-archive-file.txt"
cmp "$TMP/upload.txt" "$TMP/folder-archive-file.txt"
unzip -Z1 "$TMP/shared-folder.zip" | grep -Fxq '.._evil.txt'
! unzip -Z1 "$TMP/shared-folder.zip" | grep -Eq '(^/|(^|/)\.\.(/|$)|\\)'
DUPLICATE_STATUS=$(curl -sS -o "$TMP/duplicate.json" -w '%{http_code}' -u "admin:$PASS_A" -X POST --data-binary "@$TMP/upload.txt" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=uploads%2Ftransfer.txt")
[[ "$DUPLICATE_STATUS" == "400" ]]
TRAVERSAL_UPLOAD=$(curl -sS -o "$TMP/upload-traversal.json" -w '%{http_code}' -u "admin:$PASS_A" -X POST --data-binary "@$TMP/upload.txt" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=..%2Foutside.txt")
[[ "$TRAVERSAL_UPLOAD" == "400" ]]
SYMLINK_UPLOAD=$(curl -sS -o "$TMP/upload-symlink.json" -w '%{http_code}' -u "admin:$PASS_A" -X POST --data-binary "@$TMP/upload.txt" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=escape-dir%2Fescaped.txt")
[[ "$SYMLINK_UPLOAD" == "400" ]]
dd if=/dev/zero of="$TMP/large.bin" bs=2048 count=1 status=none
LARGE_UPLOAD=$(curl -sS -o "$TMP/upload-large.json" -w '%{http_code}' -u "admin:$PASS_A" -X POST --data-binary "@$TMP/large.bin" \
  "http://127.0.0.1:$PORT_A/api/files/upload?path=uploads%2Ftoo-large.bin")
[[ "$LARGE_UPLOAD" == "400" ]]
ACTIVITY=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/activity")
grep -q 'FILE_UPLOADED' <<< "$ACTIVITY"

curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=sample.txt' --data-urlencode 'permission=VIEW' \
  "http://127.0.0.1:$PORT_A/api/grants" >/dev/null
REMOTE=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-shares?peerId=$NODE_A")
SHARE_ID=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["shareId"] for x in d["shares"] if x.get("path")=="sample.txt"))' <<< "$REMOTE")
curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-download/$NODE_A/$SHARE_ID" -o "$TMP/downloaded.txt"
cmp "$TMP/storage-a/sample.txt" "$TMP/downloaded.txt"
EXPECTED_HASH=$(sha256sum "$TMP/storage-a/sample.txt" | awk '{print $1}')
curl -fsS -u "admin:$PASS_A" -D "$TMP/local-hash.headers" -o /dev/null \
  "http://127.0.0.1:$PORT_A/api/files/download?path=sample.txt"
grep -qi "X-Content-SHA256: $EXPECTED_HASH" "$TMP/local-hash.headers"
curl -fsS -u "admin:$PASS_B" -D "$TMP/remote-hash.headers" -o /dev/null \
  "http://127.0.0.1:$PORT_B/api/remote-download/$NODE_A/$SHARE_ID"
grep -qi "X-Content-SHA256: $EXPECTED_HASH" "$TMP/remote-hash.headers"
# Byte ranges work end-to-end through both nodes, so interrupted clients can resume.
curl -fsS -u "admin:$PASS_B" -H 'Range: bytes=0-3' -D "$TMP/range.headers" \
  "http://127.0.0.1:$PORT_B/api/remote-download/$NODE_A/$SHARE_ID" -o "$TMP/range.bin"
[[ "$(cat "$TMP/range.bin")" == "Pers" ]]
grep -qi 'Content-Range: bytes 0-3/41' "$TMP/range.headers"
RANGE_416=$(curl -sS -o "$TMP/range416" -w '%{http_code}' -u "admin:$PASS_A" -H 'Range: bytes=999-1000' \
  "http://127.0.0.1:$PORT_A/api/files/download?path=sample.txt")
[[ "$RANGE_416" == "416" ]]

DELETE_STATUS=$(curl -sS -o "$TMP/delete.json" -w '%{http_code}' -u "admin:$PASS_B" -X DELETE \
  "http://127.0.0.1:$PORT_B/api/remote-shares/$NODE_A/$SHARE_ID")
[[ "$DELETE_STATUS" == "403" ]]

# MODIFY deletion creates a recoverable owner-local version before removing the original.
printf 'owner recovery after remote delete\n' > "$TMP/storage-a/remote-delete.txt"
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "peerId=$NODE_B" --data-urlencode 'path=remote-delete.txt' --data-urlencode 'permission=MODIFY' \
  "http://127.0.0.1:$PORT_A/api/grants" >/dev/null
REMOTE_AFTER_MODIFY=$(curl -fsS -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/remote-shares?peerId=$NODE_A")
MODIFY_SHARE_ID=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["shareId"] for x in d["shares"] if x.get("path")=="remote-delete.txt"))' <<< "$REMOTE_AFTER_MODIFY")
curl -fsS -u "admin:$PASS_B" -X DELETE "http://127.0.0.1:$PORT_B/api/remote-shares/$NODE_A/$MODIFY_SHARE_ID" >/dev/null
[[ ! -e "$TMP/storage-a/remote-delete.txt" ]]
REMOTE_VERSION=$(curl -fsS -u "admin:$PASS_A" "http://127.0.0.1:$PORT_A/api/versions?path=remote-delete.txt")
REMOTE_VERSION_ID=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["versions"][0]["id"])' <<< "$REMOTE_VERSION")
curl -fsS -u "admin:$PASS_A" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'destination=remote-delete-recovered.txt' \
  "http://127.0.0.1:$PORT_A/api/versions/$REMOTE_VERSION_ID/restore" >/dev/null
[[ -f "$TMP/storage-a/remote-delete-recovered.txt" ]]
grep -q 'owner recovery after remote delete' "$TMP/storage-a/remote-delete-recovered.txt"

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

# Password rotation preserves access while only the salted hash remains on disk.
NEW_PASSWORD='A-strong-new-password-2026!'
curl -fsS -u "admin:$PASS_B" -X PUT -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "currentPassword=$PASS_B" --data-urlencode "newPassword=$NEW_PASSWORD" \
  "http://127.0.0.1:$PORT_B/api/admin/password" >/dev/null
OLD_PASSWORD_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -u "admin:$PASS_B" "http://127.0.0.1:$PORT_B/api/files")
[[ "$OLD_PASSWORD_STATUS" == "401" ]]
curl -fsS -u "admin:$NEW_PASSWORD" "http://127.0.0.1:$PORT_B/api/files" >/dev/null
[[ -f "$TMP/data-b/admin-password.hash" && ! -f "$TMP/data-b/admin-password.txt" ]]

UNAUTH_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_A/api/files")
[[ "$UNAUTH_STATUS" == "401" ]]

# Administrator lockout: six invalid credential attempts trigger a temporary 429 response.
for i in $(seq 1 6); do curl -sS -o /dev/null -u 'admin:wrong-password' "http://127.0.0.1:$PORT_B/api/files" || true; done
LOCKOUT_STATUS=$(curl -sS -o "$TMP/lockout.json" -w '%{http_code}' -u 'admin:wrong-password' "http://127.0.0.1:$PORT_B/api/files")
[[ "$LOCKOUT_STATUS" == "429" ]]

# A non-loopback plaintext listener must fail closed.
set +e
PERSONALCLOUD_BIND_ADDRESS=0.0.0.0 PERSONALCLOUD_PORT=19789 PERSONALCLOUD_DATA_DIR="$TMP/data-no-tls" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-no-tls" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/e.log" 2>&1
BIND_EXIT=$?
set -e
[[ "$BIND_EXIT" != "0" ]]
grep -q 'blocked without TLS' "$TMP/e.log"

# Node state and user-owned file storage must never overlap.
mkdir -p "$TMP/overlap-root"
set +e
PERSONALCLOUD_PORT=19795 PERSONALCLOUD_DATA_DIR="$TMP/overlap-root/data" PERSONALCLOUD_STORAGE_ROOT="$TMP/overlap-root" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/overlap.log" 2>&1
OVERLAP_EXIT=$?
set -e
[[ "$OVERLAP_EXIT" != "0" ]]
grep -q 'must be separate, non-overlapping directories' "$TMP/overlap.log"

# Pairing endpoint throttles repeated failures independently of admin login throttling.
PERSONALCLOUD_NAME=Pair-Throttle PERSONALCLOUD_PORT=19792 PERSONALCLOUD_DATA_DIR="$TMP/data-f" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-f" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/f.log" 2>&1 & PID_F=$!
for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:19792/node/info" >/dev/null 2>&1 && break; sleep 0.25; done
PASS_F=$(sed -n 's/^First-run password: //p' "$TMP/f.log")
GOOD_INVITE=$(curl -fsS -u "admin:$PASS_F" -X POST "http://127.0.0.1:19792/api/invites")
GOOD_CODE=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' <<< "$GOOD_INVITE")
for i in $(seq 1 8); do
  curl -sS -o /dev/null -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'code=0000000000000000' --data-urlencode 'nodeId=00000000-0000-0000-0000-000000000001' \
    --data-urlencode 'nodeName=Invalid' "http://127.0.0.1:19792/node/pair" || true
done
PAIR_LOCKOUT=$(curl -sS -o "$TMP/pair-lockout.json" -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "code=$GOOD_CODE" --data-urlencode 'nodeId=00000000-0000-0000-0000-000000000002' \
  --data-urlencode 'nodeName=Valid' "http://127.0.0.1:19792/node/pair")
[[ "$PAIR_LOCKOUT" == "429" ]]

# TLS server + pinned test truststore + authenticated node-to-node pairing/health.
keytool -genkeypair -alias personalcloud -keyalg RSA -keysize 2048 -validity 7 -dname 'CN=localhost' \
  -ext 'SAN=dns:localhost,ip:127.0.0.1' -storetype PKCS12 -keystore "$TMP/tls.p12" \
  -storepass changeit -keypass changeit -noprompt >/dev/null 2>&1
keytool -exportcert -alias personalcloud -keystore "$TMP/tls.p12" -storepass changeit -rfc -file "$TMP/tls.crt" >/dev/null 2>&1
keytool -importcert -alias personalcloud -file "$TMP/tls.crt" -storetype PKCS12 -keystore "$TMP/trust.p12" \
  -storepass changeit -noprompt >/dev/null 2>&1
PERSONALCLOUD_NAME=TLS-Node PERSONALCLOUD_PORT=19789 PERSONALCLOUD_DATA_DIR="$TMP/data-c" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-c" \
  PERSONALCLOUD_TLS_KEYSTORE="$TMP/tls.p12" PERSONALCLOUD_TLS_KEYSTORE_PASSWORD=changeit \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/c.log" 2>&1 & PID_C=$!
PERSONALCLOUD_NAME=TLS-Client PERSONALCLOUD_PORT=19790 PERSONALCLOUD_DATA_DIR="$TMP/data-d" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-d" \
  PERSONALCLOUD_TLS_TRUSTSTORE="$TMP/trust.p12" PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD=changeit \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/d.log" 2>&1 & PID_D=$!
for i in $(seq 1 40); do
  if curl -kfsS "https://127.0.0.1:19789/node/info" >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:19790/node/info" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
PASS_C=$(sed -n 's/^First-run password: //p' "$TMP/c.log")
PASS_D=$(sed -n 's/^First-run password: //p' "$TMP/d.log")
TLS_INVITE=$(curl -kfsS -u "admin:$PASS_C" -X POST "https://127.0.0.1:19789/api/invites")
TLS_CODE=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' <<< "$TLS_INVITE")
curl -fsS -u "admin:$PASS_D" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'baseUrl=https://127.0.0.1:19789' --data-urlencode "code=$TLS_CODE" \
  "http://127.0.0.1:19790/api/peers" >/dev/null
TLS_HEALTH=$(curl -fsS -u "admin:$PASS_D" "http://127.0.0.1:19790/api/peers/health")
grep -q 'ONLINE' <<< "$TLS_HEALTH"
curl -kfsS -D - -o /dev/null "https://127.0.0.1:19789/node/info" | grep -qi 'strict-transport-security'

# State corruption recovers from the last atomic-write backup.
PERSONALCLOUD_NAME=Recovery PERSONALCLOUD_PORT=19791 PERSONALCLOUD_DATA_DIR="$TMP/data-e" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-e" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/e-first.log" 2>&1 & PID_E=$!
for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:19791/node/info" >/dev/null 2>&1 && break; sleep 0.25; done
PASS_E=$(sed -n 's/^First-run password: //p' "$TMP/e-first.log")
curl -fsS -u "admin:$PASS_E" -X POST "http://127.0.0.1:19791/api/invites" >/dev/null
curl -fsS -u "admin:$PASS_E" -X POST "http://127.0.0.1:19791/api/invites" >/dev/null
kill "$PID_E"; wait "$PID_E" 2>/dev/null || true; PID_E=""
python3 -c 'from pathlib import Path; Path("'$TMP'/data-e/state.properties").write_bytes(b"broken=\\u00XZ\\n")'
PERSONALCLOUD_NAME=Recovery PERSONALCLOUD_PORT=19791 PERSONALCLOUD_DATA_DIR="$TMP/data-e" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-e" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/e-recovery.log" 2>&1 & PID_E=$!
for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:19791/node/info" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "http://127.0.0.1:19791/node/info" >/dev/null
grep -q 'invite' "$TMP/data-e/state.properties"

# Migrate the old plaintext admin-password.txt format to a PBKDF2 hash.
mkdir -p "$TMP/data-g" "$TMP/storage-g"
printf 'Legacy-Test-Password-2026!' > "$TMP/data-g/admin-password.txt"
PERSONALCLOUD_NAME=Legacy PERSONALCLOUD_PORT=19793 PERSONALCLOUD_DATA_DIR="$TMP/data-g" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-g" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/g.log" 2>&1 & PID_G=$!
for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:19793/node/info" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS -u 'admin:Legacy-Test-Password-2026!' "http://127.0.0.1:19793/api/files" >/dev/null
[[ -f "$TMP/data-g/admin-password.hash" && ! -f "$TMP/data-g/admin-password.txt" ]]


# TOTP MFA enrollment, browser-session enforcement, replay prevention, recovery, and disable.
PERSONALCLOUD_NAME=MFA-Node PERSONALCLOUD_PORT=19794 PERSONALCLOUD_DATA_DIR="$TMP/data-h" PERSONALCLOUD_STORAGE_ROOT="$TMP/storage-h" \
  java --add-modules jdk.httpserver -jar "$ROOT/build/personalcloud.jar" >"$TMP/h.log" 2>&1 & PID_H=$!
for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:19794/node/info" >/dev/null 2>&1 && break; sleep 0.25; done
PASS_H=$(sed -n 's/^First-run password: //p' "$TMP/h.log")
[[ -n "$PASS_H" ]]
AUTH_STATUS=$(curl -fsS "http://127.0.0.1:19794/api/auth/status")
grep -q '"authenticated":false' <<< "$AUTH_STATUS"
SETUP=$(curl -fsS -u "admin:$PASS_H" -X POST "http://127.0.0.1:19794/api/mfa/setup")
MFA_SECRET=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["secret"])' <<< "$SETUP")
MFA_ENABLE_COUNTER=$(( $(date +%s) / 30 ))
MFA_ENABLE_CODE=$(python3 - "$MFA_SECRET" <<'PYTOTPE'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1]
key = base64.b32decode(secret + '=' * ((8-len(secret)%8)%8))
counter = int(time.time()) // 30
raw = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
offset = raw[-1] & 15
value = struct.unpack('>I', raw[offset:offset+4])[0] & 0x7fffffff
print(f'{value % 1000000:06d}')
PYTOTPE
)
ENABLE=$(curl -fsS -u "admin:$PASS_H" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "code=$MFA_ENABLE_CODE" "http://127.0.0.1:19794/api/mfa/enable")
RECOVERY=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["recoveryCodes"][0])' <<< "$ENABLE")
RECOVERY_FOR_DISABLE=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["recoveryCodes"][1])' <<< "$ENABLE")
[[ $(python3 -c 'import json,sys;print(len(json.load(sys.stdin)["recoveryCodes"]))' <<< "$ENABLE") == "10" ]]
BASIC_AFTER_MFA=$(curl -sS -o /dev/null -w '%{http_code}' -u "admin:$PASS_H" "http://127.0.0.1:19794/api/files")
[[ "$BASIC_AFTER_MFA" == "401" ]]
NO_OTP=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin' --data-urlencode "password=$PASS_H" \
  "http://127.0.0.1:19794/api/auth/login")
[[ "$NO_OTP" == "401" ]]
REPLAY_ENROLLMENT=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin' --data-urlencode "password=$PASS_H" --data-urlencode "code=$MFA_ENABLE_CODE" \
  "http://127.0.0.1:19794/api/auth/login")
[[ "$REPLAY_ENROLLMENT" == "401" ]]
# An unused recovery code should work exactly once.
curl -fsS -c "$TMP/h.cookies" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin' --data-urlencode "password=$PASS_H" --data-urlencode "code=$RECOVERY" \
  "http://127.0.0.1:19794/api/auth/login" >/dev/null
MFA_STATUS=$(curl -fsS -b "$TMP/h.cookies" "http://127.0.0.1:19794/api/mfa/status")
grep -q '"remainingRecoveryCodes":9' <<< "$MFA_STATUS"
RECOVERY_REPLAY=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin' --data-urlencode "password=$PASS_H" --data-urlencode "code=$RECOVERY" \
  "http://127.0.0.1:19794/api/auth/login")
[[ "$RECOVERY_REPLAY" == "401" ]]
# Disable MFA with a second, unused recovery code; the endpoint also requires the admin password.
curl -fsS -b "$TMP/h.cookies" -c "$TMP/h.cookies" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "password=$PASS_H" --data-urlencode "code=$RECOVERY_FOR_DISABLE" \
  "http://127.0.0.1:19794/api/mfa/disable" >/dev/null
MFA_DISABLED=$(curl -fsS -b "$TMP/h.cookies" "http://127.0.0.1:19794/api/mfa/status")
grep -q '"enabled":false' <<< "$MFA_DISABLED"
# Session logout invalidates the cookie; Basic auth is available again after MFA is disabled.
curl -fsS -b "$TMP/h.cookies" -X POST "http://127.0.0.1:19794/api/auth/logout" >/dev/null
LOGGED_OUT=$(curl -fsS "http://127.0.0.1:19794/api/auth/status")
grep -q '"authenticated":false' <<< "$LOGGED_OUT"
curl -fsS -u "admin:$PASS_H" "http://127.0.0.1:19794/api/files" >/dev/null

echo "PASS: peer pairing and permissions; transport TLS; token encryption; file/folder sharing; directory-preserving uploads; bounded upload/path/symlink controls; plain-text preview; file move with grant preservation; local/remote delete recovery snapshots and restore; ZIP sanitization; SHA-256/range downloads; activity audit; login/pairing throttling; state backup recovery; legacy password migration; TOTP MFA; browser sessions; OTP/recovery-code replay rejection."
