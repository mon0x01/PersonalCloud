#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# This contract suite invokes the built CLI for TLS diagnostics. Keep it safe to
# run from a fresh checkout instead of relying on a jar left by another test job.
CORE_JAR="$ROOT/build/personalcloud.jar"
NEEDS_CORE_BUILD=0
if [[ ! -s "$CORE_JAR" || "$ROOT/build.sh" -nt "$CORE_JAR" ]]; then
  NEEDS_CORE_BUILD=1
else
  while IFS= read -r -d '' source_file; do
    if [[ "$source_file" -nt "$CORE_JAR" ]]; then
      NEEDS_CORE_BUILD=1
      break
    fi
  done < <(find src/main -type f -print0)
fi
if (( NEEDS_CORE_BUILD )); then
  echo "Building fresh desktop core for Linux integration contracts..."
  ./build.sh
fi

bash -n integrations/linux/personalcloudctl integrations/linux/personalcloud-mount \
  integrations/linux/personalcloud-dolphin-reference integrations/linux/personalcloud-dolphin-place-file \
  integrations/linux/personalcloud-dolphin-share-file integrations/linux/install-dolphin-actions.sh \
  integrations/linux/build-fuse.sh scripts/create-desktop-peer-tls.sh scripts/test-desktop-peer-tls-provisioning.sh \
  scripts/android-peer-test.sh scripts/android-desktop-interop-test.sh scripts/test-all.sh \
  scripts/start-node.sh scripts/test-start-node-tls-routing.sh

grep -Fq 'bash "$ROOT/scripts/android-desktop-interop-test.sh"' scripts/android-peer-test.sh
grep -q 'default_permissions,nodev,nosuid,noexec' integrations/linux/fuse/src/main/java/dev/personalcloud/linux/fuse/FuseMountMain.java
grep -q 'Mount point must be empty' integrations/linux/fuse/src/main/java/dev/personalcloud/linux/fuse/FuseMountMain.java
# Maven must use a normal dependency resolved from a project-local repository;
# the deprecated system scope makes the adapter non-reproducible downstream.
if grep -Eq '<scope>system</scope>|<systemPath>' integrations/linux/fuse/pom.xml; then
  echo "FAIL: FUSE Maven module uses a project-local system-scoped dependency." >&2
  exit 1
fi
grep -Fq 'maven.repo.local="$MAVEN_REPO"' integrations/linux/build-fuse.sh
grep -Fq 'maven-install-plugin:3.1.3:install-file' integrations/linux/build-fuse.sh
grep -Fq 'ServicesResourceTransformer' integrations/linux/fuse/pom.xml
grep -Fq 'META-INF/MANIFEST.MF' integrations/linux/fuse/pom.xml
FUSE=integrations/linux/fuse/src/main/java/dev/personalcloud/linux/fuse/PersonalCloudFuse.java
grep -Fq 'if ((mask & 1) != 0 && !attributes.directory()) return -ErrorCodes.EACCES();' "$FUSE"
grep -Fq 'WritableVirtualFilesystem' "$FUSE"
grep -Fq 'public int write(' "$FUSE"
grep -Fq 'public int create(' "$FUSE"
grep -Fq 'public int mkdir(' "$FUSE"
grep -Fq 'public int unlink(' "$FUSE"
grep -Fq 'public int rmdir(' "$FUSE"
grep -Fq 'public int rename(' "$FUSE"
grep -Fq 'public int truncate(' "$FUSE"
grep -Fq 'public int ftruncate(' "$FUSE"
grep -Fq 'public int flush(' "$FUSE"
grep -Fq 'public int release(' "$FUSE"
grep -Fq 'public int utimens(' "$FUSE"
grep -Fq 'filesystem.upload(' "$FUSE"
grep -Fq 'filesystem.download(' "$FUSE"
grep -Fq 'filesystem.move(' "$FUSE"
grep -Fq 'filesystem.delete(' "$FUSE"
grep -Fq 'if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();' "$FUSE"
if grep -Eq 'int (write|create|mkdir|unlink|rmdir|rename|truncate|ftruncate)\(.*return -ErrorCodes\.EROFS\(\);' "$FUSE"; then
  echo "FAIL: FUSE writable callbacks must not be hard-coded read-only." >&2
  exit 1
fi
# The reference planes must stay read-only while eligible storage is writable.
grep -Fq 'return filesystem.isWritable(path) ? -ErrorCodes.EPERM() : -ErrorCodes.EROFS();' "$FUSE"
grep -Fq 'return filesystem.isWritable(path) ? -ErrorCodes.EOPNOTSUPP() : -ErrorCodes.EROFS();' "$FUSE"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/konsole" <<'SH'
#!/usr/bin/env bash
printf 'argc=%s\nroot=%s\nitem=%s\n' "$#" "${8:-}" "${9:-}" > "$PERSONALCLOUD_TEST_CAPTURE"
SH
chmod +x "$TMP/bin/konsole"
ITEM="$TMP/Research notes ; $(date +%s)"
PATH="$TMP/bin:$PATH" PERSONALCLOUD_TEST_CAPTURE="$TMP/args.txt" \
  integrations/linux/personalcloud-dolphin-reference "$ITEM"
grep -Fxq 'argc=9' "$TMP/args.txt"
grep -Fxq "item=$ITEM" "$TMP/args.txt"
grep -Fxq "root=$ROOT" "$TMP/args.txt"
PATH="$TMP/bin:$PATH" PERSONALCLOUD_TEST_CAPTURE="$TMP/args.txt" \
  integrations/linux/personalcloud-dolphin-place-file "$ITEM"
grep -Fxq "item=$ITEM" "$TMP/args.txt"
grep -Fxq "root=$ROOT" "$TMP/args.txt"
PATH="$TMP/bin:$PATH" PERSONALCLOUD_TEST_CAPTURE="$TMP/args.txt" \
  integrations/linux/personalcloud-dolphin-share-file "$ITEM"
grep -Fxq "item=$ITEM" "$TMP/args.txt"
grep -Fxq "root=$ROOT" "$TMP/args.txt"

touch "$TMP/ordinary-file.bin"
ln -s "$TMP/ordinary-file.bin" "$TMP/file-link.bin"
if integrations/linux/personalcloud-dolphin-share-file "$TMP/file-link.bin" >/dev/null 2>&1; then
  echo "FAIL: Dolphin share action accepted a symbolic link." >&2
  exit 1
fi

XDG_DATA_HOME="$TMP/data" ./integrations/linux/install-dolphin-actions.sh >/dev/null
MENU="$TMP/data/kio/servicemenus/personalcloud-reference.desktop"
test -s "$MENU"
grep -Fq 'MimeType=inode/directory;' "$MENU"
grep -Fq 'Add folder as PersonalCloud reference' "$MENU"
grep -Fq "Exec=\"$ROOT/integrations/linux/personalcloud-dolphin-reference\" %f" "$MENU"
SEND_MENU="$TMP/data/kio/servicemenus/personalcloud-send-file.desktop"
test -s "$SEND_MENU"
grep -Fq 'MimeType=all/allfiles;' "$SEND_MENU"
grep -Fq 'Send to a PersonalCloud device' "$SEND_MENU"
grep -Fq "Exec=\"$ROOT/integrations/linux/personalcloud-dolphin-place-file\" %f" "$SEND_MENU"
SHARE_MENU="$TMP/data/kio/servicemenus/personalcloud-share-file.desktop"
test -s "$SHARE_MENU"
grep -Fq 'MimeType=all/allfiles;' "$SHARE_MENU"
grep -Fq 'Share through PersonalCloud (no copy)' "$SHARE_MENU"
grep -Fq "Exec=\"$ROOT/integrations/linux/personalcloud-dolphin-share-file\" %f" "$SHARE_MENU"

bash scripts/test-desktop-peer-tls-provisioning.sh
bash scripts/test-start-node-tls-routing.sh

echo "PASS: Linux integration shell syntax, writable FUSE callbacks with read-only reference planes, safe Dolphin arguments, symlink rejection, desktop TLS provisioning, TLS identity/truststore routing and all service-menu installation."
