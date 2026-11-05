#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n integrations/linux/personalcloudctl integrations/linux/personalcloud-mount \
  integrations/linux/personalcloud-dolphin-reference integrations/linux/personalcloud-dolphin-place-file \
  integrations/linux/personalcloud-dolphin-share-file integrations/linux/install-dolphin-actions.sh \
  integrations/linux/build-fuse.sh scripts/create-desktop-peer-tls.sh scripts/test-desktop-peer-tls-provisioning.sh \
  scripts/android-peer-test.sh scripts/android-desktop-interop-test.sh scripts/test-all.sh \
  scripts/start-node.sh scripts/test-start-node-tls-routing.sh

grep -Fq 'bash "$ROOT/scripts/android-desktop-interop-test.sh"' scripts/android-peer-test.sh
grep -q 'ro,default_permissions,nodev,nosuid,noexec' integrations/linux/fuse/src/main/java/dev/personalcloud/linux/fuse/FuseMountMain.java
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
grep -Fq 'if ((mask & 1) != 0 && !attributes.directory()) return -ErrorCodes.EACCES();' integrations/linux/fuse/src/main/java/dev/personalcloud/linux/fuse/PersonalCloudFuse.java
for operation in write write_buf create mknod mkdir unlink rmdir rename link symlink truncate ftruncate chmod chown utimens setxattr removexattr fallocate; do
  grep -Eq "int ${operation}\\(.*return -ErrorCodes\\.EROFS\\(\\);" integrations/linux/fuse/src/main/java/dev/personalcloud/linux/fuse/PersonalCloudFuse.java || {
    echo "FAIL: FUSE mutation callback '${operation}' is not explicitly read-only." >&2
    exit 1
  }
done

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

echo "PASS: Linux integration shell syntax, read-only FUSE callbacks, safe Dolphin arguments, symlink rejection, desktop TLS provisioning, TLS identity/truststore routing and all service-menu installation."
