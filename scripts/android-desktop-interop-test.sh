#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p build
TMP="$(mktemp -d "$ROOT/build/android-desktop-interop.XXXXXX")"
cleanup() {
  # The test JVMs have exited before this trap runs. Remove only disposable test
  # credentials synchronously so installer wrappers do not inherit stray children.
  rm -rf -- "$TMP"
}
trap cleanup EXIT

DESKTOP_PASS='DesktopInterop-2026!'
ANDROID_PASS='AndroidInterop-2026!'
TRUST_PASS='AndroidTrust-2026!'

run_keytool() {
  timeout --signal=TERM --kill-after=3s 30s keytool -J-Djava.security.egd=file:/dev/urandom "$@"
}

echo "Preparing disposable TLS test identities..."
for identity in desktop android; do
  pass="$DESKTOP_PASS"
  [[ "$identity" == android ]] && pass="$ANDROID_PASS"

  run_keytool -genkeypair -alias "$identity" -keyalg RSA -keysize 2048 -validity 365 \
    -storetype PKCS12 -keystore "$TMP/$identity.p12" \
    -storepass "$pass" -keypass "$pass" \
    -dname "CN=$identity" -ext 'SAN=ip:127.0.0.1' >/dev/null 2>&1

  run_keytool -exportcert -rfc -alias "$identity" \
    -keystore "$TMP/$identity.p12" -storepass "$pass" \
    -file "$TMP/$identity.crt" >/dev/null 2>&1
done

run_keytool -importcert -noprompt -alias personalcloud-android-peer \
  -file "$TMP/android.crt" \
  -keystore "$TMP/android-truststore.p12" \
  -storetype PKCS12 -storepass "$TRUST_PASS" >/dev/null 2>&1

# Start from a clean generated output directory: stale class files can hide source/test drift.
rm -rf build/android-peer-classes
mkdir -p build/android-peer-classes

run_java() {
  local seconds="$1"
  shift
  JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-Djava.security.egd=file:/dev/urandom" \
    timeout --signal=TERM --kill-after=5s "${seconds}s" java "$@"
}

mapfile -t ANDROID_MAIN < <(
  find android-peer/peer-core/src/main/java \
    -type f -name '*.java' -print | sort
)

mapfile -t ANDROID_TEST < <(
  find android-peer/peer-core/src/test/java \
    -type f -name '*.java' ! -name 'DesktopInteropTest.java' \
    -print | sort
)

if ((${#ANDROID_MAIN[@]} == 0 || ${#ANDROID_TEST[@]} == 0)); then
  echo "FAIL: Android peer-core source or tests are missing." >&2
  exit 1
fi

echo "Compiling Android peer-core production code..."
timeout --signal=TERM --kill-after=5s 60s javac --release 17 -Xlint:all -encoding UTF-8 -d build/android-peer-classes "${ANDROID_MAIN[@]}"

echo "Compiling Java 17-compatible peer-core tests..."
timeout --signal=TERM --kill-after=5s 60s javac --release 17 --add-modules jdk.httpserver -Xlint:all -encoding UTF-8 \
  -cp "build/android-peer-classes" \
  -d build/android-peer-classes "${ANDROID_TEST[@]}"

INTEROP_TEST="integrations/android-desktop-interop/src/test/java/dev/personalcloud/android/core/DesktopInteropTest.java"

test -f "$INTEROP_TEST"

echo "Compiling desktop–Android integration test separately..."
timeout --signal=TERM --kill-after=5s 60s javac --release 21 --add-modules jdk.httpserver -Xlint:all -encoding UTF-8 \
  -cp "build/classes:build/android-peer-classes" \
  -d build/android-peer-classes "$INTEROP_TEST"

echo "Running Android network storage tests..."
run_java 60 -cp build/android-peer-classes \
  dev.personalcloud.android.core.NetworkStorageServiceTest

echo "Running Android resumable transfer manager tests..."
run_java 60 -cp build/android-peer-classes \
  dev.personalcloud.android.core.ResumableTransferManagerTest

echo "Running Android durable outbound sender queue tests..."
run_java 60 -cp build/android-peer-classes \
  dev.personalcloud.android.core.OutboundTransferQueueTest

echo "Running Android endpoint resolver tests..."
run_java 30 -cp build/android-peer-classes \
  dev.personalcloud.android.core.PeerEndpointResolverTest

echo "Running Android membership concurrency and liveness tests..."
run_java 60 -cp build/android-peer-classes \
  dev.personalcloud.android.core.NetworkMembershipConcurrencyTest

echo "Running Android peer protocol tests..."
for required in android.p12 android.crt; do
  test -s "$TMP/$required" || { echo "FAIL: missing disposable peer TLS artifact: $TMP/$required" >&2; exit 1; }
done
run_java 90 --add-modules jdk.httpserver \
  -cp build/android-peer-classes \
  dev.personalcloud.android.core.PeerNodeProtocolTest \
  "$TMP/android.p12" "$ANDROID_PASS" "$TMP/android.crt"

if [[ "${PERSONALCLOUD_SKIP_DESKTOP_INTEROP:-0}" == "1" ]]; then
  echo "INFO: Full desktop-process interoperability is deferred by installer policy."
  echo "INFO: Run 'bash scripts/android-desktop-interop-test.sh' without this variable for the end-to-end test."
  echo "PASS: Android peer-core storage, transfer, queue, membership and protocol tests."
else
  echo "Running desktop–Android interoperability tests..."
  for required in desktop.p12 android.p12 desktop.crt android.crt android-truststore.p12; do
    test -s "$TMP/$required" || { echo "FAIL: missing disposable interop TLS artifact: $TMP/$required" >&2; exit 1; }
  done
  run_java 240 --add-modules jdk.httpserver \
    -cp "build/classes:build/android-peer-classes" \
    dev.personalcloud.android.core.DesktopInteropTest \
    "$ROOT/build/personalcloud.jar" \
    "$TMP/desktop.p12" "$TMP/android.p12" \
    "$TMP/desktop.crt" "$TMP/android-truststore.p12" \
    "$DESKTOP_PASS" "$ANDROID_PASS" "$TRUST_PASS"

  echo "PASS: Android peer and desktop interoperability tests."
fi
