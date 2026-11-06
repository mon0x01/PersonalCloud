#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ENV_FILE="$HOME/.config/personalcloud/android-build-env.sh"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_FILE"
fi

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
GRADLE="$(command -v gradle || true)"
if [[ -z "$GRADLE" && -n "${GRADLE_HOME:-}" && -x "$GRADLE_HOME/bin/gradle" ]]; then
  GRADLE="$GRADLE_HOME/bin/gradle"
fi

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -n "$SDK" && -s "$SDK/platforms/android-35/android.jar" ]] \
  || fail "Android SDK Platform 35 is missing. Run scripts/setup-android-build-tools.sh first."
[[ -n "$GRADLE" && -x "$GRADLE" ]] \
  || fail "Gradle 8.9 is missing. Run scripts/setup-android-build-tools.sh first."
[[ -x "$SDK/build-tools/35.0.0/aapt" ]] \
  || fail "Android Build Tools 35.0.0 are missing. Run scripts/setup-android-build-tools.sh first."
[[ -x "$SDK/build-tools/35.0.0/apksigner" ]] \
  || fail "Android Build Tools apksigner is missing. Run scripts/setup-android-build-tools.sh first."
ACTUAL_GRADLE_VERSION="$("$GRADLE" --version | awk '/^Gradle / {print $2; exit}')"
[[ "$ACTUAL_GRADLE_VERSION" == "8.9" ]] \
  || fail "Gradle 8.9 is required for this pinned Android Gradle Plugin; found '${ACTUAL_GRADLE_VERSION:-unknown}'. Run scripts/setup-android-build-tools.sh or select Gradle 8.9."

cd "$ROOT/android-peer"
echo "Building PersonalCloud Android app with Gradle $ACTUAL_GRADLE_VERSION and Android API 35..."
"$GRADLE" --no-daemon --stacktrace :app:assembleDebug

APK="$ROOT/android-peer/app/build/outputs/apk/debug/app-debug.apk"
[[ -s "$APK" ]] || fail "Gradle finished without producing the expected APK: $APK"
unzip -t "$APK" >/dev/null
BADGING="$("$SDK/build-tools/35.0.0/aapt" dump badging "$APK")"
grep -Fq "package: name='dev.personalcloud.android.dev'" <<< "$BADGING" \
  || fail "Debug APK package identity does not match dev.personalcloud.android.dev."
grep -Fq "sdkVersion:'28'" <<< "$BADGING" \
  || fail "APK minimum SDK is not Android API 28."
grep -Fq "targetSdkVersion:'35'" <<< "$BADGING" \
  || fail "APK target SDK is not Android API 35."
"$SDK/build-tools/35.0.0/apksigner" verify --verbose "$APK"

printf '\nPASS: Android debug APK built, identity/SDK levels checked and signature verified.\n'
printf 'APK: %s\n' "$APK"
printf 'Size: %s bytes\n' "$(stat -c '%s' "$APK")"
printf 'SHA-256: '
sha256sum "$APK" | awk '{print $1}'
