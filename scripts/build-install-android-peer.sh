#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"

fail(){ echo "FAIL: $*" >&2; exit 1; }

[[ -n "$SDK" && -d "$SDK" ]] || fail "Set ANDROID_HOME or ANDROID_SDK_ROOT to an installed Android SDK."
[[ -s "$SDK/platforms/android-35/android.jar" ]] || fail "Android SDK Platform 35 is required (compileSdk 35). Install it with Android SDK Manager, then rerun."
command -v gradle >/dev/null 2>&1 || fail "Gradle is not installed or not on PATH."
command -v adb >/dev/null 2>&1 || fail "Android platform-tools (adb) are not installed or not on PATH."

if [[ -n "${ANDROID_SERIAL:-}" ]]; then
  SERIAL="$ANDROID_SERIAL"
  STATE="$(adb -s "$SERIAL" get-state 2>/dev/null || true)"
  [[ "$STATE" == "device" ]] || fail "ANDROID_SERIAL '$SERIAL' is not an authorized online Android device."
else
  mapfile -t DEVICES < <(adb devices | awk 'NR > 1 && $2 == "device" {print $1}')
  ((${#DEVICES[@]} == 1)) || fail "Expected exactly one authorized Android device; found ${#DEVICES[@]}. Set ANDROID_SERIAL when multiple devices are attached."
  SERIAL="${DEVICES[0]}"
fi

API="$(adb -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"
[[ "$API" =~ ^[0-9]+$ ]] || fail "Could not read Android API level from device '$SERIAL'."
(( API >= 28 )) || fail "PersonalCloud requires Android API 28 or newer; connected device reports API $API."

cd "$ROOT/android-peer"
echo "Building PersonalCloud Android peer for device $SERIAL (API $API)..."
gradle --no-daemon :app:assembleDebug
APK="$ROOT/android-peer/app/build/outputs/apk/debug/app-debug.apk"
[[ -s "$APK" ]] || fail "Gradle finished without producing the expected debug APK: $APK"

echo "Installing update without clearing app data..."
adb -s "$SERIAL" install -r "$APK"
echo
printf 'PASS: installed PersonalCloud Android peer APK on %s.\n' "$SERIAL"
printf 'APK SHA-256: '
sha256sum "$APK" | awk '{print $1}'
echo "Existing app data, encrypted configuration and imported identities were not cleared by this script."
echo "Open PersonalCloud on Android and confirm the peer service is running after the update."
