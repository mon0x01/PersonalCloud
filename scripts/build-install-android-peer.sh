#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ENV_FILE="$HOME/.config/personalcloud/android-build-env.sh"
[[ ! -f "$ENV_FILE" ]] || source "$ENV_FILE"

fail(){ echo "FAIL: $*" >&2; exit 1; }

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
ADB="$(command -v adb || true)"
if [[ -z "$ADB" && -n "$SDK" && -x "$SDK/platform-tools/adb" ]]; then
  ADB="$SDK/platform-tools/adb"
fi
[[ -n "$SDK" && -d "$SDK" ]] || fail "Run scripts/setup-android-build-tools.sh first."
[[ -n "$ADB" && -x "$ADB" ]] || fail "ADB is unavailable. Run scripts/setup-android-build-tools.sh first."

if [[ -n "${ANDROID_SERIAL:-}" ]]; then
  SERIAL="$ANDROID_SERIAL"
  STATE="$("$ADB" -s "$SERIAL" get-state 2>/dev/null || true)"
  [[ "$STATE" == "device" ]] || fail "ANDROID_SERIAL '$SERIAL' is not an authorized online Android device."
else
  mapfile -t DEVICES < <("$ADB" devices | awk 'NR > 1 && $2 == "device" {print $1}')
  ((${#DEVICES[@]} == 1)) || fail "Expected exactly one authorized Android device; found ${#DEVICES[@]}. Set ANDROID_SERIAL when multiple devices are attached."
  SERIAL="${DEVICES[0]}"
fi

API="$("$ADB" -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"
[[ "$API" =~ ^[0-9]+$ ]] || fail "Could not read Android API level from device '$SERIAL'."
(( API >= 28 )) || fail "PersonalCloud requires Android API 28 or newer; connected device reports API $API."

"$ROOT/scripts/build-android-apk.sh"
APK="$ROOT/android-peer/app/build/outputs/apk/debug/app-debug.apk"
echo "Installing PersonalCloud Android peer on $SERIAL (API $API)..."
"$ADB" -s "$SERIAL" install -r "$APK"
printf '\nPASS: installed PersonalCloud Android peer APK on %s.\n' "$SERIAL"
printf 'APK SHA-256: '
sha256sum "$APK" | awk '{print $1}'
echo "Existing app data, encrypted configuration and imported identities were not cleared by this script."
echo "Open PersonalCloud on Android and confirm the peer service is running after the update."
