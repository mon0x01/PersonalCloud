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
INSTALL_USER="${PERSONALCLOUD_ANDROID_INSTALL_USER:-0}"
[[ "$INSTALL_USER" =~ ^[0-9]+$ ]] || fail "PERSONALCLOUD_ANDROID_INSTALL_USER must be a numeric Android user ID."
[[ "$API" =~ ^[0-9]+$ ]] || fail "Could not read Android API level from device '$SERIAL'."
(( API >= 28 )) || fail "PersonalCloud requires Android API 28 or newer; connected device reports API $API."

"$ROOT/scripts/build-android-apk.sh"
APK="$ROOT/android-peer/app/build/outputs/apk/debug/app-debug.apk"
APP_ID="dev.personalcloud.android.dev"
echo "Installing PersonalCloud Android development peer on $SERIAL (API $API, Android user $INSTALL_USER)..."
"$ADB" -s "$SERIAL" install --user "$INSTALL_USER" -r "$APK"
INSTALLED_PACKAGE="$("$ADB" -s "$SERIAL" shell pm list packages --user "$INSTALL_USER" "$APP_ID" | tr -d '\r')"
[[ "$INSTALLED_PACKAGE" == "package:$APP_ID" ]] || fail "Installation command completed but $APP_ID is not installed for Android user $INSTALL_USER."
printf '\nPASS: installed PersonalCloud Android development APK on %s (user %s).\n' "$SERIAL" "$INSTALL_USER"
printf 'APK SHA-256: '
sha256sum "$APK" | awk '{print $1}'
echo "The stable package dev.personalcloud.android and its Island profile data were not modified."
echo "The development build uses a separate package ID and separate app data/Keystore identity."
echo "Open PersonalCloud Peer (development build) on Android user $INSTALL_USER and confirm the peer service starts."
