#!/usr/bin/env bash
set -Eeuo pipefail

# Install a reproducible Android CLI build toolchain without sudo or system-wide changes.
# Pinned versions and published SHA-256 values are intentionally kept in this script.
ANDROID_TOOLS_ROOT="${PERSONALCLOUD_ANDROID_TOOLS_ROOT:-$HOME/.local/share/personalcloud/android-build-tools}"
SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
GRADLE_VERSION="8.9"
CMDLINE_BUILD="15859902"
CMDLINE_SHA256="4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583"
GRADLE_SHA256="d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab"
ENV_FILE="$HOME/.config/personalcloud/android-build-env.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in curl unzip sha256sum df awk sed java; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required tool '$tool' is missing. Install it with your OS package manager."
done

JAVA_VERSION="$(java -version 2>&1 | sed -nE 's/.*version "([0-9]+).*/\1/p' | head -1)"
[[ "$JAVA_VERSION" =~ ^[0-9]+$ ]] || fail "Could not determine Java version."
(( JAVA_VERSION >= 17 )) || fail "Android Gradle Plugin 8.7.3 requires JDK 17 or newer; found Java $JAVA_VERSION."

FREE_KB="$(df -Pk "$HOME" | awk 'NR==2 {print $4}')"
[[ "$FREE_KB" =~ ^[0-9]+$ ]] || fail "Could not determine free disk space."
(( FREE_KB >= 2500000 )) || fail "At least 2.5 GB free space is required for Android SDK 35 and Gradle."

if [[ -e "$ENV_FILE" ]] && ! grep -Fq 'Managed by PersonalCloud scripts/setup-android-build-tools.sh' "$ENV_FILE"; then
  fail "Refusing to overwrite existing custom environment file: $ENV_FILE"
fi

mkdir -p "$ANDROID_TOOLS_ROOT" "$SDK_ROOT/cmdline-tools" "$(dirname "$ENV_FILE")"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/personalcloud-android-tools.XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT

CMDLINE_ARCHIVE="$TMP/commandlinetools-linux-${CMDLINE_BUILD}_latest.zip"
GRADLE_ARCHIVE="$TMP/gradle-${GRADLE_VERSION}-bin.zip"

if [[ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]]; then
  echo "Downloading Android command-line tools build $CMDLINE_BUILD..."
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 20 \
    "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_BUILD}_latest.zip" \
    --output "$CMDLINE_ARCHIVE"
  echo "$CMDLINE_SHA256  $CMDLINE_ARCHIVE" | sha256sum --check --status \
    || fail "Android command-line tools SHA-256 mismatch. Archive was not installed."
  mkdir -p "$TMP/cmdline-extract"
  unzip -q "$CMDLINE_ARCHIVE" -d "$TMP/cmdline-extract"
  [[ -x "$TMP/cmdline-extract/cmdline-tools/bin/sdkmanager" ]] \
    || fail "Android command-line tools archive has an unexpected structure."
  STAGED_TOOLS="$SDK_ROOT/cmdline-tools/.latest.new.$$"
  rm -rf -- "$STAGED_TOOLS"
  mv "$TMP/cmdline-extract/cmdline-tools" "$STAGED_TOOLS"
  rm -rf -- "$SDK_ROOT/cmdline-tools/latest"
  mv "$STAGED_TOOLS" "$SDK_ROOT/cmdline-tools/latest"
else
  echo "Android command-line tools already installed."
fi

GRADLE_HOME="$ANDROID_TOOLS_ROOT/gradle-${GRADLE_VERSION}"
if [[ ! -x "$GRADLE_HOME/bin/gradle" ]]; then
  echo "Downloading Gradle $GRADLE_VERSION..."
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 20 \
    "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    --output "$GRADLE_ARCHIVE"
  echo "$GRADLE_SHA256  $GRADLE_ARCHIVE" | sha256sum --check --status \
    || fail "Gradle distribution SHA-256 mismatch. Archive was not installed."
  mkdir -p "$TMP/gradle-extract"
  unzip -q "$GRADLE_ARCHIVE" -d "$TMP/gradle-extract"
  [[ -x "$TMP/gradle-extract/gradle-${GRADLE_VERSION}/bin/gradle" ]] \
    || fail "Gradle archive has an unexpected structure."
  rm -rf -- "$GRADLE_HOME"
  mv "$TMP/gradle-extract/gradle-${GRADLE_VERSION}" "$GRADLE_HOME"
else
  echo "Gradle $GRADLE_VERSION already installed."
fi

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
[[ -x "$SDKMANAGER" ]] || fail "sdkmanager is not executable after installation."

export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export PATH="$GRADLE_HOME/bin:$SDK_ROOT/cmdline-tools/latest/bin:$SDK_ROOT/platform-tools:$PATH"

printf 'Accepting Android SDK licenses...\n'
# sdkmanager exits after accepting licenses; disable pipefail for this one pipeline so
# `yes` receiving SIGPIPE after success does not turn the successful SDK operation into a failure.
set +o pipefail
if yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null; then
  LICENSE_STATUS=0
else
  LICENSE_STATUS=$?
fi
set -o pipefail
(( LICENSE_STATUS == 0 )) || fail "Android SDK license acceptance failed (exit $LICENSE_STATUS)."
printf 'Installing Android platform, build tools and ADB...\n'
"$SDKMANAGER" --sdk_root="$SDK_ROOT" --install \
  'platform-tools' 'platforms;android-35' 'build-tools;35.0.0'

{
  printf '%s\n' '# Managed by PersonalCloud scripts/setup-android-build-tools.sh'
  printf 'export ANDROID_HOME=%q\n' "$SDK_ROOT"
  printf 'export ANDROID_SDK_ROOT=%q\n' "$SDK_ROOT"
  printf 'export GRADLE_HOME=%q\n' "$GRADLE_HOME"
  printf 'export PATH=%q:"$PATH"\n' "$GRADLE_HOME/bin:$SDK_ROOT/cmdline-tools/latest/bin:$SDK_ROOT/platform-tools"
} > "$TMP/android-build-env.sh"
chmod 600 "$TMP/android-build-env.sh"
mv "$TMP/android-build-env.sh" "$ENV_FILE"

[[ -s "$SDK_ROOT/platforms/android-35/android.jar" ]] || fail "Android API 35 platform installation is incomplete."
[[ -x "$SDK_ROOT/platform-tools/adb" ]] || fail "ADB installation is incomplete."
[[ -x "$SDK_ROOT/build-tools/35.0.0/aapt" ]] || fail "Android Build Tools 35.0.0 installation is incomplete."

printf '\nPASS: Android build toolchain installed and verified.\n'
printf 'SDK: %s\nGradle: %s\nEnvironment: %s\n' "$SDK_ROOT" "$GRADLE_HOME" "$ENV_FILE"
printf 'Build APK: %s/scripts/build-android-apk.sh\n' "$(cd "$(dirname "$0")/.." && pwd -P)"
printf 'Install on one connected authorized device: %s/scripts/build-install-android-peer.sh\n' "$(cd "$(dirname "$0")/.." && pwd -P)"
