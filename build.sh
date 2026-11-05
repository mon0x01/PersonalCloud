#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

JAVA_VERSION="$(java -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p')"
if [[ -z "$JAVA_VERSION" || "$JAVA_VERSION" -lt 21 ]]; then
  echo "PersonalCloud requires JDK 21 or newer (found: ${JAVA_VERSION:-unknown})." >&2
  exit 1
fi

rm -rf build/classes
mkdir -p build/classes
mapfile -t SOURCES < <(find src/main/java -type f -name '*.java' -print | sort)
if ((${#SOURCES[@]} == 0)); then
  echo "No Java application sources found." >&2
  exit 1
fi
javac --release 21 --add-modules jdk.httpserver -encoding UTF-8 -d build/classes "${SOURCES[@]}"
jar --create --file build/personalcloud.jar --main-class dev.personalcloud.PersonalCloudApplication -C build/classes .
echo "Built build/personalcloud.jar (${#SOURCES[@]} Java source files)."
