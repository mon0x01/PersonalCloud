#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

JAVA_VERSION=$(java -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p')
if [[ -z "${JAVA_VERSION}" || "${JAVA_VERSION}" -lt 21 ]]; then
  echo "PersonalCloud requires JDK 21 or newer." >&2
  exit 1
fi

rm -rf build/classes
mkdir -p build/classes
javac --add-modules jdk.httpserver -encoding UTF-8 -d build/classes $(find src/main/java -name '*.java' -print)
cp -R src/main/resources/. build/classes/
jar --create --file build/personalcloud.jar --main-class dev.personalcloud.PersonalCloudApplication -C build/classes .
echo "Built build/personalcloud.jar"
