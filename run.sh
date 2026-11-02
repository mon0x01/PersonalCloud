#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -f build/personalcloud.jar ]]; then
  ./build.sh
fi
exec java --add-modules jdk.httpserver -jar build/personalcloud.jar
