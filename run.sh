#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ ! -f build/personalcloud.jar ]]; then ./build.sh; fi
exec java --add-modules jdk.httpserver -jar build/personalcloud.jar "$@"
