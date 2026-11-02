#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
./build.sh
mkdir -p build/test-classes
javac --add-modules jdk.httpserver -encoding UTF-8 -cp build/classes -d build/test-classes $(find src/test/java -name '*.java' -print)
java -cp build/classes:build/test-classes dev.personalcloud.core.TotpServiceTest
java -cp build/classes:build/test-classes dev.personalcloud.core.StorageWatcherTest
java -cp build/classes:build/test-classes dev.personalcloud.core.VersionServiceTest
bash scripts/smoke-test.sh
if command -v node >/dev/null 2>&1; then
  node --check src/main/resources/web/app.js
else
  echo "Node.js not found; skipped JavaScript syntax check." >&2
fi
echo "PASS: build, unit tests, end-to-end smoke tests, and available frontend syntax checks."
