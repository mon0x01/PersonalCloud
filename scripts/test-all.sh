#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
./scripts/test-v2-foundation.sh
./scripts/android-peer-test.sh
./scripts/test-android-app-integration.sh
./scripts/test-linux-integration.sh
echo "PASS: Complete scoped PersonalCloud Java test suite."
