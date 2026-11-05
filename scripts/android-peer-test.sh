#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
./build.sh
bash "$ROOT/scripts/android-desktop-interop-test.sh"
echo "PASS: Android peer protocol and headless Java desktop interoperability."
