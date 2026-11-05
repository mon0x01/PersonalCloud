#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
./build.sh
mkdir -p build/test-classes
mapfile -t TEST_SOURCES < <(find src/test/java -type f -name '*.java' -print | sort)
if ((${#TEST_SOURCES[@]} == 0)); then echo "No Java tests found." >&2; exit 1; fi
javac --add-modules jdk.httpserver -encoding UTF-8 -cp build/personalcloud.jar -d build/test-classes "${TEST_SOURCES[@]}"

for test in \
  dev.personalcloud.core.StorageWatcherTest \
  dev.personalcloud.core.StateStoreAtomicityTest \
  dev.personalcloud.core.StateStoreMultiProcessTest \
  dev.personalcloud.core.StateStorePathSafetyTest \
  dev.personalcloud.core.FileServiceUploadAtomicityTest \
  dev.personalcloud.core.VersionServiceTest \
  dev.personalcloud.storage.ReferenceStorageServiceTest \
  dev.personalcloud.control.LocalControlClientTest \
  dev.personalcloud.storage.ReferenceFileSystemModelCacheTest \
  dev.personalcloud.protocol.PeerProtocolServerTest \
  dev.personalcloud.network.NetworkMembershipServiceTest \
  dev.personalcloud.network.NetworkProtocolIntegrationTest \
  dev.personalcloud.network.RemoteReferenceIntegrationTest \
  dev.personalcloud.network.ManagedStorageIntegrationTest \
  dev.personalcloud.network.NetworkPeerClientRangeValidationTest \
  dev.personalcloud.network.OutboundTransferQueueTest \
  dev.personalcloud.network.DirectConnectivityDiagnosticsTest \
  dev.personalcloud.transfer.ResumableTransferManagerTest; do
  java --add-modules jdk.httpserver -cp "build/personalcloud.jar:build/test-classes" "$test"
done

echo "PASS: Java-only node, reference storage, local control, CLI and peer protocol tests."
