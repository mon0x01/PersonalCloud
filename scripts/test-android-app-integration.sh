#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash -n scripts/build-install-android-peer.sh

MANIFEST=android-peer/app/src/main/AndroidManifest.xml
SERVICE=android-peer/app/src/main/java/dev/personalcloud/android/PeerService.java
BOOT_RECEIVER=android-peer/app/src/main/java/dev/personalcloud/android/PeerBootReceiver.java
PROVIDER=android-peer/app/src/main/java/dev/personalcloud/android/PersonalCloudDocumentsProvider.java
RUNTIME=android-peer/app/src/main/java/dev/personalcloud/android/PeerRuntime.java
STORAGE_RUNTIME=android-peer/app/src/main/java/dev/personalcloud/android/AndroidStorageRuntime.java
SAF_STORE=android-peer/app/src/main/java/dev/personalcloud/android/AndroidSafReferenceStore.java
MAIN=android-peer/app/src/main/java/dev/personalcloud/android/MainActivity.java
PEER_NODE=android-peer/peer-core/src/main/java/dev/personalcloud/android/core/PeerNode.java

# Manifest contract: foreground peer service plus Android's system DocumentsProvider.
grep -Fq 'android:name=".PeerService"' "$MANIFEST"
grep -Fq 'android:foregroundServiceType="connectedDevice"' "$MANIFEST"
grep -Fq 'android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE' "$MANIFEST"
grep -Fq 'android.permission.CHANGE_NETWORK_STATE' "$MANIFEST"
grep -Fq 'android.permission.RECEIVE_BOOT_COMPLETED' "$MANIFEST"
grep -Fq 'android:name=".PeerBootReceiver"' "$MANIFEST"
grep -Fq 'android.intent.action.BOOT_COMPLETED' "$MANIFEST"
grep -Fq 'android:name=".PersonalCloudDocumentsProvider"' "$MANIFEST"
grep -Fq 'android:authorities="${applicationId}.documents"' "$MANIFEST"
grep -Fq 'android.permission.MANAGE_DOCUMENTS' "$MANIFEST"
grep -Fq 'android:exported="true"' "$MANIFEST"

# Service lifecycle: single startup, start the listener before periodic membership sync,
# run sync only for an enrolled node, and stop the scheduler on service teardown.
grep -Fq 'starting.compareAndSet(false,true)' "$SERVICE"
grep -Fq 'node.start(InetAddress.getByName("0.0.0.0"),8879,context.getServerSocketFactory())' "$SERVICE"
grep -Fq 'PeerRuntime.node=node;' "$SERVICE"
grep -Fq 'if(membership!=null){' "$SERVICE"
grep -Fq 'startCatalogueSynchronization(membership,store)' "$SERVICE"
grep -Fq 'createOutboundTransferQueue(store, membership)' "$SERVICE"
grep -Fq 'startOutboundTransferRecovery(queue)' "$SERVICE"
grep -Fq 'queue.retryDue()' "$SERVICE"
grep -Fq 'queue.hasActiveSource(uri.toString())' "$SERVICE"
grep -Fq 'scheduleWithFixedDelay' "$SERVICE"
grep -Fq 'membership.synchronizeOnce(trustedCa)' "$SERVICE"
grep -Fq 'if(!Boolean.TRUE.equals(membership.status().get("joined"))) return;' "$SERVICE"
grep -Fq 'catalogueScheduler.shutdownNow()' "$SERVICE"
grep -Fq 'outboundTransferScheduler.shutdownNow()' "$SERVICE"
grep -Fq 'PeerRuntime.membership=null' "$SERVICE"
grep -Fq 'PeerRuntime.outboundTransfers=null' "$SERVICE"
grep -Fq 'FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE' "$SERVICE"
grep -Fq 'certificateAddressWhenAvailable' "$SERVICE"
grep -Fq 'registerDefaultNetworkCallback(networkCallback)' "$SERVICE"
grep -Fq 'onLinkPropertiesChanged(Network network,LinkProperties properties)' "$SERVICE"
grep -Fq 'scheduleEndpointRefresh(keyStore,membership,properties)' "$SERVICE"
grep -Fq 'membership.updateLocalEndpoint(endpoint)' "$SERVICE"
grep -Fq 'if(!networkEndpointValid)' "$SERVICE"
grep -Fq 'networkEndpointValid=false' "$SERVICE"
grep -Fq 'unregisterNetworkCallback(callback)' "$SERVICE"
grep -Fq 'PeerEndpointResolver.selectIpv4Address' "$SERVICE"
grep -Fq 'public synchronized Map<String, Object> updateLocalEndpoint(String candidate)' android-peer/peer-core/src/main/java/dev/personalcloud/android/core/NetworkMembershipClient.java
grep -Fq 'startupFailed' "$SERVICE"
grep -Fq 'volatile NetworkMembershipClient membership' "$RUNTIME"
grep -Fq 'volatile OutboundTransferQueue outboundTransfers' "$RUNTIME"
grep -Fq 'ACTION_BOOT_COMPLETED' "$BOOT_RECEIVER"
grep -Fq 'getConfig("peer_autostart")' "$BOOT_RECEIVER"
grep -Fq 'putConfig("peer_autostart","true")' "$MAIN"
grep -Fq 'putConfig("peer_autostart","false")' "$MAIN"

# The Android operator surface must make the signed membership lifecycle usable without
# falling back to legacy invitation pairing: bootstrap, password-proof join, approval,
# rejection, member listing and revocation are all exposed as explicit actions.
grep -Fq 'Create private network on this phone' "$MAIN"
grep -Fq 'Request to join an existing network' "$MAIN"
grep -Fq 'beginJoin(endpoint,account,password,ca)' "$MAIN"
grep -Fq 'refreshJoin(ca)' "$MAIN"
grep -Fq 'pendingRequests()' "$MAIN"
grep -Fq 'requireMembership().approve(request)' "$MAIN"
grep -Fq 'requireMembership().reject(request,' "$MAIN"
grep -Fq 'Review pending device requests' "$MAIN"
grep -Fq 'setItems(labels,(dialog,which)->reviewEnrollment(pending.get(which)))' "$MAIN"
grep -Fq 'membership.members()' "$MAIN"
grep -Fq 'revokeMember(member)' "$MAIN"
grep -Fq 'java.util.Arrays.fill(password' "$MAIN"
grep -Fq 'listRecoverySnapshots()' "$MAIN"
grep -Fq 'restoreRecoverySnapshot(snapshot)' "$MAIN"
grep -Fq 'Existing files are never overwritten' "$MAIN"
grep -Fq 'pickManagedUpload()' "$MAIN"
grep -Fq 'Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION' "$MAIN"
grep -Fq 'takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)' "$MAIN"
grep -Fq 'queue.place(managedMember, destination, uri.toString())' "$MAIN"
grep -Fq 'requireOutboundTransfers().resume(id)' "$MAIN"
grep -Fq 'requireOutboundTransfers().abort(id)' "$MAIN"
grep -Fq 'Show outbound transfer queue' "$MAIN"
grep -Fq 'Resume selected outbound transfer' "$MAIN"
grep -Fq 'Abort selected outbound transfer' "$MAIN"
grep -Fq 'hasActiveSource(uri.toString())' "$MAIN"
grep -Fq 'InputStreamSource' android-peer/peer-core/src/main/java/dev/personalcloud/android/core/PeerConnector.java
grep -Fq 'Managed source changed between digest verification and transfer' android-peer/peer-core/src/main/java/dev/personalcloud/android/core/PeerConnector.java
grep -Fq 'source.open()' android-peer/peer-core/src/main/java/dev/personalcloud/android/core/PeerConnector.java

# SAF contract: network content is read-only, served through seekable proxy descriptors,
# with signed network membership and explicit stale/offline handling.
grep -Fq 'extends DocumentsProvider' "$PROVIDER"
grep -Fq 'NetworkPeerConnector.readReferenceRange' "$PROVIDER"
grep -Fq 'NetworkPeerConnector.readManagedRange' "$PROVIDER"
grep -Fq 'openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY' "$PROVIDER"
grep -Fq 'Offline · cached metadata · unavailable' "$PROVIDER"
grep -Fq 'requireMembership()' "$PROVIDER"
grep -Fq 'if (!"r".equals(mode))' "$PROVIDER"
if grep -Eq 'FLAG_SUPPORTS_WRITE|insertDocument\(|renameDocument\(' "$PROVIDER"; then
  echo 'FAIL: Android DocumentsProvider must remain read-only in this scope.' >&2
  exit 1
fi


# In-place Android SAF references: folder selection persists provider permission and stores
# only the tree/document locator. The grant path must not copy the selected source bytes.
grep -Fq 'Intent.ACTION_OPEN_DOCUMENT_TREE' "$MAIN"
grep -Fq 'Intent.ACTION_OPEN_DOCUMENT' "$MAIN"
grep -Fq 'PICK_REFERENCE_FILE' "$MAIN"
grep -Fq 'pickReferenceFile()' "$MAIN"
grep -Fq 'Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION' "$MAIN"
grep -Fq 'takePersistableUriPermission(' "$MAIN"
grep -Fq 'Intent.FLAG_GRANT_READ_URI_PERMISSION' "$MAIN"
grep -Fq 'Intent.FLAG_GRANT_WRITE_URI_PERMISSION' "$MAIN"
grep -Fq 'requireNode().grantExternalNetworkReference(' "$MAIN"
grep -Fq 'releasePersistedPermissionIfUnused(uri.toString(), newlyPersistedReferencePermissionFlags[0])' "$MAIN"
grep -Fq 'persistedPermissionFlags(uri)' "$MAIN"
grep -Fq 'configureExternalReferenceStore(externalReferences)' android-peer/app/src/main/java/dev/personalcloud/android/PeerService.java
if sed -n '/grantReference(String memberId/,/^    }/p' "$SAF_STORE" | grep -Eq 'openInputStream|openFileDescriptor|Files\.copy|copyUri'; then
  echo 'FAIL: SAF reference creation must not copy or read source file bytes.' >&2
  exit 1
fi
grep -Fq 'DocumentsContract.buildChildDocumentsUriUsingTree' "$SAF_STORE"
grep -Fq 'DocumentsContract.isDocumentUri(contextForResolver(), selected)' "$SAF_STORE"
grep -Fq 'rootDocumentUri' "$SAF_STORE"
grep -Fq 'rootKind' "$SAF_STORE"
grep -Fq 'Single-file Android references are read-only in this release' "$SAF_STORE"
grep -Fq 'resolver.openFileDescriptor(document, "r")' "$SAF_STORE"
grep -Fq 'new BoundedInputStream(input, length)' "$SAF_STORE"
grep -Fq 'offset > expectedSize || length > expectedSize - offset' "$SAF_STORE"
grep -Fq 'DOWNLOAD+DELETE' "$SAF_STORE"
grep -Fq 'FLAG_SUPPORTS_DELETE' "$SAF_STORE"
grep -Fq 'copyAndHash(input, output, before.size)' "$SAF_STORE"
grep -Fq 'restoreRecoverySnapshot' "$SAF_STORE"

# Persisted URI access is retained while any live grant or recovery snapshot references a tree.
# Snapshot budgets are grouped by the selected tree plus relative path, not filename alone.
grep -Fq 'retainedForRecovery' "$SAF_STORE"
grep -Fq 'releaseUriPermissionIfUnused' "$SAF_STORE"
grep -Fq 'releasePersistedPermissionIfUnused' "$SAF_STORE"
grep -Fq 'flags &= requestedReleaseFlags' "$SAF_STORE"
grep -Fq 'text(record.get("treeUri")) + "\u0000" + text(record.get("path"))' "$SAF_STORE"
grep -Fq 'MAX_TOTAL_SNAPSHOT_BYTES - retainedBytes' "$SAF_STORE"
grep -Fq 'java.util.Set<String> members' "$SAF_STORE"

# The owner must see the same no-copy SAF locations through Android's system document picker.
# The service and DocumentsProvider share one process-wide store instance.
grep -Fq 'AndroidStorageRuntime.references(this)' "$SERVICE"
grep -Fq 'AndroidStorageRuntime.references(appContext())' "$PROVIDER"
grep -Fq 'public static synchronized AndroidSafReferenceStore references(Context context)' "$STORAGE_RUNTIME"
grep -Fq 'DOC_LOCAL_REFERENCES' "$PROVIDER"
grep -Fq 'Existing Android files and folders · no copy' "$PROVIDER"
grep -Fq 'localReferenceRoots()' "$PROVIDER"
grep -Fq 'localReferenceChildren(parent.grantId, parent.path)' "$PROVIDER"
grep -Fq 'DocumentId.localReferenceDir(grantId, path)' "$PROVIDER"
grep -Fq 'DocumentId.localReferenceFile(grantId, path)' "$PROVIDER"
grep -Fq 'LocalReferenceFileCallback(content, size, signal)' "$PROVIDER"
grep -Fq 'externalReferences.openOwnerReference(id.grantId, id.path)' "$PROVIDER"
grep -Fq 'case "localrefdir"' "$PROVIDER"
grep -Fq 'case "localreffile"' "$PROVIDER"

# The app layer is source-validated here. Full SDK compilation is a separate build requirement.
if command -v gradle >/dev/null 2>&1 && [[ -n "${ANDROID_HOME:-}${ANDROID_SDK_ROOT:-}" ]]; then
  (cd android-peer && gradle --offline :app:assembleDebug)
else
  echo 'INFO: Android SDK/Gradle unavailable; app framework source was statically validated, not SDK-compiled.'
fi

grep -Fq 'AndroidSafManagedStorageBackend' "$ROOT/android-peer/app/src/main/java/dev/personalcloud/android/PeerService.java"
grep -Fq 'DocumentsContract.createDocument' "$ROOT/android-peer/app/src/main/java/dev/personalcloud/android/AndroidSafManagedStorageBackend.java"
grep -Fq 'openManagedContent' "$ROOT/android-peer/peer-core/src/main/java/dev/personalcloud/android/core/NetworkStorageService.java"
grep -Fq 'PICK_MANAGED_SAF_TREE' "$ROOT/android-peer/app/src/main/java/dev/personalcloud/android/MainActivity.java"
echo 'PASS: Android connected-device foreground service, opt-in boot recovery, startup failure handling, signed membership, DocumentsProvider, and SAF storage contracts.'
