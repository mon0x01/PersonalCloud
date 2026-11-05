package dev.personalcloud.android;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.personalcloud.android.core.PeerNode;
import dev.personalcloud.android.core.PeerConnector;
import dev.personalcloud.android.core.NetworkMembershipClient;
import dev.personalcloud.android.core.NetworkPeerConnector;
import dev.personalcloud.android.core.NetworkStorageService;
import dev.personalcloud.android.core.OutboundTransferQueue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int PICK_P12=1, PICK_CA=2, PICK_FILE=3, PICK_TREE=4, PICK_REFERENCE_FILE=5, PICK_MANAGED_UPLOAD=6, PICK_MANAGED_SAF_TREE=7;
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private LinearLayout content;
    private TextView status;
    private EditText desktopUrl, pairingCode, caPath, peerId, sharePath, permission, shareId, remoteShareId, downloadName;
    private EditText networkName, accountName, enrollmentPeerUrl, enrollmentRequestId, revokeMemberId, recoverySnapshotId;
    private EditText managedTargetMember, managedTargetPath, managedTransferId;
    private AndroidStateStore config;
    private TextView storageStatus;
    private AndroidStorageVolumeRegistry volumeRegistry;

    @Override public void onCreate(Bundle state){super.onCreate(state);config=new AndroidStateStore(this);buildUi();if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},90);}
    private void buildUi(){
        ScrollView scroll=new ScrollView(this);content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);content.setPadding(36,28,36,48);scroll.addView(content);setContentView(scroll);
        addTitle("PersonalCloud Android Peer");addText("Independent Android node. Imported files use app-managed storage; referenced files stay in their original Android storage provider.");
        status=addText("Status: "+PeerRuntime.lastStatus);
        storageStatus=addText("Storage inventory: waiting for scan...");
        addButton("Choose network-managed storage destination (internal / SD card)",
                new View.OnClickListener(){public void onClick(View v){chooseManagedStorage();}});
        addButton("Choose SAF managed folder (USB OTG / document provider)",
                new View.OnClickListener(){public void onClick(View v){pickManagedSafTree();}});
        if ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            addButton("Run SAF provider self-test", new View.OnClickListener(){
                public void onClick(View v){runSafProviderSelfTest();}
            });
        }
        addButton("Import TLS server identity (.p12)",new View.OnClickListener(){public void onClick(View v){pick(PICK_P12,"application/x-pkcs12");}});
        addButton("Import trusted peer CA (.crt / .pem)",new View.OnClickListener(){public void onClick(View v){pick(PICK_CA,"*/*");}});
        addButton("Start Android peer service",new View.OnClickListener(){public void onClick(View v){startNode();}});
        addButton("Stop Android peer service",new View.OnClickListener(){public void onClick(View v){stopNode();}});
        addButton("Import a new file into app-owned managed storage",new View.OnClickListener(){public void onClick(View v){pick(PICK_FILE,"*/*");}});
        addDivider();addTitle("Private network membership");
        networkName=addInput("New private network name");
        accountName=addInput("Network account name");
        addButton("Create private network on this phone",new View.OnClickListener(){public void onClick(View v){bootstrapNetwork();}});
        enrollmentPeerUrl=addInput("Existing member HTTPS endpoint, e.g. https://192.168.1.10:8787");
        addButton("Request to join an existing network",new View.OnClickListener(){public void onClick(View v){joinNetwork();}});
        enrollmentRequestId=addInput("Enrollment request ID (for status / approval)");
        addButton("Check my enrollment approval",new View.OnClickListener(){public void onClick(View v){refreshEnrollment();}});
        addButton("Review pending device requests",new View.OnClickListener(){public void onClick(View v){showPendingEnrollments();}});
        addButton("Show network status and members",new View.OnClickListener(){public void onClick(View v){showNetworkMembers();}});
        revokeMemberId=addInput("Member node ID to revoke (never this device or network root)");
        addButton("Revoke network member",new View.OnClickListener(){public void onClick(View v){confirmRevokeMember();}});
        managedTargetMember=addInput("Destination member node ID for managed placement");
        managedTargetPath=addInput("Destination relative path, e.g. Documents/report.pdf");
        addButton("Place an existing Android file on that device (durable direct transfer)",new View.OnClickListener(){public void onClick(View v){pickManagedUpload();}});
        managedTransferId=addInput("Outbound transfer job ID (for resume / abort)");
        addButton("Show outbound transfer queue",new View.OnClickListener(){public void onClick(View v){listOutboundTransfers();}});
        addButton("Resume selected outbound transfer",new View.OnClickListener(){public void onClick(View v){resumeOutboundTransfer();}});
        addButton("Abort selected outbound transfer",new View.OnClickListener(){public void onClick(View v){abortOutboundTransfer();}});
        addDivider();addTitle("Pair with a desktop node");
        desktopUrl=addInput("Desktop HTTPS URL, e.g. https://192.168.1.20:8877");
        pairingCode=addInput("Desktop one-time pairing code");
        caPath=addInput("Trusted CA file (imported CA is selected automatically)");
        addButton("Pair Android with desktop",new View.OnClickListener(){public void onClick(View v){pairDesktop();}});
        addButton("Generate invitation for desktop to pair with this phone",new View.OnClickListener(){public void onClick(View v){generateInvite();}});
        addDivider();addTitle("Share files owned by this phone");
        peerId=addInput("Active network member node ID");
        sharePath=addInput("Storage-relative path, e.g. Documents/photo.jpg");
        permission=addInput("Permission: DOWNLOAD or DOWNLOAD+DELETE");permission.setText(R.string.default_permission_download);
        addButton("List phone-owned files",new View.OnClickListener(){public void onClick(View v){listLocalFiles();}});
        addButton("Reference existing Android folder (no copy) and share with peer",new View.OnClickListener(){public void onClick(View v){pickTree();}});
        addButton("Reference one existing Android file (no copy) and share with peer",new View.OnClickListener(){public void onClick(View v){pickReferenceFile();}});
        addDivider();addTitle("Owner recovery");
        recoverySnapshotId=addInput("Recovery snapshot ID");
        addButton("List retained deletion recovery snapshots",new View.OnClickListener(){public void onClick(View v){listRecoverySnapshots();}});
        addButton("Restore recovery snapshot without overwriting",new View.OnClickListener(){public void onClick(View v){restoreRecoverySnapshot();}});
        addButton("Share app-owned path with this peer",new View.OnClickListener(){public void onClick(View v){grant();}});
        addButton("Revoke this peer's grant for the path",new View.OnClickListener(){public void onClick(View v){revokeGrant();}});
        addButton("List paired devices",new View.OnClickListener(){public void onClick(View v){listPeers();}});
        addDivider();addTitle("Browse files shared by a desktop peer");
        shareId=addInput("Outgoing peer node ID");
        remoteShareId=addInput("Remote share ID (copy from remote listing)");
        downloadName=addInput("Download filename, e.g. report.pdf");
        addButton("List remote shares",new View.OnClickListener(){public void onClick(View v){listRemote();}});
        addButton("Download selected remote share",new View.OnClickListener(){public void onClick(View v){downloadRemote();}});
        addText("Protocol compatibility: PersonalCloud node/1. Android API 28+. HTTPS is mandatory for LAN peers. Import a server .p12 whose IP SAN matches the phone's Wi-Fi IP, and import the desktop CA before pairing outbound.");
    }
    private void runSafProviderSelfTest(){
        if(PeerRuntime.node!=null){
            setStatus("Stop the Android peer service before running the SAF provider self-test.");
            return;
        }
        io.execute(()->{
            try{
                String tree=config.getConfig(AndroidSafManagedStorageBackend.TREE_URI_CONFIG_KEY);
                String identity=config.getConfig(AndroidManagedStorageLocations.CONFIG_KEY);
                AndroidSafManagedStorageBackend backend =
                        new AndroidSafManagedStorageBackend(MainActivity.this,tree,identity);
                Map<String,Object> result=backend.runProviderSelfTest();
                setStatus("SAF provider device self-test PASS: "+result);
            }catch(Exception error){
                setStatus("SAF provider device self-test FAILED: "+message(error));
            }
        });
    }

    private void pickManagedSafTree(){
        if(PeerRuntime.node!=null){
            setStatus("Stop the Android peer service before changing its managed-storage destination.");
            return;
        }
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                |Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                |Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                |Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
        startActivityForResult(intent,PICK_MANAGED_SAF_TREE);
    }

    private void chooseManagedStorage(){
        if(PeerRuntime.node!=null){
            setStatus("Stop the Android peer service before changing its managed-storage destination.");
            return;
        }
        io.execute(()->{
            try{
                String current=config.getConfig(AndroidManagedStorageLocations.CONFIG_KEY);
                if(current==null||current.isBlank())current=AndroidManagedStorageLocations.APP_PRIVATE_ID;
                Map<String,Object> persisted=config.loadDomain("network-storage");
                Object rows=persisted.get("managedFiles");
                boolean hasManagedFiles=rows instanceof Map && !((Map<?,?>)rows).isEmpty();
                List<AndroidManagedStorageLocations.Location> options=new java.util.ArrayList<>();
                for(AndroidManagedStorageLocations.Location location:AndroidManagedStorageLocations.available(this)){
                    if(location.writable)options.add(location);
                }
                if(options.isEmpty())throw new IllegalStateException("No writable managed-storage locations are available.");
                final String selected=current;
                final boolean filesExist=hasManagedFiles;
                final List<AndroidManagedStorageLocations.Location> choices=options;
                String[] labels=new String[choices.size()];
                for(int i=0;i<choices.size();i++){
                    AndroidManagedStorageLocations.Location location=choices.get(i);
                    labels[i]=(location.id.equals(selected)?"CURRENT · ":"")+location.display(this);
                }
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    new AlertDialog.Builder(this)
                            .setTitle("Network-managed placement destination")
                            .setItems(labels,(dialog,which)->{
                                AndroidManagedStorageLocations.Location chosen=choices.get(which);
                                if(PeerRuntime.node!=null){
                                    setStatus("Stop the Android peer service before changing storage.");
                                    return;
                                }
                                if(filesExist&&!selected.equals(chosen.id)){
                                    setStatus("Cannot change volume while managed files are registered on "
                                            +selected+". Existing files must be migrated or removed first. No data was changed.");
                                    return;
                                }
                                Runnable saveSelection=()->io.execute(()->{
                                    try{
                                        config.putConfig(AndroidManagedStorageLocations.CONFIG_KEY,chosen.id);
                                        setStatus("Managed placement destination saved: "+chosen.label
                                                +". Restart the Android peer service to apply it.");
                                    }catch(Exception error){setStatus("Could not save storage destination: "+message(error));}
                                });
                                if(!AndroidManagedStorageLocations.APP_PRIVATE_ID.equals(chosen.id)){
                                    new AlertDialog.Builder(this)
                                            .setTitle("App-specific external storage")
                                            .setMessage("Android may delete PersonalCloud app-specific files when the app is uninstalled. Keep another copy of important data. This is not a user-owned SAF folder.")
                                            .setNegativeButton("Cancel",null)
                                            .setPositiveButton("Use this volume",(confirm,confirmationButton)->saveSelection.run())
                                            .show();
                                }else{
                                    saveSelection.run();
                                }
                            })
                            .setNegativeButton("Cancel",null)
                            .show();
                });
            }catch(Exception error){setStatus("Storage destination selection failed: "+message(error));}
        });
    }

    private NetworkMembershipClient requireMembership(){NetworkMembershipClient membership=PeerRuntime.membership;if(membership==null)throw new IllegalStateException("Start the Android peer service first. Private network membership requires Android 13 or newer.");return membership;}
    private void bootstrapNetwork(){String name=networkName.getText().toString().trim(),account=accountName.getText().toString().trim();if(name.isEmpty()||account.isEmpty()){setStatus("Enter a network name and account name first.");return;}passwordDialog("Create network password",true,password->{try{Map<String,Object> result=requireMembership().bootstrap(name,account,password);setStatus("Private network created: "+result);}catch(Exception error){setStatus("Network creation failed: "+message(error));}});}
    private void joinNetwork(){String endpoint=enrollmentPeerUrl.getText().toString().trim(),account=accountName.getText().toString().trim();if(endpoint.isEmpty()){setStatus("Enter an existing member HTTPS endpoint first.");return;}passwordDialog("Network account password",false,password->{try{String ca=config.getConfig("peer_ca");Map<String,Object> result=requireMembership().beginJoin(endpoint,account,password,ca);String request=String.valueOf(result.get("requestId"));runOnUiThread(()->enrollmentRequestId.setText(request));setStatus("Enrollment request submitted; an existing member must approve it: "+result);}catch(Exception error){setStatus("Network enrollment failed: "+message(error));}});}
    private void refreshEnrollment(){String request=enrollmentRequestId.getText().toString().trim();io.execute(()->{try{String ca=config.getConfig("peer_ca");Map<String,Object> result=requireMembership().refreshJoin(ca);setStatus("Enrollment status: "+result);}catch(Exception error){setStatus("Enrollment status check failed: "+message(error));}});}
    private void showPendingEnrollments(){io.execute(()->{try{List<Map<String,Object>> pending=requireMembership().pendingRequests();if(pending.isEmpty()){setStatus("There are no pending network enrollment requests.");return;}String[] labels=new String[pending.size()];for(int i=0;i<pending.size();i++){Map<String,Object> row=pending.get(i);labels[i]=String.valueOf(row.get("nodeName"))+" · "+String.valueOf(row.get("nodeId"));}runOnUiThread(()->new AlertDialog.Builder(MainActivity.this).setTitle("Review pending device").setItems(labels,(dialog,which)->reviewEnrollment(pending.get(which))).setNegativeButton("Close",null).show());}catch(Exception error){setStatus("Could not list enrollment requests: "+message(error));}});}
    private void reviewEnrollment(Map<String,Object> pending){String request=String.valueOf(pending.get("requestId"));String details="Device: "+pending.get("nodeName")+"\nNode ID: "+pending.get("nodeId")+"\nEndpoint: "+pending.get("endpoint");new AlertDialog.Builder(this).setTitle("Approve this device?").setMessage(details).setPositiveButton("Approve",(dialog,which)->io.execute(()->{try{setStatus("Enrollment approval result: "+requireMembership().approve(request));}catch(Exception error){setStatus("Enrollment approval failed: "+message(error));}})).setNegativeButton("Reject",(dialog,which)->io.execute(()->{try{setStatus("Enrollment rejection result: "+requireMembership().reject(request,"Rejected by network device owner."));}catch(Exception error){setStatus("Enrollment rejection failed: "+message(error));}})).setNeutralButton("Cancel",null).show();}
    private void showNetworkMembers(){io.execute(()->{try{NetworkMembershipClient membership=requireMembership();setStatus("Network status: "+membership.status()+"\nMembers: "+membership.members());}catch(Exception error){setStatus("Could not read network membership: "+message(error));}});}
    private void confirmRevokeMember(){String member=revokeMemberId.getText().toString().trim();if(member.isEmpty()){setStatus("Enter the member node ID to revoke.");return;}new AlertDialog.Builder(this).setTitle("Revoke network member?").setMessage("This immediately blocks this member from authenticated PersonalCloud operations. It does not delete its local files.").setNegativeButton("Cancel",null).setPositiveButton("Revoke",(dialog,which)->io.execute(()->{try{requireMembership().revokeMember(member);setStatus("Network member revoked: "+member);}catch(Exception error){setStatus("Member revocation failed: "+message(error));}})).show();}
    private void listRecoverySnapshots(){io.execute(()->{try{setStatus("Owner-local recovery snapshots: "+AndroidStorageRuntime.references(MainActivity.this).listRecoverySnapshots());}catch(Exception error){setStatus("Could not list recovery snapshots: "+message(error));}});}
    private void restoreRecoverySnapshot(){String snapshot=recoverySnapshotId.getText().toString().trim();if(snapshot.isEmpty()){setStatus("Enter a recovery snapshot ID first.");return;}new AlertDialog.Builder(this).setTitle("Restore deleted Android document?").setMessage("The original path is restored only if the destination name is still available. Existing files are never overwritten.").setNegativeButton("Cancel",null).setPositiveButton("Restore",(dialog,which)->io.execute(()->{try{Map<String,Object> result=AndroidStorageRuntime.references(MainActivity.this).restoreRecoverySnapshot(snapshot);setStatus("Recovery restore verified: "+result);}catch(Exception error){setStatus("Recovery restore failed: "+message(error));}})).show();}
    private void passwordDialog(String title,boolean confirmation,PasswordAction action){EditText secret=new EditText(this);secret.setSingleLine(true);secret.setHint("Network password");secret.setInputType(129);EditText confirm=confirmation?new EditText(this):null;if(confirm!=null){confirm.setSingleLine(true);confirm.setHint("Confirm network password");confirm.setInputType(129);}LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);fields.addView(secret);if(confirm!=null)fields.addView(confirm);new AlertDialog.Builder(this).setTitle(title).setView(fields).setNegativeButton("Cancel",null).setPositiveButton(confirmation?"Create":"Continue",(dialog,which)->{char[] password=secret.getText().toString().toCharArray();char[] repeated=confirm==null?null:confirm.getText().toString().toCharArray();if(repeated!=null&&!sameCharacters(password,repeated)){java.util.Arrays.fill(password,'\0');java.util.Arrays.fill(repeated,'\0');setStatus("Password confirmation did not match.");return;}if(repeated!=null)java.util.Arrays.fill(repeated,'\0');io.execute(()->{try{action.run(password);}catch(Exception error){setStatus("Password operation failed: "+message(error));}finally{java.util.Arrays.fill(password,'\0');}});}).show();}
    private static boolean sameCharacters(char[] left,char[] right){int difference=left.length^right.length;int maximum=Math.max(left.length,right.length);for(int i=0;i<maximum;i++){char a=i<left.length?left[i]:0;char b=i<right.length?right[i]:0;difference|=a^b;}return difference==0;}
    private static String message(Exception error){return error.getMessage()==null?error.getClass().getSimpleName():error.getMessage();}
    private interface PasswordAction{void run(char[] password)throws Exception;}
    private void pick(int code,String type){Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType(type);startActivityForResult(i,code);}
    private void pickTree(){Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION|Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);startActivityForResult(intent,PICK_TREE);}
    private void pickReferenceFile(){Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.addCategory(Intent.CATEGORY_OPENABLE);intent.setType("*/*");intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);startActivityForResult(intent,PICK_REFERENCE_FILE);}
    private void pickManagedUpload(){Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.addCategory(Intent.CATEGORY_OPENABLE);intent.setType("*/*");intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);startActivityForResult(intent,PICK_MANAGED_UPLOAD);}
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        // Capture view values on the UI thread; background work must not touch Activity views.
        boolean isReferenceSelection = request == PICK_TREE || request == PICK_REFERENCE_FILE;
        String selectedMember = isReferenceSelection ? peerId.getText().toString().trim() : "";
        String selectedPermission = isReferenceSelection ? permission.getText().toString().trim() : "";
        String managedMember = request == PICK_MANAGED_UPLOAD ? managedTargetMember.getText().toString().trim() : "";
        String managedPath = request == PICK_MANAGED_UPLOAD ? managedTargetPath.getText().toString().trim() : "";
        int selectedUriFlags = data.getFlags()
                & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        io.execute(() -> {
            int[] newlyPersistedReferencePermissionFlags = {0};
            boolean[] referenceCommitted = {false};
            try {
                if (request == PICK_MANAGED_SAF_TREE) {
                    if(PeerRuntime.node!=null)throw new IllegalStateException("Stop the Android peer service before changing managed storage.");
                    if((selectedUriFlags & Intent.FLAG_GRANT_READ_URI_PERMISSION)==0
                            ||(selectedUriFlags & Intent.FLAG_GRANT_WRITE_URI_PERMISSION)==0){
                        throw new SecurityException("The selected SAF folder must grant both persistent read and write access.");
                    }
                    AndroidSafManagedStorageBackend.validateSelection(this,uri);
                    String newStorageId=AndroidSafManagedStorageBackend.storageIdForTree(uri);
                    String current=config.getConfig(AndroidManagedStorageLocations.CONFIG_KEY);
                    if(current==null||current.isBlank())current=AndroidManagedStorageLocations.APP_PRIVATE_ID;
                    Map<String,Object> persisted=config.loadDomain("network-storage");
                    Object rows=persisted.get("managedFiles");
                    boolean hasManagedFiles=rows instanceof Map && !((Map<?,?>)rows).isEmpty();
                    if(hasManagedFiles&&!current.equals(newStorageId)){
                        throw new IllegalStateException("Managed files are registered on storage volume '"+current+"'. Remove or migrate them before changing placement.");
                    }
                    int previous=persistedPermissionFlags(uri);
                    getContentResolver().takePersistableUriPermission(uri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                    try{
                        config.putConfig(AndroidSafManagedStorageBackend.TREE_URI_CONFIG_KEY,uri.toString());
                        config.putConfig(AndroidManagedStorageLocations.CONFIG_KEY,newStorageId);
                    }catch(Exception failure){
                        int added=(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION)&~previous;
                        if((added&Intent.FLAG_GRANT_READ_URI_PERMISSION)!=0)try{getContentResolver().releasePersistableUriPermission(uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(Exception ignored){}
                        if((added&Intent.FLAG_GRANT_WRITE_URI_PERMISSION)!=0)try{getContentResolver().releasePersistableUriPermission(uri,Intent.FLAG_GRANT_WRITE_URI_PERMISSION);}catch(Exception ignored){}
                        throw failure;
                    }
                    setStatus("SAF managed folder saved. Network-managed files will be stored in PersonalCloud Managed inside the selected folder. Restart the peer service to apply it.");
                } else if (request == PICK_P12) {
                    Path file = copyUri(uri, "server-identity.p12");
                    runOnUiThread(() -> passwordDialog(file));
                } else if (request == PICK_CA) {
                    Path file = copyUri(uri, "peer-ca.crt");
                    config.putConfig("peer_ca", file.toString());
                    setStatus("Trusted CA imported: " + file.getFileName());
                } else if (request == PICK_FILE) {
                    String name = displayName(uri);
                    Path root = java.nio.file.Paths.get(getFilesDir().getAbsolutePath(), "node-storage");
                    Files.createDirectories(root);
                    Path target = root.resolve(safeFilename(name));
                    if (Files.exists(target)) throw new IllegalArgumentException("A file with that name already exists in node storage.");
                    try (InputStream in = getContentResolver().openInputStream(uri);
                         OutputStream out = Files.newOutputStream(target)) {
                        if (in == null) throw new IllegalStateException("Could not open selected document.");
                        byte[] buffer = new byte[65536];
                        int read;
                        while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                    }
                    setStatus("Imported into phone-owned managed storage: " + target.getFileName());
                } else if (request == PICK_TREE || request == PICK_REFERENCE_FILE) {
                    if ((selectedUriFlags & Intent.FLAG_GRANT_READ_URI_PERMISSION) == 0) {
                        throw new SecurityException("Android did not grant persistent read access to the selected document.");
                    }
                    int previousPersistedFlags = persistedPermissionFlags(uri);
                    if ((selectedUriFlags & Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0) {
                        getContentResolver().takePersistableUriPermission(
                                uri,
                                Intent.FLAG_GRANT_READ_URI_PERMISSION
                                        | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                    } else {
                        getContentResolver().takePersistableUriPermission(
                                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    }
                    newlyPersistedReferencePermissionFlags[0] = selectedUriFlags & ~previousPersistedFlags;
                    Map<String,Object> grant = requireNode().grantExternalNetworkReference(
                            selectedMember, uri.toString(), selectedPermission);
                    referenceCommitted[0] = true;
                    String kind = request == PICK_TREE ? "folder" : "file";
                    setStatus("Existing Android " + kind + " referenced in place (no copy). Grant: " + grant);
                } else if (request == PICK_MANAGED_UPLOAD) {
                    if (managedMember.isEmpty()) throw new IllegalArgumentException("Enter the destination network member ID first.");
                    if ((selectedUriFlags & Intent.FLAG_GRANT_READ_URI_PERMISSION) == 0) {
                        throw new SecurityException("Android did not grant read access to the selected document.");
                    }
                    int previous = persistedPermissionFlags(uri);
                    getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    newlyPersistedReferencePermissionFlags[0] = Intent.FLAG_GRANT_READ_URI_PERMISSION & ~previous;
                    String destination = managedPath.isEmpty() ? displayName(uri) : managedPath;
                    OutboundTransferQueue queue = requireOutboundTransfers();
                    Map<String,Object> job = queue.place(managedMember, destination, uri.toString());
                    referenceCommitted[0] = true;
                    String jobId = String.valueOf(job.get("jobId"));
                    runOnUiThread(() -> managedTransferId.setText(jobId));
                    setStatus("Durable direct placement job " + jobId + " is " + job.get("status")
                            + ". It resumes automatically while the peer service is running.");
                }
            } catch (Exception error) {
                boolean transferStillNeedsSource = false;
                if (request == PICK_MANAGED_UPLOAD && PeerRuntime.outboundTransfers != null) {
                    try { transferStillNeedsSource = PeerRuntime.outboundTransfers.hasActiveSource(uri.toString()); }
                    catch (Exception ignored) { transferStillNeedsSource = true; }
                }
                if (newlyPersistedReferencePermissionFlags[0] != 0 && !referenceCommitted[0]
                        && !transferStillNeedsSource) {
                    try {
                        AndroidStorageRuntime.references(MainActivity.this)
                                .releasePersistedPermissionIfUnused(uri.toString(), newlyPersistedReferencePermissionFlags[0]);
                    } catch (Exception ignored) { }
                }
                setStatus("Error: " + (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage()));
            }
        });
    }
    private int persistedPermissionFlags(Uri uri) {
        int flags = 0;
        for (android.content.UriPermission permission : getContentResolver().getPersistedUriPermissions()) {
            if (!permission.getUri().equals(uri)) continue;
            if (permission.isReadPermission()) flags |= Intent.FLAG_GRANT_READ_URI_PERMISSION;
            if (permission.isWritePermission()) flags |= Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
        }
        return flags;
    }
    private void passwordDialog(Path file){EditText pass=new EditText(this);pass.setHint("PKCS#12 password");pass.setInputType(129);new AlertDialog.Builder(this).setTitle("Protect server identity").setMessage("Enter the password for this TLS identity. It is stored encrypted with Android Keystore.").setView(pass).setNegativeButton("Cancel",null).setPositiveButton("Save",(d,w)->io.execute(()->{try{config.putConfig("keystore_path",file.toString());config.putConfig("keystore_password",pass.getText().toString());setStatus("TLS server identity imported.");}catch(Exception e){setStatus("Error: "+e.getMessage());}})).show();}
    private Path copyUri(Uri uri,String name)throws Exception{Path target=java.nio.file.Paths.get(getFilesDir().getAbsolutePath(),name);try(InputStream in=getContentResolver().openInputStream(uri);OutputStream out=Files.newOutputStream(target)){if(in==null)throw new IllegalStateException("Unable to read selected file.");byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1)out.write(b,0,n);}return target;}
    private void startNode(){
        io.execute(()->{
            try{
                String id=config.getConfig("node_id");
                if(id.length()==0){
                    id=java.util.UUID.randomUUID().toString();
                    config.putConfig("node_id",id);
                }
                config.putConfig("node_name","PersonalCloud-Android");
                config.putConfig("peer_autostart","true");
                Intent i=new Intent(this,PeerService.class);
                i.setAction(PeerService.ACTION_START);
                startForegroundService(i);
                setStatus("Peer start requested. Automatic startup after reboot is enabled; check the notification for actual status.");
            }catch(Exception e){
                setStatus("Error: "+e.getMessage());
            }
        });
    }
    private void stopNode(){
        io.execute(()->{
            try{
                config.putConfig("peer_autostart","false");
                stopService(new Intent(MainActivity.this,PeerService.class));
                setStatus("Peer stop requested. Automatic startup after reboot is disabled.");
            }catch(Exception e){
                setStatus("Error stopping peer: "+e.getMessage());
            }
        });
    }
    private OutboundTransferQueue requireOutboundTransfers() {
        OutboundTransferQueue queue = PeerRuntime.outboundTransfers;
        if (queue == null) throw new IllegalStateException(
                "Start the Android peer service and join an approved private network before managed placement.");
        return queue;
    }

    private void listOutboundTransfers() {
        io.execute(() -> {
            try {
                setStatus("Durable outbound transfers (newest first):\n" + requireOutboundTransfers().list());
            } catch (Exception error) { setStatus("Could not list outbound transfers: " + message(error)); }
        });
    }

    private void resumeOutboundTransfer() {
        String id = managedTransferId.getText().toString().trim();
        io.execute(() -> {
            try { setStatus("Outbound transfer resume result: " + requireOutboundTransfers().resume(id)); }
            catch (Exception error) { setStatus("Could not resume outbound transfer: " + message(error)); }
        });
    }

    private void abortOutboundTransfer() {
        String id = managedTransferId.getText().toString().trim();
        new AlertDialog.Builder(this).setTitle("Abort outbound transfer?")
                .setMessage("The receiver will retain no partial file. A transfer already committed cannot be aborted.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Abort", (dialog, which) -> io.execute(() -> {
                    try { setStatus("Outbound transfer abort result: " + requireOutboundTransfers().abort(id)); }
                    catch (Exception error) { setStatus("Could not abort outbound transfer: " + message(error)); }
                })).show();
    }

    private void pairDesktop(){String url=desktopUrl.getText().toString().trim(),code=pairingCode.getText().toString().trim();io.execute(()->{try{PeerNode n=requireNode();String ca=caPath.getText().toString().trim();if(ca.length()==0)ca=config.getConfig("peer_ca");n.pairWith(url,code,ca);setStatus("Paired with desktop. Refresh paired devices to see its node ID.");}catch(Exception e){setStatus("Pairing failed: "+e.getMessage());}});}
    private void generateInvite(){io.execute(()->{try{String code=requireNode().createInvitation();setStatus("One-time invitation (valid 10 minutes): "+code+"\nAndroid peer URL(s): "+localIpv4Urls()+"\nOn desktop, add a peer using one of these HTTPS URLs and this code. Desktop must trust the Android CA.");}catch(Exception e){setStatus("Error: "+e.getMessage());}});}
    private void grant(){String id=peerId.getText().toString().trim(),path=sharePath.getText().toString().trim(),level=permission.getText().toString().trim();io.execute(()->{try{Map<String,Object> grant=requireNode().grantNetworkReference(id,path,level);setStatus("Granted "+level+" access to app-owned path "+path+": "+grant);}catch(Exception e){setStatus("Grant failed: "+e.getMessage());}});}
    private void listPeers(){io.execute(()->{try{List<Map<String,Object>> peers=requireNode().peers();setStatus("Paired devices:\n"+peers.toString());}catch(Exception e){setStatus("Error: "+e.getMessage());}});}
    private void listLocalFiles(){io.execute(()->{try{setStatus("Phone-owned files:\n"+requireNode().listLocalFiles().toString());}catch(Exception e){setStatus("Error: "+e.getMessage());}});}
    private void revokeGrant(){String id=peerId.getText().toString().trim(),path=sharePath.getText().toString().trim();io.execute(()->{try{requireNode().revokeGrant(id,path);setStatus("Grant revoked for "+path);}catch(Exception e){setStatus("Revoke failed: "+e.getMessage());}});}
    private void listRemote(){String id=shareId.getText().toString().trim();io.execute(()->{try{String ca=config.getConfig("peer_ca");List<Map<String,Object>> shares=requireNode().outgoingShares(id,ca);setStatus("Remote shares (shareId / name / permission):\n"+shares.toString());}catch(Exception e){setStatus("Remote listing failed: "+e.getMessage());}});}
    private void downloadRemote(){String peer=shareId.getText().toString().trim(),remote=remoteShareId.getText().toString().trim(),filename=downloadName.getText().toString().trim();io.execute(()->{try{String safe=safeFilename(filename.length()==0?remote:filename);Path destination=java.nio.file.Paths.get(getFilesDir().getAbsolutePath(),"node-storage",safe);requireNode().downloadShare(peer,remote,destination,config.getConfig("peer_ca"));setStatus("Downloaded and checksum-verified into phone storage: "+safe);}catch(Exception e){setStatus("Download failed: "+e.getMessage());}});}
    private String localIpv4Urls(){StringBuilder result=new StringBuilder();try{java.util.Enumeration<java.net.NetworkInterface> interfaces=java.net.NetworkInterface.getNetworkInterfaces();while(interfaces!=null&&interfaces.hasMoreElements()){java.net.NetworkInterface network=interfaces.nextElement();java.util.Enumeration<java.net.InetAddress> addresses=network.getInetAddresses();while(addresses.hasMoreElements()){java.net.InetAddress address=addresses.nextElement();if(address instanceof java.net.Inet4Address&&!address.isLoopbackAddress()&&!address.isLinkLocalAddress()){if(result.length()>0)result.append(", ");result.append("https://").append(address.getHostAddress()).append(":8879");}}}}catch(Exception ignored){}return result.length()==0?"No active IPv4 address found":result.toString();}
    private PeerNode requireNode(){long deadline=System.currentTimeMillis()+10000;PeerNode n;while((n=PeerRuntime.node)==null&&System.currentTimeMillis()<deadline){try{Thread.sleep(100);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("Interrupted while waiting for peer service.");}}if(n==null)throw new IllegalStateException("Peer service is not ready. Confirm that a valid TLS identity was imported and the foreground service is running.");return n;}
    private String displayName(Uri uri){try(Cursor c=getContentResolver().query(uri,null,null,null,null)){if(c!=null&&c.moveToFirst()){int i=c.getColumnIndex(OpenableColumns.DISPLAY_NAME);if(i>=0)return c.getString(i);}}return "imported-file";}
    private static String safeFilename(String s){String n=s==null?"imported-file":s.replaceAll("[\\\\/:*?\"<>|]","_").trim();if(n.length()==0||n.equals(".")||n.equals(".."))return "imported-file";return n;}
    private EditText addInput(String hint){EditText e=new EditText(this);e.setSingleLine(true);e.setHint(hint);content.addView(e,new LinearLayout.LayoutParams(-1,-2));return e;}
    private void addButton(String text,View.OnClickListener click){Button b=new Button(this);b.setText(text);b.setOnClickListener(click);content.addView(b,new LinearLayout.LayoutParams(-1,-2));}
    private TextView addText(String text){TextView t=new TextView(this);t.setText(text);t.setTextSize(15);t.setPadding(0,8,0,12);content.addView(t);return t;}
    private void addTitle(String text){TextView t=addText(text);t.setTextSize(21);t.setTypeface(null,android.graphics.Typeface.BOLD);}
    private void addDivider(){View v=new View(this);v.setBackgroundColor(0xffcccccc);LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,2);p.setMargins(0,20,0,16);content.addView(v,p);}
    private void setStatus(String text){runOnUiThread(()->status.setText(getString(R.string.status_format, text)));}
    @Override protected void onStart() {
        super.onStart();
        try {
            volumeRegistry = new AndroidStorageVolumeRegistry(this, snapshot -> {
                String display = snapshot.toDisplayText(MainActivity.this);
                runOnUiThread(() -> {
                    if (storageStatus != null && !isDestroyed()) {
                        storageStatus.setText(display);
                    }
                });
            });
            volumeRegistry.start();
        } catch (Exception error) {
            storageStatus.setText("Storage inventory unavailable: "
                    + (error.getMessage() == null
                    ? error.getClass().getSimpleName() : error.getMessage()));
        }
    }

    @Override protected void onStop() {
        AndroidStorageVolumeRegistry registry = volumeRegistry;
        volumeRegistry = null;
        if (registry != null) registry.close();
        super.onStop();
    }

    @Override protected void onDestroy(){io.shutdown();super.onDestroy();}
}
