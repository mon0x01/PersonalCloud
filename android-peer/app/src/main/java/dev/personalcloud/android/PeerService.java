package dev.personalcloud.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.UriPermission;
import android.net.Uri;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;
import android.os.IBinder;

import dev.personalcloud.android.core.PeerNode;
import dev.personalcloud.android.core.NetworkMembershipClient;
import dev.personalcloud.android.core.ExternalReferenceStore;
import dev.personalcloud.android.core.ManagedStorageBackend;
import dev.personalcloud.android.core.NetworkPeerConnector;
import dev.personalcloud.android.core.NetworkStorageService;
import dev.personalcloud.android.core.OutboundTransferQueue;
import dev.personalcloud.android.core.PeerEndpointResolver;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class PeerService extends Service {
    private static final String CHANNEL="personalcloud_peer";
    private static final String TAG="PersonalCloudPeer";
    public static final String ACTION_START="dev.personalcloud.android.action.START_PEER";
    private volatile boolean startupFailed;
    private volatile boolean keepFailureNotification;
    private final AtomicBoolean starting = new AtomicBoolean();
    private ScheduledExecutorService catalogueScheduler;
    private ScheduledExecutorService outboundTransferScheduler;
    private volatile ConnectivityManager connectivityManager;
    private volatile ConnectivityManager.NetworkCallback networkCallback;
    private volatile ExecutorService networkChangeExecutor;
    private final AtomicBoolean networkRefreshQueued = new AtomicBoolean();
    private volatile boolean networkEndpointValid;

    @Override public void onCreate(){super.onCreate();createChannel();}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(PeerRuntime.node!=null || !starting.compareAndSet(false,true)) return START_STICKY;
        startupFailed=false;
        keepFailureNotification=false;

        Notification initial=notification("PersonalCloud peer is starting",true);
        try {
            if(Build.VERSION.SDK_INT>=34) {
                startForeground(31,initial,ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
            } else {
                startForeground(31,initial);
            }
        } catch(RuntimeException error) {
            failStartup(error,startId,false);
            starting.set(false);
            return START_NOT_STICKY;
        }

        new Thread(new Runnable(){public void run(){
            try {
                startNode();
            } catch(Exception error) {
                failStartup(error,startId,true);
            } finally {
                starting.set(false);
            }
        }},"pc-node-start").start();
        return START_STICKY;
    }

    private void startNode()throws Exception{
        AndroidStateStore store=new AndroidStateStore(this);
        String p12=store.getConfig("keystore_path"),password=store.getConfig("keystore_password");
        if(p12.length()==0||password.length()==0)throw new IllegalStateException("Import a TLS identity (.p12) before starting the Android peer.");
        KeyStore keyStore=KeyStore.getInstance("PKCS12");try(FileInputStream in=new FileInputStream(p12)){keyStore.load(in,password.toCharArray());}
        InetAddress certificateAddress=certificateAddressWhenAvailable(keyStore);
        KeyManagerFactory kmf=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());kmf.init(keyStore,password.toCharArray());SSLContext context=SSLContext.getInstance("TLS");context.init(kmf.getKeyManagers(),null,null);
        String nodeId=store.getConfig("node_id");if(nodeId.length()==0){nodeId=UUID.randomUUID().toString();store.putConfig("node_id",nodeId);}
        String name=store.getConfig("node_name");if(name.length()==0)name="PersonalCloud-Android";
        String selectedStorageId=store.getConfig(AndroidManagedStorageLocations.CONFIG_KEY);
        if(selectedStorageId==null||selectedStorageId.isBlank())selectedStorageId=AndroidManagedStorageLocations.APP_PRIVATE_ID;
        ManagedStorageBackend managedBackend=null;
        Path managedRoot=null;
        if(selectedStorageId.startsWith("saf:")){
            managedBackend=new AndroidSafManagedStorageBackend(this,
                    store.getConfig(AndroidSafManagedStorageBackend.TREE_URI_CONFIG_KEY),selectedStorageId);
        }else{
            managedRoot=AndroidManagedStorageLocations.resolveManagedRoot(this,selectedStorageId);
        }
        Path root=java.nio.file.Paths.get(getFilesDir().getAbsolutePath(),"node-storage");
        PeerNode node=new PeerNode(nodeId,name,root,managedRoot,selectedStorageId,managedBackend,store,new PeerNode.Events(){public void onStateChanged(String message){PeerRuntime.lastStatus=message;}});
        ExternalReferenceStore externalReferences = AndroidStorageRuntime.references(this);
        node.configureExternalReferenceStore(externalReferences);
        NetworkMembershipClient membership=null;
        if(Build.VERSION.SDK_INT>=33){
            String endpoint=PeerEndpointResolver.httpsEndpoint(certificateAddress,8879);
            membership=new NetworkMembershipClient(store,nodeId,name,endpoint);
            membership.updateLocalEndpoint(endpoint);
            networkEndpointValid=true;
            node.configureNetworkMembership(membership);
        }
        node.start(InetAddress.getByName("0.0.0.0"),8879,context.getServerSocketFactory());
        PeerRuntime.node=node;
        PeerRuntime.membership=membership;
        if(membership!=null){
            registerNetworkMonitor(keyStore,membership);
            OutboundTransferQueue queue = createOutboundTransferQueue(store, membership);
            PeerRuntime.outboundTransfers = queue;
            startCatalogueSynchronization(membership,store);
            startOutboundTransferRecovery(queue);
        }
        PeerRuntime.lastStatus=(Build.VERSION.SDK_INT>=33?"Running HTTPS and private-network membership on port 8879":"Running legacy peer on port 8879; private-network membership requires Android 13 or newer") + "; managed placement volume=" + selectedStorageId;
    }
    private OutboundTransferQueue createOutboundTransferQueue(AndroidStateStore store,
                                                                  NetworkMembershipClient membership) {
        return new OutboundTransferQueue(store,
                memberId -> NetworkPeerConnector.activeEndpoint(membership, memberId),
                locator -> () -> getContentResolver().openInputStream(Uri.parse(locator)),
                new OutboundTransferQueue.TransferTransport() {
                    private String trustedCa() throws Exception { return store.getConfig("peer_ca"); }
                    @Override public Map<String,Object> create(String endpoint, String transferId,
                            String destinationPath, long size, String sha256) throws Exception {
                        return NetworkPeerConnector.createManagedTransfer(endpoint, transferId,
                                destinationPath, size, sha256, membership, trustedCa());
                    }
                    @Override public Map<String,Object> resume(String endpoint, String transferId,
                            dev.personalcloud.android.core.PeerConnector.InputStreamSource source,
                            long size) throws Exception {
                        return NetworkPeerConnector.resumeManagedFile(endpoint, transferId, source,
                                size, membership, trustedCa(), NetworkStorageService.MAX_MANAGED_FILE_BYTES);
                    }
                    @Override public Map<String,Object> status(String endpoint, String transferId) throws Exception {
                        return NetworkPeerConnector.transferStatus(endpoint, transferId, membership, trustedCa());
                    }
                    @Override public Map<String,Object> abort(String endpoint, String transferId) throws Exception {
                        return NetworkPeerConnector.abortTransfer(endpoint, transferId, membership, trustedCa());
                    }
                }, NetworkStorageService.MAX_MANAGED_FILE_BYTES);
    }

    private void startOutboundTransferRecovery(final OutboundTransferQueue queue) {
        if (outboundTransferScheduler != null) outboundTransferScheduler.shutdownNow();
        outboundTransferScheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "personalcloud-android-transfer-recovery");
            thread.setDaemon(true);
            return thread;
        });
        outboundTransferScheduler.scheduleWithFixedDelay(() -> {
            try {
                int attempted = queue.retryDue();
                cleanupUnusedTransferPermissions(queue);
                if (attempted > 0) PeerRuntime.lastStatus = "Peer service running; resumed "
                        + attempted + " pending outbound transfer job(s).";
            } catch (Exception error) {
                Log.w(TAG, "Outbound transfer recovery pass failed.", error);
            }
        }, 10, 30, TimeUnit.SECONDS);
    }

    private void cleanupUnusedTransferPermissions(OutboundTransferQueue queue) throws Exception {
        AndroidSafReferenceStore references = AndroidStorageRuntime.references(this);
        String managedTree = new AndroidStateStore(this).getConfig(AndroidSafManagedStorageBackend.TREE_URI_CONFIG_KEY);
        for (UriPermission permission : getContentResolver().getPersistedUriPermissions()) {
            Uri uri = permission.getUri();
            if (uri.toString().equals(managedTree) || queue.hasActiveSource(uri.toString())) continue;
            int flags = 0;
            if (permission.isReadPermission()) flags |= Intent.FLAG_GRANT_READ_URI_PERMISSION;
            if (permission.isWritePermission()) flags |= Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
            if (flags != 0) references.releasePersistedPermissionIfUnused(uri.toString(), flags);
        }
    }

    private InetAddress certificateAddress(KeyStore keyStore)throws Exception{
        X509Certificate certificate=serverCertificate(keyStore);
        List<byte[]> sans=certificateIpv4Sans(certificate);
        return PeerEndpointResolver.selectIpv4Address(currentNetworkAddresses(null),sans);
    }

    private X509Certificate serverCertificate(KeyStore keyStore)throws Exception{
        Enumeration<String> aliases=keyStore.aliases();
        while(aliases.hasMoreElements()){
            String alias=aliases.nextElement();
            if(keyStore.isKeyEntry(alias)){
                java.security.cert.Certificate cert=keyStore.getCertificate(alias);
                if(cert instanceof X509Certificate)return (X509Certificate)cert;
            }
        }
        throw new IllegalStateException("The PKCS#12 identity contains no X.509 server certificate.");
    }

    private List<byte[]> certificateIpv4Sans(X509Certificate certificate)throws Exception{
        List<byte[]> result=new ArrayList<byte[]>();
        Collection<List<?>> sans=certificate.getSubjectAlternativeNames();
        if(sans!=null)for(List<?> san:sans){
            if(san.size()>1&&Integer.valueOf(7).equals(san.get(0))){
                byte[] parsed=PeerEndpointResolver.parseIpv4San(san.get(1));
                if(parsed!=null)result.add(parsed);
            }
        }
        return result;
    }

    private List<InetAddress> currentNetworkAddresses(LinkProperties supplied){
        List<InetAddress> result=new ArrayList<InetAddress>();
        LinkProperties properties=supplied;
        ConnectivityManager manager=getSystemService(ConnectivityManager.class);
        if(properties==null&&manager!=null){
            Network active=manager.getActiveNetwork();
            if(active!=null)properties=manager.getLinkProperties(active);
        }
        if(properties!=null){
            for(LinkAddress link:properties.getLinkAddresses())result.add(link.getAddress());
        }
        if(!result.isEmpty())return result;

        try{
            Enumeration<NetworkInterface> interfaces=NetworkInterface.getNetworkInterfaces();
            while(interfaces!=null&&interfaces.hasMoreElements()){
                NetworkInterface network=interfaces.nextElement();
                if(!network.isUp()||network.isLoopback())continue;
                Enumeration<InetAddress> addresses=network.getInetAddresses();
                while(addresses.hasMoreElements())result.add(addresses.nextElement());
            }
        }catch(Exception error){Log.w(TAG,"Could not enumerate active network addresses.",error);}
        return result;
    }

    private InetAddress certificateAddressWhenAvailable(KeyStore keyStore)throws Exception{
        long deadline=SystemClock.elapsedRealtime()+TimeUnit.SECONDS.toMillis(90);
        long nextNotification=0L;
        while(true){
            try {
                return certificateAddress(keyStore);
            } catch(IllegalStateException error) {
                String message=error.getMessage();
                if(message==null || !message.startsWith("No active Wi-Fi IPv4 address matches")) {
                    throw error;
                }
                long now=SystemClock.elapsedRealtime();
                PeerRuntime.lastStatus="Waiting for an active phone IPv4 address covered by the TLS certificate...";
                if(now>=nextNotification){
                    getSystemService(NotificationManager.class).notify(31,notification(PeerRuntime.lastStatus,true));
                    nextNotification=now+TimeUnit.SECONDS.toMillis(10);
                }
                if(now>=deadline){
                    throw new IllegalStateException(message+" Network readiness timed out after 90 seconds.",error);
                }
                Thread.sleep(2000L);
            }
        }
    }

    private void registerNetworkMonitor(final KeyStore keyStore,final NetworkMembershipClient membership){
        if(Build.VERSION.SDK_INT<24)return;
        ConnectivityManager manager=getSystemService(ConnectivityManager.class);
        if(manager==null){PeerRuntime.lastStatus="Peer service running; network-change monitoring is unavailable.";return;}
        connectivityManager=manager;
        networkChangeExecutor=Executors.newSingleThreadExecutor(task->{
            Thread thread=new Thread(task,"personalcloud-android-network-monitor");
            thread.setDaemon(true);
            return thread;
        });
        networkCallback=new ConnectivityManager.NetworkCallback(){
            @Override public void onAvailable(Network network){scheduleEndpointRefresh(keyStore,membership,null);}
            @Override public void onLinkPropertiesChanged(Network network,LinkProperties properties){
                scheduleEndpointRefresh(keyStore,membership,properties);
            }
            @Override public void onLost(Network network){
                Network active=manager.getActiveNetwork();
                if(active==null){
                    networkEndpointValid=false;
                    PeerRuntime.lastStatus="Peer service running; active network lost, waiting for network recovery.";
                }else if(!active.equals(network)){
                    scheduleEndpointRefresh(keyStore,membership,manager.getLinkProperties(active));
                }
            }
        };
        try{
            manager.registerDefaultNetworkCallback(networkCallback);
            scheduleEndpointRefresh(keyStore,membership,null);
        }catch(RuntimeException error){
            networkCallback=null;
            ExecutorService executor=networkChangeExecutor;
            networkChangeExecutor=null;
            if(executor!=null)executor.shutdownNow();
            PeerRuntime.lastStatus="Peer service running; network-change monitoring could not start: "+error.getClass().getSimpleName();
            Log.w(TAG,PeerRuntime.lastStatus,error);
        }
    }

    private void scheduleEndpointRefresh(final KeyStore keyStore,final NetworkMembershipClient membership,
                                         final LinkProperties properties){
        ExecutorService executor=networkChangeExecutor;
        if(executor==null||executor.isShutdown()||!networkRefreshQueued.compareAndSet(false,true))return;
        try{
            executor.execute(()->{
                try{
                    InetAddress address;
                    try{
                        address=PeerEndpointResolver.selectIpv4Address(
                                currentNetworkAddresses(properties),certificateIpv4Sans(serverCertificate(keyStore)));
                    }catch(IllegalStateException noCoveredAddress){
                        networkEndpointValid=false;
                        PeerRuntime.lastStatus="Peer service running; network changed but no active IPv4 address is covered by the TLS certificate. Membership sync is paused until the Android TLS identity is renewed.";
                        Log.w(TAG,PeerRuntime.lastStatus,noCoveredAddress);
                        return;
                    }
                    String endpoint=PeerEndpointResolver.httpsEndpoint(address,8879);
                    Map<String,Object> result=membership.updateLocalEndpoint(endpoint);
                    networkEndpointValid=true;
                    if(Boolean.TRUE.equals(result.get("changed"))){
                        PeerRuntime.lastStatus="Peer service running; network endpoint refreshed to "+endpoint;
                        Log.i(TAG,"Updated advertised endpoint after network change: "+endpoint);
                    }
                }catch(Exception error){
                    PeerRuntime.lastStatus="Peer service running; could not persist the new network endpoint: "+error.getClass().getSimpleName();
                    Log.e(TAG,PeerRuntime.lastStatus,error);
                }finally{networkRefreshQueued.set(false);}
            });
        }catch(RuntimeException rejected){networkRefreshQueued.set(false);}
    }

    private void failStartup(final Exception error,final int startId,final boolean foregroundReady){
        startupFailed=true;
        String detail=error.getMessage();
        if(detail==null || detail.isBlank()) detail=error.getClass().getSimpleName();
        PeerRuntime.lastStatus="Start failed: "+detail;
        Log.e(TAG,PeerRuntime.lastStatus,error);

        new Handler(Looper.getMainLooper()).post(()->{
            if(foregroundReady){
                try {
                    getSystemService(NotificationManager.class)
                            .notify(31,notification(PeerRuntime.lastStatus,false));
                    keepFailureNotification=true;
                    stopForeground(false);
                } catch(RuntimeException notificationError) {
                    Log.e(TAG,"Could not publish startup failure notification.",notificationError);
                    keepFailureNotification=false;
                    stopForeground(true);
                }
            } else {
                keepFailureNotification=false;
                stopForeground(true);
            }
            stopSelf(startId);
        });
    }

    private void startCatalogueSynchronization(final NetworkMembershipClient membership, final AndroidStateStore store){
        if(catalogueScheduler!=null) catalogueScheduler.shutdownNow();
        catalogueScheduler=Executors.newSingleThreadScheduledExecutor(task->{Thread thread=new Thread(task,"personalcloud-android-catalogue");thread.setDaemon(true);return thread;});
        catalogueScheduler.scheduleWithFixedDelay(()->{
            try{
                if(!Boolean.TRUE.equals(membership.status().get("joined"))) return;
                if(!networkEndpointValid){
                    PeerRuntime.lastStatus="Peer service running; membership sync paused because no active IPv4 address is covered by the TLS certificate.";
                    return;
                }
                String trustedCa=store.getConfig("peer_ca");
                Map<String,Object> result=membership.synchronizeOnce(trustedCa);
                PeerRuntime.lastStatus="Peer service running; network catalogue checked "
                        +String.valueOf(result.getOrDefault("syncedAt",""))
                        +"; online="+String.valueOf(result.getOrDefault("online",java.util.List.of()));
            }catch(Exception error){
                PeerRuntime.lastStatus="Peer service running; catalogue sync failed: "
                        +(error.getMessage()==null?error.getClass().getSimpleName():error.getMessage());
            }
        },5,20,TimeUnit.SECONDS);
    }

    @Override public void onDestroy(){
        ConnectivityManager manager=connectivityManager;
        ConnectivityManager.NetworkCallback callback=networkCallback;
        connectivityManager=null;
        networkCallback=null;
        if(manager!=null&&callback!=null){try{manager.unregisterNetworkCallback(callback);}catch(RuntimeException error){Log.w(TAG,"Could not unregister network callback.",error);}}
        ExecutorService networkExecutor=networkChangeExecutor;
        networkChangeExecutor=null;
        if(networkExecutor!=null)networkExecutor.shutdownNow();
        networkRefreshQueued.set(false);
        networkEndpointValid=false;
        if(catalogueScheduler!=null){catalogueScheduler.shutdownNow();catalogueScheduler=null;}
        if(outboundTransferScheduler!=null){outboundTransferScheduler.shutdownNow();outboundTransferScheduler=null;}
        PeerNode n=PeerRuntime.node;
        if(n!=null)n.close();
        PeerRuntime.node=null;
        PeerRuntime.membership=null;
        PeerRuntime.outboundTransfers=null;
        if(!startupFailed){
            PeerRuntime.lastStatus="Node stopped";
            stopForeground(true);
        } else if(!keepFailureNotification) {
            stopForeground(true);
        }
        super.onDestroy();
    }
    @Override public IBinder onBind(Intent intent){return null;}
    private void createChannel(){NotificationChannel c=new NotificationChannel(CHANNEL,"PersonalCloud peer",NotificationManager.IMPORTANCE_LOW);getSystemService(NotificationManager.class).createNotificationChannel(c);}
    private Notification notification(String text){
        return notification(text,true);
    }
    private Notification notification(String text,boolean ongoing){
        return new Notification.Builder(this,CHANNEL)
                .setContentTitle("PersonalCloud")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setOngoing(ongoing)
                .build();
    }
}
