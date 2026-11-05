package dev.personalcloud.runtime;

import dev.personalcloud.control.LocalControlServer;
import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.protocol.PeerProtocolServer;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.network.NetworkMembershipService;
import dev.personalcloud.network.DeviceCatalogueService;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceVersionService;
import dev.personalcloud.storage.ManagedStorageService;

/** Owns the lifecycle and dependency graph of one PersonalCloud node. */
public final class PersonalCloudNode implements AutoCloseable {
    private final AppConfig config;
    private final StateStore state;
    private final FileService files;
    private final PeerService peers;
    private final VersionService versions;
    private final GrantService grants;
    private final ReferenceStorageService references;
    private final NetworkMembershipService membership;
    private final DeviceCatalogueService catalogue;
    private final ReferenceGrantService referenceGrants;
    private final ReferenceVersionService referenceVersions;
    private final ManagedStorageService managedStorage;
    private final PeerProtocolServer protocol;
    private final LocalControlServer localControl;
    private boolean started;

    public PersonalCloudNode(AppConfig config) throws Exception {
        this.config = config;
        this.state = new StateStore(config.dataDirectory());
        this.files = new FileService(config.storageRoot());
        this.peers = new PeerService(state, config);
        this.versions = new VersionService(config.dataDirectory(), files);
        this.grants = new GrantService(state, files, peers, versions, config.maxFileBytes());
        this.references = new ReferenceStorageService(state, config.dataDirectory(), files.root());
        this.membership = new NetworkMembershipService(state, config);
        this.catalogue = new DeviceCatalogueService(config, membership);
        this.referenceGrants = new ReferenceGrantService(state, references, membership);
        this.referenceVersions = new ReferenceVersionService(config.dataDirectory(), references);
        this.managedStorage = new ManagedStorageService(state, config);
        this.protocol = new PeerProtocolServer(config, files, peers, grants, new AuditLog(config.dataDirectory()),
                membership, references, referenceGrants, referenceVersions, managedStorage);
        this.localControl = new LocalControlServer(config.dataDirectory(), config.nodeId(), config.nodeName(), references,
                config, peers, grants, membership, catalogue, referenceGrants, referenceVersions, managedStorage);
    }

    public synchronized void start() throws Exception {
        if (started) throw new IllegalStateException("PersonalCloud node is already started.");
        // Persist the endpoint that this process will actually bind before either
        // the peer API or the local control socket starts serving member data.
        membership.reconcileLocalEndpoint();
        localControl.start();
        try {
            protocol.start();
            catalogue.start();
            started = true;
        } catch (Exception failure) {
            localControl.close();
            files.close();
            throw failure;
        }
    }

    public AppConfig config() { return config; }
    public java.nio.file.Path controlSocket() { return localControl.socketPath(); }

    @Override public synchronized void close() {
        catalogue.close();
        protocol.close();
        localControl.close();
        files.close();
        started = false;
    }
}
