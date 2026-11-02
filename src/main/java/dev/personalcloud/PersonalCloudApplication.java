package dev.personalcloud;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.web.PersonalCloudServer;

public final class PersonalCloudApplication {
    public static void main(String[] args) throws Exception {
        AppConfig config = AppConfig.load();
        StateStore store = new StateStore(config.dataDirectory());
        FileService files = new FileService(config.storageRoot());
        PeerService peers = new PeerService(store, config);
        VersionService versions = new VersionService(config.dataDirectory(), files);
        GrantService grants = new GrantService(store, files, peers, versions, config.maxUploadBytes());
        PersonalCloudServer server = new PersonalCloudServer(config, store, files, peers, grants, versions);
        server.start();

        System.out.println();
        System.out.println("PersonalCloud node is running");
        System.out.println("--------------------------------");
        System.out.println("Device       : " + config.nodeName());
        System.out.println("Node ID      : " + config.nodeId());
        System.out.println("Dashboard    : " + (config.tlsKeystore() == null ? "http" : "https") + "://localhost:" + config.port());
        System.out.println("Bind address : " + config.bindAddress());
        System.out.println("Storage root : " + files.root());
        System.out.println("Username     : admin");
        if (config.adminPasswordGenerated()) {
            System.out.println("First-run password: " + config.firstRunPassword());
            System.out.println("Save this password now. Only a salted password hash is stored on disk.");
        } else {
            System.out.println("Password     : salted hash stored in " + config.dataDirectory().resolve("admin-password.hash"));
        }
        System.out.println();
        System.out.println(config.tlsKeystore() == null
                ? "Security: loopback-only HTTP is active. Configure TLS before network binding."
                : "Security: HTTPS is active. Use a trusted certificate and protect the keystore password.");
        System.out.println("Press Ctrl+C to stop.");
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
