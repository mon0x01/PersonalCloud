package dev.personalcloud;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.web.PersonalCloudServer;

public final class PersonalCloudApplication {
    public static void main(String[] args) throws Exception {
        AppConfig config = AppConfig.load();
        StateStore store = new StateStore(config.dataDirectory());
        FileService files = new FileService(config.storageRoot());
        PeerService peers = new PeerService(store, config);
        GrantService grants = new GrantService(store, files, peers);
        PersonalCloudServer server = new PersonalCloudServer(config, store, files, peers, grants);
        server.start();

        System.out.println();
        System.out.println("PersonalCloud node is running");
        System.out.println("--------------------------------");
        System.out.println("Device       : " + config.nodeName());
        System.out.println("Node ID      : " + config.nodeId());
        System.out.println("Dashboard    : http://localhost:" + config.port());
        System.out.println("Bind address : " + config.bindAddress());
        System.out.println("Storage root : " + files.root());
        System.out.println("Username     : admin");
        if (config.adminPasswordGenerated()) {
            System.out.println("First-run password: " + config.adminPassword());
            System.out.println("Save this password now. It is stored in the protected data directory.");
        } else {
            System.out.println("Password     : stored in " + config.dataDirectory().resolve("admin-password.txt"));
        }
        System.out.println();
        System.out.println("Security: use on a trusted LAN or VPN only. This build does not provide HTTPS.");
        System.out.println("Press Ctrl+C to stop.");
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
