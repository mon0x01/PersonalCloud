package dev.personalcloud;

import dev.personalcloud.cli.PersonalCloudCli;
import dev.personalcloud.core.AppConfig;
import dev.personalcloud.runtime.PersonalCloudNode;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

/** Headless entry point. PersonalCloud is a node service, not a browser dashboard. */
public final class PersonalCloudApplication {
    private PersonalCloudApplication() { }

    public static void main(String[] args) throws Exception {
        if (args != null && args.length > 0 && "local".equals(args[0])) {
            PersonalCloudCli.run(Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        if (args != null && args.length > 0 && ("help".equals(args[0]) || "--help".equals(args[0]))) {
            printUsage();
            return;
        }

        AppConfig config = AppConfig.load();
        PersonalCloudNode node = new PersonalCloudNode(config);
        node.start();
        Runtime.getRuntime().addShutdownHook(new Thread(node::close, "personalcloud-shutdown"));

        String scheme = config.tlsKeystore() == null ? "http" : "https";
        System.out.println();
        System.out.println("PersonalCloud node is running");
        System.out.println("--------------------------------");
        System.out.println("Device        : " + config.nodeName());
        System.out.println("Node ID       : " + config.nodeId());
        System.out.println("Peer endpoint : " + scheme + "://" + config.bindAddress() + ":" + config.port());
        System.out.println("Managed files : " + config.storageRoot());
        System.out.println("Local control : " + node.controlSocket());
        System.out.println("Interface     : OS-native integration / Java local CLI");
        System.out.println("Browser UI    : not included in this scoped build");
        System.out.println("Press Ctrl+C to stop.");

        new CountDownLatch(1).await();
    }

    private static void printUsage() {
        System.out.println("PersonalCloud node service\n"
                + "  java -jar build/personalcloud.jar                 Start this device as a node\n"
                + "  java -jar build/personalcloud.jar local help      Local Java control CLI\n"
                + "\nThe peer endpoint serves only the PersonalCloud peer protocol.\n"
                + "The local CLI communicates through an owner-only Unix-domain socket.");
    }
}
