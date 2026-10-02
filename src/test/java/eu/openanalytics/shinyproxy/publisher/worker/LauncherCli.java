/*
 * Skald
 *
 * Copyright (C) 2026 Gard Kroken
 *
 * Built on ShinyProxy, Copyright (C) 2016-2026 Open Analytics NV.
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.shinyproxy.publisher.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Request;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The launcher from the command line, for the RUN-step probes (dev/run_attack_harness.py's
 * Java mode, dev/java_launcher.py): they launch and dispose through THIS code, so the
 * egress, attack and bounds matrices measure the worker and gateway the driver ships
 * (18553b8 N1, 543ed35 N2). Test scope: a probe tool, not part of the platform.
 *
 * <pre>
 * launch  --attempt ID --worker IMAGE --gateway IMAGE --registry HOST --quota-mb N
 *         [--repo HOST]... [--private-mirror HOST]... [--outer-network NAME]...
 *         [--dns IP]... [--add-host NAME:IP]...        prints the handle as JSON
 * dispose --attempt ID --worker IMAGE --gateway IMAGE  prints what was left, exit 1 if any
 * </pre>
 */
public final class LauncherCli {

    private LauncherCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
        }
        Map<String, List<String>> opts = new HashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (!args[i].startsWith("--") || i + 1 >= args.length) {
                usage();
            }
            opts.computeIfAbsent(args[i].substring(2), k -> new ArrayList<>()).add(args[i + 1]);
        }
        ObjectMapper json = new ObjectMapper();
        try (DockerClient docker = new JerseyDockerClientBuilder().fromEnv().build()) {
            DockerWorkerLauncher launcher = new DockerWorkerLauncher(docker,
                    WorkerProfile.load("runc-rootless"), Images.of(one(opts, "worker"), one(opts, "gateway")));
            switch (args[0]) {
                case "launch" -> {
                    Handle h = launcher.launch(new Request(one(opts, "attempt"), Settings.defaults(),
                            Integer.parseInt(one(opts, "quota-mb")),
                            new Egress(all(opts, "outer-network"), one(opts, "registry"), all(opts, "repo"),
                                    all(opts, "private-mirror"), all(opts, "dns"), all(opts, "add-host"))));
                    System.out.println(json.writeValueAsString(h));
                }
                case "dispose" -> {
                    List<String> left = launcher.dispose(DockerWorkerLauncher.handle(one(opts, "attempt")));
                    System.out.println(json.writeValueAsString(left));
                    if (!left.isEmpty()) {
                        System.exit(1);
                    }
                }
                default -> usage();
            }
        }
    }

    private static String one(Map<String, List<String>> opts, String name) {
        List<String> v = opts.get(name);
        if (v == null || v.size() != 1) {
            throw new IllegalArgumentException("--" + name + " exactly once");
        }
        return v.get(0);
    }

    private static List<String> all(Map<String, List<String>> opts, String name) {
        return opts.getOrDefault(name, List.of());
    }

    private static void usage() {
        System.err.println("usage: LauncherCli launch|dispose --attempt ID --worker IMAGE --gateway IMAGE ...");
        System.exit(2);
    }
}
