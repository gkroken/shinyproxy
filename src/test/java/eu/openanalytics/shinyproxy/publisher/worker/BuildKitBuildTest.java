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

import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Recipe;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Push;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Request;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.LogsParam;
import org.mandas.docker.client.DockerClient.RemoveContainerParam;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;
import org.mandas.docker.client.messages.ContainerConfig;
import org.mandas.docker.client.messages.HostConfig;
import org.mandas.docker.client.messages.RegistryAuth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A real build through the shipped launcher and the client: the context staged through a
 * volume, buildctl in its own container, the push through the gateway with a credential
 * only the client holds, and the digest the client reports pulled back from the registry.
 * `make test` builds the worker and gateway images first.
 */
public class BuildKitBuildTest {

    private static final String WORKER = "skald-buildkit-worker:test";
    private static final String GATEWAY = "skald-egress-gateway:test";
    private static final int REGISTRY_PORT = 15031;
    private static final String SECRET_A = TestRegistry.SECRET_A;
    private static final String SECRET_B = TestRegistry.SECRET_B;
    private static final Credential CRED = TestRegistry.CRED;
    private static TestRegistry registry;
    private static DockerClient docker;
    private static DockerWorkerLauncher launcher;
    private static BuildKitClient client;

    @BeforeAll
    public static void start() throws Exception {
        docker = new JerseyDockerClientBuilder().fromEnv().build();
        for (String image : List.of(WORKER, GATEWAY, Images.HELPER, Images.SETUP, TestRegistry.IMAGE)) {
            assertNotNull(docker.inspectImage(image), image + " is missing; run `make test`");
        }
        Images images = Images.of(WORKER, GATEWAY);
        launcher = new DockerWorkerLauncher(docker, WorkerProfile.load("runc-rootless"), images);
        client = new BuildKitClient(docker, launcher, images);
        registry = new TestRegistry(docker, "skald-bkt", REGISTRY_PORT);
    }

    @AfterAll
    public static void stop() throws Exception {
        if (docker != null) {
            try {
                if (registry != null) {
                    registry.close();
                }
            } finally {
                docker.close();
            }
        }
    }

    @Test
    public void aBuildPushesThroughTheGatewayAndReportsTheDigestTheRegistryHolds(@TempDir Path dir) throws Exception {
        Path payload = Files.createDirectories(dir.resolve("payload"));
        Files.writeString(payload.resolve("app.py"), "print('hello')\n");
        Files.createDirectories(payload.resolve("www"));
        Files.writeString(payload.resolve("www/a.txt"), "a\n");
        // Build code's view: its own environment, every process it can see, and every file
        // on its root, for the password AND for config.json's base64 "auth" form (94b4dae
        // N2: a leak of the config file itself). Each count has a planted control (a process
        // and a file that DO hold both), so a probe that cannot see reads 0 and fails: the
        // answer is 0, 1, 1 for each form.
        String authField = java.util.Base64.getEncoder().encodeToString(
                (CRED.username() + ":" + CRED.password()).getBytes(StandardCharsets.UTF_8));
        int half = authField.length() / 2;
        String probe = "P1=" + SECRET_A + "; P2=" + SECRET_B + "; S=\"$P1$P2\"; "
                + "A1=" + authField.substring(0, half) + "; A2=" + authField.substring(half) + "; B=\"$A1$A2\"; "
                + "env SKALD_CTL=\"$S $B\" sleep 120 & CTL=$!; echo \"$S $B\" > /ctl; sleep 2; "
                + "{ for X in \"$S\" \"$B\"; do env | grep -c \"$X\";"
                + " cat /proc/[0-9]*/environ 2>/dev/null | tr '\\0' '\\n' | grep -c \"$X\";"
                + " find / -xdev -type f -exec grep -l \"$X\" {} + 2>/dev/null | grep -c .; done;"
                + " ls -A /app; } > /report 2>&1; kill $CTL; rm -f /ctl; true";
        Recipe recipe = new Recipe("FROM " + registry.base() + "\n"
                + "COPY skald/test.lock /opt/skald/test.lock\n"
                + "COPY app/ /app/\n"
                + "RUN [\"sh\", \"-c\", " + quote(probe) + "]\n",
                Map.of("skald/test.lock", "lock\n".getBytes(StandardCharsets.UTF_8)));
        String attempt = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        UUID buildId = UUID.randomUUID();
        Push push = new Push(registry.name, "content/bkt", buildId, CRED);
        Handle h = launcher.launch(new Request(attempt, Settings.defaults(), 256,
                new Egress(List.of(registry.outer), registry.name, List.of("pypi.org"), List.of(), List.of(), List.of())));
        String pushed;
        try {
            client.stage(h, payload, recipe);
            client.start(h, push);
            long deadline = System.nanoTime() + 900_000_000_000L;
            while (client.exitCode(h).isEmpty()) {
                assertTrue(System.nanoTime() < deadline, "the build finished within 15 minutes");
                Thread.sleep(1000);
            }
            assertEquals(0L, client.exitCode(h).orElseThrow(), client.log(h));
            pushed = client.pushed(h, push);
            assertTrue(pushed.matches(registry.name + ":5000/content/bkt@sha256:[0-9a-f]{64}"), pushed);
            assertTrue(client.log(h).contains("pushing manifest"), "the log is buildctl's progress");

            // The client: no host path, no network, its own unprivileged identity.
            var info = docker.inspectContainer(h.client());
            HostConfig hc = info.hostConfig();
            assertEquals(List.of(h.socketVolume() + ":/skald-sock", h.contextVolume() + ":/c:ro"), hc.binds());
            assertEquals("none", hc.networkMode());
            assertTrue(hc.readonlyRootfs());
            assertEquals(List.of("ALL"), hc.capDrop());
            assertEquals(List.of("no-new-privileges"), hc.securityOpt());
            assertEquals("2401:2401", info.config().user());
            // The worker: no credential in its configuration.
            String worker = docker.inspectContainer(h.worker()).config().toString();
            assertFalse(worker.contains(CRED.password()), "the worker's configuration has no credential");
        } finally {
            assertEquals(List.of(), launcher.dispose(h), "the client and the context volume are disposed too");
        }
        assertEquals(List.of(), launcher.leftovers(h));

        // The registry holds what the client reported, under the ledgered tag too.
        RegistryAuth auth = registry.auth();
        String local = registry.local("content/bkt");
        String digest = pushed.substring(pushed.indexOf('@') + 1);
        docker.pull(local + ":build-" + buildId, auth);
        docker.pull(local + "@" + digest, auth);
        String id = docker.inspectImage(local + "@" + digest).id();
        try {
            assertEquals(id, docker.inspectImage(local + ":build-" + buildId).id(),
                    "the tag resolves to the reported digest");
            String report = run(local + "@" + digest, "cat", "/report");
            assertEquals(List.of("0", "1", "1", "0", "1", "1", "app.py", "www"), report.strip().lines().toList(),
                    "build code saw no credential but its own controls, and /app is the payload alone: "
                            + report);
            assertEquals("lock\n", run(local + "@" + digest, "cat", "/opt/skald/test.lock"));
        } finally {
            docker.removeImage(id, true, false);
        }
    }

    @Test
    public void stagingRefusesAContextVolumeItDidNotMake(@TempDir Path dir) throws Exception {
        // The launch refuses this too (DockerWorkerLauncherTest); stage() checks again, since a
        // stale context of the same attempt would otherwise be built from.
        String attempt = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        Handle h = DockerWorkerLauncher.handle(attempt);
        docker.createVolume(org.mandas.docker.client.messages.Volume.builder().name(h.contextVolume())
                .labels(Map.of(DockerWorkerLauncher.ATTEMPT_LABEL, attempt)).build());
        try {
            IllegalStateException e = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> client.stage(h, Files.createDirectories(dir.resolve("p")), new Recipe("FROM x\n", Map.of())));
            assertTrue(e.getMessage().contains("already taken"), e.getMessage());
            assertFalse(docker.listContainers(DockerClient.ListContainersParam.allContainers()).stream()
                    .anyMatch(c -> c.names().contains("/" + BuildKitClient.stageHelper(h))), "no helper was made");
        } finally {
            docker.removeVolume(h.contextVolume());
        }
    }

    private static String run(String image, String... cmd) throws Exception {
        String name = "skald-bkt-check-" + UUID.randomUUID().toString().substring(0, 8);
        docker.createContainer(ContainerConfig.builder().image(image).cmd(cmd)
                .hostConfig(HostConfig.builder().networkMode("none").build()).build(), name);
        try {
            docker.startContainer(name);
            docker.waitContainer(name);
            try (var logs = docker.logs(name, LogsParam.stdout(), LogsParam.stderr())) {
                return logs.readFully();
            }
        } finally {
            docker.removeContainer(name, RemoveContainerParam.forceKill());
        }
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
