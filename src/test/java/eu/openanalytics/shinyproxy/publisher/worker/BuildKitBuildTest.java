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
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.LogsParam;
import org.mandas.docker.client.DockerClient.RemoveContainerParam;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;
import org.mandas.docker.client.exceptions.DockerException;
import org.mandas.docker.client.messages.ContainerConfig;
import org.mandas.docker.client.messages.HostConfig;
import org.mandas.docker.client.messages.NetworkConfig;
import org.mandas.docker.client.messages.PortBinding;
import org.mandas.docker.client.messages.RegistryAuth;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
    /** registry:2, pinned. */
    private static final String REGISTRY_IMAGE = "registry@sha256:"
            + "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373";
    private static final int REGISTRY_PORT = 15031;
    private static final String RUN_ID = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    private static final String OUTER = "skald-bkt-outer-" + RUN_ID;
    private static final String REGISTRY = "skald-bkt-registry-" + RUN_ID;
    // Split in the Dockerfile so the RUN's own command line never holds it whole.
    private static final String SECRET_A = "skaldbktsecret";
    private static final String SECRET_B = "x7q2";
    private static final Credential CRED = new Credential("skald-launcher", SECRET_A + SECRET_B);
    private static DockerClient docker;
    private static DockerWorkerLauncher launcher;
    private static BuildKitClient client;

    @BeforeAll
    public static void start() throws Exception {
        docker = new JerseyDockerClientBuilder().fromEnv().build();
        for (String image : List.of(WORKER, GATEWAY, Images.HELPER, Images.SETUP, REGISTRY_IMAGE)) {
            assertNotNull(docker.inspectImage(image), image + " is missing; run `make test`");
        }
        Images images = Images.of(WORKER, GATEWAY);
        launcher = new DockerWorkerLauncher(docker, WorkerProfile.load("runc-rootless"), images);
        client = new BuildKitClient(docker, launcher, images);
        // The operator's side: a registry that requires the credential to read or write,
        // on a network the gateway joins, and published on the host to seed and check it.
        docker.createNetwork(NetworkConfig.builder().name(OUTER).build());
        String htpasswd = CRED.username() + ":" + new BCryptPasswordEncoder().encode(CRED.password()) + "\n";
        docker.createContainer(ContainerConfig.builder().image(REGISTRY_IMAGE)
                .env("REGISTRY_AUTH=htpasswd", "REGISTRY_AUTH_HTPASSWD_REALM=skald",
                        "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd")
                .exposedPorts("5000/tcp")
                .hostConfig(HostConfig.builder().networkMode(OUTER)
                        .portBindings(Map.of("5000/tcp", List.of(PortBinding.of("127.0.0.1", REGISTRY_PORT))))
                        .build()).build(), REGISTRY);
        docker.copyToContainer(tar("auth/htpasswd", htpasswd), REGISTRY, "/");
        docker.startContainer(REGISTRY);
        RegistryAuth auth = RegistryAuth.builder().username(CRED.username()).password(CRED.password())
                .serverAddress("localhost:" + REGISTRY_PORT).build();
        String base = "localhost:" + REGISTRY_PORT + "/base/busybox:1";
        docker.tag(Images.HELPER, base);
        for (int i = 0; ; i++) {
            try {
                docker.push(base, auth);
                break;
            } catch (DockerException e) {
                if (i >= 20) {
                    throw e;
                }
                Thread.sleep(500);
            }
        }
        docker.removeImage(base);
    }

    @AfterAll
    public static void stop() throws Exception {
        if (docker != null) {
            try {
                docker.removeContainer(REGISTRY, RemoveContainerParam.forceKill(), RemoveContainerParam.removeVolumes());
            } finally {
                docker.removeNetwork(OUTER);
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
        // on its root. Each count has a planted control (a process and a file that DO hold
        // the secret), so a probe that cannot see reads 0 and fails: the answer is 0, 1, 1.
        String probe = "P1=" + SECRET_A + "; P2=" + SECRET_B + "; S=\"$P1$P2\"; "
                + "env SKALD_CTL=\"$S\" sleep 120 & CTL=$!; echo \"$S\" > /ctl; sleep 2; "
                + "{ env | grep -c \"$S\"; cat /proc/[0-9]*/environ 2>/dev/null | tr '\\0' '\\n' | grep -c \"$S\";"
                + " find / -xdev -type f -exec grep -l \"$S\" {} + 2>/dev/null | grep -c .;"
                + " ls -A /app; } > /report 2>&1; kill $CTL; rm -f /ctl; true";
        Recipe recipe = new Recipe("FROM " + REGISTRY + ":5000/base/busybox:1\n"
                + "COPY skald/test.lock /opt/skald/test.lock\n"
                + "COPY app/ /app/\n"
                + "RUN [\"sh\", \"-c\", " + quote(probe) + "]\n",
                Map.of("skald/test.lock", "lock\n".getBytes(StandardCharsets.UTF_8)));
        String attempt = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        UUID buildId = UUID.randomUUID();
        Push push = new Push(REGISTRY, "content/bkt", buildId, CRED);
        Handle h = launcher.launch(new Request(attempt, Settings.defaults(), 256,
                new Egress(List.of(OUTER), REGISTRY, List.of("pypi.org"), List.of(), List.of(), List.of())));
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
            assertTrue(pushed.matches(REGISTRY + ":5000/content/bkt@sha256:[0-9a-f]{64}"), pushed);
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
        RegistryAuth auth = RegistryAuth.builder().username(CRED.username()).password(CRED.password())
                .serverAddress("localhost:" + REGISTRY_PORT).build();
        String local = "localhost:" + REGISTRY_PORT + "/content/bkt";
        String digest = pushed.substring(pushed.indexOf('@') + 1);
        docker.pull(local + ":build-" + buildId, auth);
        docker.pull(local + "@" + digest, auth);
        String id = docker.inspectImage(local + "@" + digest).id();
        try {
            assertEquals(id, docker.inspectImage(local + ":build-" + buildId).id(),
                    "the tag resolves to the reported digest");
            String report = run(local + "@" + digest, "cat", "/report");
            assertEquals(List.of("0", "1", "1", "app.py", "www"), report.strip().lines().toList(),
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

    private static ByteArrayInputStream tar(String name, String body) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (TarArchiveOutputStream t = new TarArchiveOutputStream(out)) {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            TarArchiveEntry e = new TarArchiveEntry(name);
            e.setSize(bytes.length);
            e.setMode(0644);
            t.putArchiveEntry(e);
            t.write(bytes);
            t.closeArchiveEntry();
        }
        return new ByteArrayInputStream(out.toByteArray());
    }
}
