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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Request;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.ExecCreateParam;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;
import org.mandas.docker.client.messages.ContainerInfo;
import org.mandas.docker.client.messages.HostConfig;
import org.mandas.docker.client.messages.Volume;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The launcher against the real Docker daemon: the worker it starts is the measured one,
 * field by field as the daemon records it, and nothing of an attempt survives disposal.
 * `make test` builds the worker and gateway images from images/ first.
 */
public class DockerWorkerLauncherTest {

    private static final String WORKER = "skald-buildkit-worker:test";
    private static final String GATEWAY = "skald-egress-gateway:test";
    private static DockerClient docker;
    private static DockerWorkerLauncher launcher;

    @BeforeAll
    public static void connect() throws Exception {
        docker = new JerseyDockerClientBuilder().fromEnv().build();
        for (String image : List.of(WORKER, GATEWAY, Images.HELPER, Images.SETUP)) {
            assertNotNull(docker.inspectImage(image), image + " is missing; run `make test`");
        }
        launcher = new DockerWorkerLauncher(docker, WorkerProfile.load("runc-rootless"),
                Images.of(WORKER, GATEWAY));
    }

    @AfterAll
    public static void close() {
        if (docker != null) {
            docker.close();
        }
    }

    private static Request request(String attempt) {
        return new Request(attempt, Settings.defaults(), 256,
                new Egress(List.of(), "registry", List.of("pypi.org"), List.of("forge"), List.of(), List.of()));
    }

    private static String attempt() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    @Test
    public void theLaunchedWorkerIsTheMeasuredOneAndDisposalLeavesNothing() throws Exception {
        String id = attempt();
        Handle h = launcher.launch(request(id));
        try {
            ContainerInfo worker = docker.inspectContainer(h.worker());
            assertTrue(worker.state().running(), "the worker is running");
            HostConfig hc = worker.hostConfig();
            // The record of what the docker CLI set for the profile at these values
            // (18553b8 N2: Privileged and CapAdd included).
            JsonNode rec = new ObjectMapper().readTree(Path.of("dev/fixtures/worker/cli-hostconfig.json").toFile())
                    .path("host_config");
            assertEquals(rec.path("NanoCpus").asLong(), hc.nanoCpus());
            assertEquals(rec.path("Memory").asLong(), hc.memory());
            assertEquals(rec.path("MemorySwap").asLong(), hc.memorySwap());
            assertEquals(rec.path("PidsLimit").asInt(), hc.pidsLimit());
            assertEquals(rec.path("ReadonlyRootfs").asBoolean(), hc.readonlyRootfs());
            assertEquals(Map.of("/tmp", rec.path("Tmpfs").path("/tmp").asText()), hc.tmpfs());
            assertFalse(Boolean.TRUE.equals(hc.privileged()), "not privileged");
            assertTrue(hc.capAdd() == null || hc.capAdd().isEmpty(), "no capability added");
            assertEquals(List.of(rec.path("SecurityOpt").get(0).asText()), hc.securityOpt().stream()
                    .map(o -> o.startsWith("seccomp=") ? "seccomp=sha256:" + sha256(o.substring(8)) : o).toList());
            assertEquals(h.network(), hc.networkMode());
            assertEquals(List.of(h.workspaceVolume() + ":/workspace", h.socketVolume() + ":/skald-sock",
                    h.configVolume() + ":/skald-conf:ro"), hc.binds());
            assertTrue(hc.binds().stream().noneMatch(b -> b.contains("docker.sock") || b.startsWith("/")),
                    "no socket and no host path reaches the worker");
            assertEquals("2401:2401", worker.config().user(), "the image's dedicated identity");
            assertTrue(docker.inspectNetwork(h.network()).internal(), "the worker's network is internal");
            assertEquals(1, docker.inspectNetwork(h.network()).containers().size() - 1,
                    "only the worker and the gateway are on it");

            Volume ws = docker.inspectVolume(h.workspaceVolume());
            assertEquals("ext4", ws.options().get("type"));
            assertEquals("nosuid,nodev", ws.options().get("o"));
            assertTrue(ws.options().get("device").startsWith("/dev/loop"));

            // The rule the gateway runs is the one GatewayConfig writes (543ed35 N2's other
            // half: the conf the driver actually mounts).
            // The gateway is hardened (9a2658d N1).
            HostConfig gw = docker.inspectContainer(h.gateway()).hostConfig();
            assertTrue(gw.readonlyRootfs(), "gateway root read-only");
            assertEquals(List.of("ALL"), gw.capDrop());
            assertEquals(List.of("no-new-privileges"), gw.securityOpt());
            assertEquals(DockerWorkerLauncher.GATEWAY_MEMORY, gw.memory());
            assertEquals(DockerWorkerLauncher.GATEWAY_MEMORY, gw.memorySwap());
            assertEquals(128, gw.pidsLimit());
            assertFalse(Boolean.TRUE.equals(gw.privileged()));

            String mounted = exec(h.gateway(), "cat", "/skald-conf/squid.conf");
            assertEquals(GatewayConfig.squidConf("registry", List.of("pypi.org"), List.of("forge")), mounted);
        } finally {
            assertEquals(List.of(), launcher.dispose(h), "everything the attempt owned is gone");
        }
        assertEquals(List.of(), launcher.leftovers(h));
        assertEquals(List.of(), launcher.dispose(h), "disposal is idempotent");
    }

    @Test
    public void aLaunchThatFailsPartWayLeavesNothing() throws Exception {
        String id = attempt();
        DockerWorkerLauncher broken = new DockerWorkerLauncher(docker, WorkerProfile.load("runc-rootless"),
                Images.of(WORKER, "skald-egress-gateway:no-such-tag"));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> broken.launch(request(id)));
        assertFalse(e.getMessage().contains("LEFT BEHIND"), e.getMessage());
        assertEquals(List.of(), launcher.leftovers(DockerWorkerLauncher.handle(id)));
    }

    @Test
    public void aLaunchRefusesToAdoptAVolumeItDidNotMake() throws Exception {
        // 9a2658d-F1's repro: a volume already holding the workspace's name, here a 1 MiB
        // tmpfs with no labels. Docker's volume create would have returned it as is.
        for (String role : List.of("ws", "conf", "ctx")) {
            String id = attempt();
            Handle h = DockerWorkerLauncher.handle(id);
            String name = switch (role) {
                case "ws" -> h.workspaceVolume();
                case "conf" -> h.configVolume();
                default -> h.contextVolume();
            };
            docker.createVolume(Volume.builder().name(name).driver("local")
                    .driverOpts(Map.of("type", "tmpfs", "device", "tmpfs", "o", "size=1m")).build());
            try {
                IllegalStateException e = assertThrows(IllegalStateException.class,
                        () -> launcher.launch(request(id)));
                assertTrue(e.getMessage().contains("already taken"), e.getMessage());
                // Not ours, so not removed, and not changed.
                assertEquals("tmpfs", docker.inspectVolume(name).options().get("type"));
                assertEquals(List.of(), launcher.leftovers(h), "nothing of the attempt was made");
            } finally {
                docker.removeVolume(name);
            }
        }
    }

    @Test
    public void aRefusedRelaunchLeavesTheLiveLaunchRunning() throws Exception {
        // 67b7c17-F1: the same attempt launched twice. The second launch refuses, and its
        // refusal must not dispose of the first, whose objects carry the same label.
        String id = attempt();
        Handle first = launcher.launch(request(id));
        try {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> launcher.launch(request(id)));
            assertTrue(e.getMessage().contains("already taken"), e.getMessage());
            assertTrue(docker.inspectContainer(first.worker()).state().running(),
                    "the first launch's worker still runs");
            assertTrue(docker.inspectContainer(first.gateway()).state().running(),
                    "and its gateway");
            assertTrue(docker.inspectVolume(first.workspaceVolume()).options().get("device")
                    .startsWith("/dev/loop"), "and its workspace, still on its loop device");
        } finally {
            assertEquals(List.of(), launcher.dispose(first));
        }
    }

    @Test
    public void aVolumeTakenBetweenTheCheckAndTheCreateIsNotAdopted() throws Exception {
        // The upfront name check refuses first in every launch, so the re-check after
        // create (the race guard) is exercised on its own here: the name is taken, as it
        // would be by a create racing this launch's.
        String id = attempt();
        String name = DockerWorkerLauncher.handle(id).configVolume();
        Map<String, String> labels = Map.of(DockerWorkerLauncher.ATTEMPT_LABEL, id);
        docker.createVolume(Volume.builder().name(name).build());
        try {
            assertThrows(IllegalStateException.class, () -> launcher.createOwnedVolume(name, labels, null),
                    "an unlabelled volume of the name is not this launch's");
        } finally {
            docker.removeVolume(name);
        }
        docker.createVolume(Volume.builder().name(name).labels(labels).driver("local")
                .driverOpts(Map.of("type", "tmpfs", "device", "tmpfs", "o", "size=1m")).build());
        try {
            assertThrows(IllegalStateException.class, () -> launcher.createOwnedVolume(name, labels,
                    Map.of("type", "ext4", "device", "/dev/loop9", "o", "nosuid,nodev")),
                    "our label but other options is still not the volume asked for");
        } finally {
            docker.removeVolume(name);
        }
    }

    @Test
    public void disposalDetachesTheQuotaDeviceEvenWithNoVolumeToNameIt() throws Exception {
        // 9a2658d-F2: a launch that stopped after losetup and before the workspace volume
        // existed (a platform crash; reconciliation then disposes by attempt id). The image
        // is attached exactly as makeWorkspace attaches it, and no volume records the device.
        String id = attempt();
        Handle h = DockerWorkerLauncher.handle(id);
        String image = h.quotaImage();
        String setup = docker.createContainer(org.mandas.docker.client.messages.ContainerConfig.builder()
                .image(Images.SETUP).labels(Map.of(DockerWorkerLauncher.ATTEMPT_LABEL, id))
                .cmd("sh", "-c", "truncate -s 64M /s/" + image + " && mkfs.ext4 -q -F /s/" + image
                        + " && losetup --find --show /s/" + image)
                .hostConfig(HostConfig.builder().privileged(true).networkMode("none")
                        .binds(DockerWorkerLauncher.QUOTA_IMAGES_VOLUME + ":/s").build()).build()).id();
        docker.startContainer(setup);
        assertEquals(0L, docker.waitContainer(setup).statusCode());
        docker.removeContainer(setup);
        List<String> before = launcher.leftovers(h);
        assertTrue(before.stream().anyMatch(l -> l.startsWith("quota /sys/block/loop")),
                "the device is attached before disposal: " + before);
        assertEquals(List.of(), launcher.dispose(h));
        assertEquals(List.of(), launcher.leftovers(h));
    }

    @Test
    public void theLeftoverCheckSeesWhatIsLeft() throws Exception {
        // A check that reports nothing whatever exists would make the two tests above
        // vacuous; a labelled volume made by hand must be reported.
        String id = attempt();
        Handle h = DockerWorkerLauncher.handle(id);
        docker.createVolume(Volume.builder().name(h.socketVolume())
                .labels(Map.of(DockerWorkerLauncher.ATTEMPT_LABEL, id)).build());
        try {
            assertEquals(List.of("volume " + h.socketVolume()), launcher.leftovers(h));
        } finally {
            docker.removeVolume(h.socketVolume());
        }
    }

    private static String exec(String container, String... cmd) throws Exception {
        String id = docker.execCreate(container, cmd, ExecCreateParam.attachStdout(),
                ExecCreateParam.attachStderr()).id();
        try (var out = docker.execStart(id)) {
            return out.readFully();
        }
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
