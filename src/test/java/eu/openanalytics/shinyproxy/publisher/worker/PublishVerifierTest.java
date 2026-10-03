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

import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Claimed;
import eu.openanalytics.shinyproxy.publisher.build.Lease;
import eu.openanalytics.shinyproxy.publisher.storage.BuildLogWriter;
import eu.openanalytics.shinyproxy.publisher.storage.TestObjectStore;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Step 5's verification against a real registry and log store: what passes, and what each refusal says. */
public class PublishVerifierTest {

    private static DockerClient docker;
    private static TestRegistry registry;
    private static TestObjectStore logStore;
    private static BuildLogWriter logs;
    private static String digest;
    private static URI api;

    @BeforeAll
    public static void start() throws Exception {
        docker = new JerseyDockerClientBuilder().fromEnv().build();
        registry = new TestRegistry(docker, "skald-pv", 15033);
        logStore = new TestObjectStore("skald-pv-logs");
        logs = new BuildLogWriter(logStore.store, logStore.bucket);
        api = URI.create("http://localhost:" + registry.port);
        // The digest the registry serves for the seeded base, learned by a HEAD by tag.
        HttpResponse<Void> head = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create(api + "/v2/base/busybox/manifests/1"))
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .header("Accept", "application/vnd.docker.distribution.manifest.v2+json, "
                        + "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, "
                        + "application/vnd.docker.distribution.manifest.list.v2+json")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (TestRegistry.CRED.username() + ":" + TestRegistry.CRED.password()).getBytes(StandardCharsets.UTF_8)))
                .build(), HttpResponse.BodyHandlers.discarding());
        digest = head.headers().firstValue("Docker-Content-Digest").orElseThrow();
    }

    @AfterAll
    public static void stop() throws Exception {
        try {
            if (registry != null) {
                registry.close();
            }
            if (logStore != null) {
                logStore.close();
            }
        } finally {
            if (docker != null) {
                docker.close();
            }
        }
    }

    private static Claimed claimed(long generation) {
        UUID id = UUID.randomUUID();
        return new Claimed(id, UUID.randomUUID(), UUID.randomUUID(), Map.of(), new Lease(id, generation, "test"));
    }

    private static String image(String d) {
        return registry.name + ":5000/base/busybox@" + d;
    }

    /** A finished log for the attempt: one chunk, final.json with this outcome and generation. */
    private static void log(Claimed c, long generation, String outcome) {
        logs.appendChunk(c.contentId(), c.buildId(), 1, "{\"n\":1,\"t\":\"x\"}\n".getBytes(StandardCharsets.UTF_8));
        logs.finalise(c.contentId(), c.buildId(), generation, outcome, false).orElseThrow();
    }

    private static PublishVerifier verifier(Credential cred) {
        return new PublishVerifier(api, cred, logs);
    }

    @Test
    public void aVerifiedPublicationReturnsTheLogCursor() throws Exception {
        Claimed c = claimed(1);
        log(c, 1, "BUILT");
        assertEquals(1, verifier(TestRegistry.CRED).publish(c, image(digest)));
    }

    @Test
    public void everyUnverifiedPublicationIsRefusedWithItsReason() {
        Claimed ok = claimed(1);
        log(ok, 1, "BUILT");
        assertMessage("answered 404", () -> verifier(TestRegistry.CRED).publish(ok, image("sha256:" + "0".repeat(64))));
        assertMessage("answered 401", () -> verifier(new Credential("skald-launcher", "wrong")).publish(ok, image(digest)));
        assertMessage("not a pushed image by digest",
                () -> verifier(TestRegistry.CRED).publish(ok, registry.name + ":5000/base/busybox:1"));
        assertMessage("not a pushed image by digest",
                () -> verifier(TestRegistry.CRED).publish(ok, registry.name + ":5001/base/busybox@" + digest));

        Claimed noLog = claimed(1);
        assertMessage("no final.json", () -> verifier(TestRegistry.CRED).publish(noLog, image(digest)));

        Claimed failedLog = claimed(1);
        log(failedLog, 1, "FAILED:BUILD_FAILED");
        assertMessage("not this attempt's complete BUILT log", () -> verifier(TestRegistry.CRED).publish(failedLog, image(digest)));

        Claimed otherGeneration = claimed(2);
        log(otherGeneration, 1, "BUILT");
        assertMessage("not this attempt's complete BUILT log",
                () -> verifier(TestRegistry.CRED).publish(otherGeneration, image(digest)));

        Claimed gap = claimed(1);
        logs.appendChunk(gap.contentId(), gap.buildId(), 1, "{\"n\":1,\"t\":\"x\"}\n".getBytes(StandardCharsets.UTF_8));
        logs.appendChunk(gap.contentId(), gap.buildId(), 3, "{\"n\":3,\"t\":\"x\"}\n".getBytes(StandardCharsets.UTF_8));
        logs.finalise(gap.contentId(), gap.buildId(), 1, "BUILT", false).orElseThrow();
        assertMessage("not this attempt's complete BUILT log", () -> verifier(TestRegistry.CRED).publish(gap, image(digest)));

        assertThrows(IllegalArgumentException.class, () -> new PublishVerifier(URI.create(api + "/"), TestRegistry.CRED, logs));
    }

    @Test
    public void aRegistryThatServesAnotherDigestOrWantsTokensIsRefused() throws Exception {
        // Neither can be produced by registry:2 (a HEAD by digest serves that digest or 404s;
        // it uses basic authentication), so a stand-in answers: each check has its own case.
        com.sun.net.httpserver.HttpServer fake = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        fake.createContext("/v2/other/", ex -> {
            ex.getResponseHeaders().add("Docker-Content-Digest", "sha256:" + "f".repeat(64));
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        fake.createContext("/v2/tokens/", ex -> {
            ex.getResponseHeaders().add("WWW-Authenticate", "Bearer realm=\"https://auth.example/token\"");
            ex.sendResponseHeaders(401, -1);
            ex.close();
        });
        fake.start();
        try {
            PublishVerifier v = new PublishVerifier(URI.create("http://127.0.0.1:" + fake.getAddress().getPort()),
                    TestRegistry.CRED, logs);
            Claimed c = claimed(1);
            log(c, 1, "BUILT");
            assertMessage("serves other as sha256:ffff", () -> v.publish(c, registry.name + ":5000/other@" + digest));
            assertMessage("wants bearer tokens", () -> v.publish(c, registry.name + ":5000/tokens@" + digest));
        } finally {
            fake.stop(0);
        }
    }

    private interface Call {
        Object run() throws Exception;
    }

    private static void assertMessage(String part, Call call) {
        Exception e = assertThrows(Exception.class, call::run);
        assertTrue(String.valueOf(e.getMessage()).contains(part), part + " in: " + e.getMessage());
    }
}
