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
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The client's inputs, without Docker: the names it pushes to and the context it stages. */
public class BuildKitClientTest {

    private static final Credential CRED = new Credential("skald", "s3cret");
    private static final UUID BUILD = UUID.fromString("00000000-0000-0000-0000-000000000007");

    @Test
    public void thePushNameIsTheLedgeredTagAndCannotCarryAnOutputOption() {
        Push push = new Push("registry", "content/abc", BUILD, CRED);
        assertEquals("registry:5000/content/abc:build-" + BUILD, push.name());
        assertEquals("registry:5000/content/abc@sha256:" + "0".repeat(64),
                push.byDigest("sha256:" + "0".repeat(64)));
        assertTrue(BuildKitClient.buildctl(push).contains(
                "type=image,name=registry:5000/content/abc:build-" + BUILD + ",push=true"));
        // --output is one comma-separated option string: a ',' in either name would add an
        // option (another registry, registry.insecure, push=false).
        for (String repo : List.of("abc,push=false", "abc,registry.insecure=true", "ABC", "a b", "a//b",
                "/a", "a/", "-a", "a:1", "a@sha256", "", "a\nb", "a".repeat(201))) {
            assertThrows(IllegalArgumentException.class, () -> new Push("registry", repo, BUILD, CRED), repo);
        }
        for (String reg : List.of("registry,push=false", "registry:5000", "Registry", "-r", "r.", "", "r\n")) {
            assertThrows(IllegalArgumentException.class, () -> new Push(reg, "abc", BUILD, CRED), reg);
        }
    }

    @Test
    public void theCredentialIsNeverPrintedAndOnlyTheClientConfigCarriesIt() {
        Push push = new Push("registry", "abc", BUILD, CRED);
        assertFalse(CRED.toString().contains("s3cret"));
        assertFalse(push.toString().contains("s3cret"));
        assertTrue(BuildKitClient.buildctl(push).stream().noneMatch(a -> a.contains("s3cret")
                || a.contains("c2thbGQ6czNjcmV0")), "not in buildctl's argv");
        // {"auths":{"registry:5000":{"auth":base64("skald:s3cret")}}}
        assertEquals("{\"auths\":{\"registry:5000\":{\"auth\":\"c2thbGQ6czNjcmV0\"}}}",
                BuildKitClient.dockerConfig(push));
    }

    @Test
    public void theContextHoldsThePayloadUnderAppTheRecipeUnderSkaldAndTheDockerfileOutside(@TempDir Path dir)
            throws IOException {
        Path payload = Files.createDirectories(dir.resolve("payload"));
        Files.writeString(payload.resolve("app.py"), "print(1)\n");
        Files.createDirectories(payload.resolve("www/img"));
        Files.writeString(payload.resolve("www/img/a.txt"), "a");
        Path run = Files.writeString(payload.resolve("run.sh"), "#!/bin/sh\n");
        Files.setPosixFilePermissions(run, PosixFilePermissions.fromString("rwx------"));
        Files.setPosixFilePermissions(payload.resolve("app.py"), PosixFilePermissions.fromString("rw-------"));
        Recipe recipe = new Recipe("FROM x\n", Map.of("skald/requirements.lock", "lock\n".getBytes()));

        Map<String, TarArchiveEntry> entries = new LinkedHashMap<>();
        Map<String, String> bodies = new LinkedHashMap<>();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BuildKitClient.writeContext(out, payload, recipe);
        try (TarArchiveInputStream in = new TarArchiveInputStream(new ByteArrayInputStream(out.toByteArray()))) {
            for (TarArchiveEntry e; (e = in.getNextEntry()) != null; ) {
                entries.put(e.getName(), e);
                if (e.isFile()) {
                    bodies.put(e.getName(), new String(in.readAllBytes(), StandardCharsets.UTF_8));
                }
            }
        }
        assertEquals(List.of("ctx/", "ctx/app/", "ctx/skald/", "df/", "ctx/app/app.py", "ctx/app/run.sh",
                "ctx/app/www/", "ctx/app/www/img/", "ctx/app/www/img/a.txt", "ctx/skald/requirements.lock",
                "df/Dockerfile"), List.copyOf(entries.keySet()));
        assertEquals("FROM x\n", bodies.get("df/Dockerfile"));
        assertEquals("lock\n", bodies.get("ctx/skald/requirements.lock"));
        assertEquals("print(1)\n", bodies.get("ctx/app/app.py"));
        // Modes are set, not carried; owners are root.
        assertEquals(0644, entries.get("ctx/app/app.py").getMode() & 07777);
        assertEquals(0755, entries.get("ctx/app/run.sh").getMode() & 07777);
        assertEquals(0755, entries.get("ctx/app/www/").getMode() & 07777);
        assertTrue(entries.values().stream().allMatch(e -> e.getLongUserId() == 0 && e.getLongGroupId() == 0));
        assertTrue(entries.keySet().stream().noneMatch(n -> n.startsWith("ctx/") && n.endsWith("Dockerfile")),
                "no Dockerfile inside the context");
    }

    @Test
    public void onlyAWholeMetadataObjectWithADigestIsAResult() {
        String d = "sha256:" + "ab".repeat(32);
        assertEquals(d, BuildKitClient.digestFrom("{\"containerimage.digest\":\"" + d + "\",\"image.name\":\"x\"}\n"));
        for (String out : List.of("", "not json", "[]", "null", "{}", "{\"containerimage.digest\":\"sha256:abc\"}",
                "{\"containerimage.digest\":\"" + d.toUpperCase() + "\"}",
                "{\"containerimage.digest\":\"" + d + "x\"}",
                "{\"containerimage.digest\":\"sha512:" + "ab".repeat(64) + "\"}",
                "{\"containerimage.digest\":\"" + d + "\"} trailing")) {
            assertThrows(IllegalStateException.class, () -> BuildKitClient.digestFrom(out), out);
        }
    }

    @Test
    public void aLinkInThePayloadIsRefused(@TempDir Path dir) throws IOException {
        Recipe recipe = new Recipe("FROM x\n", Map.of());
        for (String kind : List.of("file", "dir", "dangling")) {
            Path payload = Files.createDirectories(dir.resolve("p-" + kind));
            Path target = kind.equals("dir") ? Files.createDirectories(dir.resolve("t-dir"))
                    : kind.equals("file") ? Files.writeString(dir.resolve("t-file"), "secret") : dir.resolve("nowhere");
            Files.createSymbolicLink(payload.resolve("link"), target);
            IOException e = assertThrows(IOException.class,
                    () -> BuildKitClient.writeContext(new ByteArrayOutputStream(), payload, recipe), kind);
            assertTrue(e.getMessage().contains("not a file or directory"), e.getMessage());
        }
    }

    @Test
    public void aRecipeFileOutsideSkaldIsRefusedBeforeDockerIsAsked(@TempDir Path dir) {
        BuildKitClient client = new BuildKitClient(null, null, null);
        for (String key : List.of("app/x", "skald/../x", "skald/a/b", "../x", "Dockerfile", "skald/", "skald/.x")) {
            Recipe recipe = new Recipe("FROM x\n", Map.of(key, new byte[0]));
            assertThrows(IllegalArgumentException.class,
                    () -> client.stage(DockerWorkerLauncher.handle("aaaaaaaa"), dir, recipe), key);
        }
    }
}
