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
package eu.openanalytics.shinyproxy.publisher.storage;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Scoped service credentials, cross-bucket denial, and revocation while running.
 *
 * <p>T4 asks for "real MinIO and scoped service credentials", and its Pass line for "no
 * public/cross-key read" and for permissions to be revoked mid-flight. Every other test in
 * this package uses the MinIO root user, which can reach everything — so none of them can
 * tell a store that respects its scope from one that ignores it.
 *
 * <p>The scoping itself is the operator's: the plan says "S3 roles are least-privilege,
 * buckets private, credentials absent from worker payloads". What is testable here is that
 * the platform works correctly when given a scoped identity, that the scope actually binds,
 * and that losing it produces an explicit storage failure rather than a silent one.
 */
class ScopedCredentialsTest {

    private static final String BUNDLES = "skald-scoped-bundles";
    private static final String LOGS = "skald-scoped-logs";
    private static final String ROOT_USER = "skald";
    private static final String ROOT_PASSWORD = "skaldskald";
    private static final String SCOPED_USER = "skald-bundles-writer";
    private static final String SCOPED_PASSWORD = "scoped-secret-key";

    private static GenericContainer<?> minio;
    private static S3Client rootClient;
    private static S3Client scopedClient;
    private static ObjectStore scoped;

    @BeforeAll
    static void startMinio() throws Exception {
        minio = new GenericContainer<>(DockerImageName.parse(
                "quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e"
                        + "708c1e2960462bd8936e"))
                .withCommand("server", "/data")
                .withEnv("MINIO_ROOT_USER", ROOT_USER)
                .withEnv("MINIO_ROOT_PASSWORD", ROOT_PASSWORD)
                .withExposedPorts(9000)
                .waitingFor(Wait.forHttp("/minio/health/live").forPort(9000));
        minio.start();

        rootClient = client(ROOT_USER, ROOT_PASSWORD);
        rootClient.createBucket(CreateBucketRequest.builder().bucket(BUNDLES).build());
        rootClient.createBucket(CreateBucketRequest.builder().bucket(LOGS).build());

        mc("alias", "set", "local", "http://localhost:9000", ROOT_USER, ROOT_PASSWORD);
        // A policy that reaches exactly one bucket. This is the shape an operator is meant
        // to deploy, so the test uses it rather than a convenient approximation.
        exec("sh", "-c", "cat > /tmp/bundles-only.json <<'JSON'\n"
                + "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                + "\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\","
                + "\"s3:DeleteObject\"],"
                + "\"Resource\":[\"arn:aws:s3:::" + BUNDLES + "\",\"arn:aws:s3:::"
                + BUNDLES + "/*\"]}]}\nJSON");
        mc("admin", "policy", "create", "local", "bundles-only", "/tmp/bundles-only.json");
        mc("admin", "user", "add", "local", SCOPED_USER, SCOPED_PASSWORD);
        mc("admin", "policy", "attach", "local", "bundles-only", "--user", SCOPED_USER);

        scopedClient = client(SCOPED_USER, SCOPED_PASSWORD);
        scoped = new S3ObjectStore(scopedClient);
    }

    @AfterAll
    static void stop() {
        if (rootClient != null) {
            rootClient.close();
        }
        if (scopedClient != null) {
            scopedClient.close();
        }
        if (minio != null) {
            minio.stop();
        }
    }

    private static S3Client client(String user, String password) {
        return S3Client.builder()
                .endpointOverride(URI.create(
                        "http://" + minio.getHost() + ":" + minio.getMappedPort(9000)))
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(user, password)))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
                .build();
    }

    private static void mc(String... args) throws Exception {
        String[] full = new String[args.length + 1];
        full[0] = "/usr/bin/mc";
        System.arraycopy(args, 0, full, 1, args.length);
        exec(full);
    }

    /** Runs a command in the MinIO container and fails loudly if it did not succeed. */
    private static void exec(String... command) throws Exception {
        Container.ExecResult result = minio.execInContainer(command);
        if (result.getExitCode() != 0) {
            throw new IllegalStateException("setup command failed: "
                    + String.join(" ", command) + "\n" + result.getStdout()
                    + result.getStderr());
        }
    }

    private static String key() {
        return ObjectKeys.bundleObject(UUID.randomUUID(), UUID.randomUUID(),
                ObjectKeys.BUNDLE_MANIFEST);
    }

    @Test
    @DisplayName("a scoped identity can do its whole job in its own bucket")
    void scopedCredentialsWorkInScope() {
        // If this failed, every denial below would be meaningless: refusing everything is
        // not the same as refusing the right things.
        String k = key();
        byte[] content = "{\"schema_version\":1}".getBytes(StandardCharsets.UTF_8);

        StoredObject written = scoped.put(BUNDLES, k, content, "application/json");
        assertEquals(content.length, written.size());
        assertTrue(scoped.head(BUNDLES, k).isPresent());
        assertEquals(content.length,
                scoped.readVerified(BUNDLES, k, written.sha256().orElseThrow()).length);
        assertNotNull(scoped.list(BUNDLES, "v1/"));

        String streamed = ObjectKeys.bundleObject(UUID.randomUUID(), UUID.randomUUID(),
                ObjectKeys.BUNDLE_ARCHIVE);
        assertTrue(scoped.putStreamingIfAbsent(BUNDLES, streamed,
                new ByteArrayInputStream(content), content.length,
                "application/gzip").isPresent());
    }

    @Test
    @DisplayName("the same identity cannot touch another bucket, read or write")
    void crossBucketAccessIsDenied() {
        // "no public/cross-key read". The logs bucket exists and holds an object the root
        // user put there, so this is the policy denying access rather than the object
        // being absent -- which is the difference between a scope that binds and a store
        // that happens to be empty.
        String k = key();
        rootClient.putObject(b -> b.bucket(LOGS).key(k),
                software.amazon.awssdk.core.sync.RequestBody.fromString("secret"));
        assertTrue(new S3ObjectStore(rootClient).head(LOGS, k).isPresent(),
                "the object must exist, or the denial below proves nothing");

        assertThrows(ObjectStoreException.class, () -> scoped.readVerified(LOGS, k,
                S3ObjectStore.sha256("secret".getBytes(StandardCharsets.UTF_8))));
        assertThrows(ObjectStoreException.class, () -> scoped.open(LOGS, k));
        assertThrows(ObjectStoreException.class, () -> scoped.list(LOGS, "v1/"));
        assertThrows(ObjectStoreException.class, () -> scoped.put(LOGS, key(),
                "x".getBytes(StandardCharsets.UTF_8), "application/json"));

        // head() is the one that must not answer "absent" for "not allowed": absent is a
        // fact a caller acts on, and forbidden is not.
        assertThrows(ObjectStoreException.class, () -> scoped.head(LOGS, k));
    }

    @Test
    @DisplayName("revoking the policy mid-flight is an explicit storage failure")
    void revocationWhileRunningFailsExplicitly() throws Exception {
        String before = key();
        byte[] content = "{\"before\":true}".getBytes(StandardCharsets.UTF_8);
        StoredObject written = scoped.put(BUNDLES, before, content, "application/json");

        // A dedicated identity, so revoking it cannot disturb the other tests.
        String user = "skald-revocable";
        mc("admin", "user", "add", "local", user, "revocable-secret-key");
        mc("admin", "policy", "attach", "local", "bundles-only", "--user", user);
        try (S3Client revocable = client(user, "revocable-secret-key")) {
            ObjectStore store = new S3ObjectStore(revocable);
            assertTrue(store.head(BUNDLES, before).isPresent(),
                    "the identity must work before it is revoked");

            mc("admin", "policy", "detach", "local", "bundles-only", "--user", user);

            // Everything must now fail, and fail as a storage failure rather than as an
            // absence or a silently dropped write. The plan: a MinIO outage "must be an
            // explicit storage failure" with "no filesystem durability fallback", and a
            // revoked credential is the same class of event.
            ObjectStoreException write = assertThrows(ObjectStoreException.class,
                    () -> store.put(BUNDLES, key(), content, "application/json"));
            assertTrue(write.getMessage().contains("could not write"), write.getMessage());
            assertThrows(ObjectStoreException.class, () -> store.head(BUNDLES, before));
            assertThrows(ObjectStoreException.class,
                    () -> store.readVerified(BUNDLES, before,
                            written.sha256().orElseThrow()));
            assertThrows(ObjectStoreException.class, () -> store.list(BUNDLES, "v1/"));
        } finally {
            mc("admin", "user", "remove", "local", user);
        }

        // And the still-scoped identity is unaffected: revocation removed one identity's
        // access, not the platform's.
        assertTrue(scoped.head(BUNDLES, before).isPresent());
    }
}
