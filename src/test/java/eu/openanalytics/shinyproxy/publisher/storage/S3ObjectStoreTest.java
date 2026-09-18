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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The object store against real MinIO, because an S3 mock proves nothing about S3.
 *
 * <p>T4's requirement is "use real MinIO and scoped service credentials". A stubbed client
 * would agree with whatever this implementation believes, and the behaviours that matter
 * here — conditional create, what a 404 looks like on HEAD, whether an ETag resembles a
 * content hash — are all the store's, not ours.
 *
 * <p>Uses a plain {@code GenericContainer} rather than a Testcontainers MinIO module, so no
 * dependency is added: {@code testcontainers:junit-jupiter} is already on the test
 * classpath for the registry's PostgreSQL tests.
 */
class S3ObjectStoreTest {

    private static final String BUCKET = "skald-test-bundles";
    private static final String USER = "skald";
    private static final String PASSWORD = "skaldskald";

    private static GenericContainer<?> minio;
    private static S3Client client;
    private static ObjectStore store;

    @BeforeAll
    static void startMinio() {
        // quay.io, as WORKPLAN-DEVSTACK.md records for the dev stack: Docker Hub's minio
        // image was not usable there.
        //
        // PINNED, like postgres:16 in every other container test here, and for a sharper
        // reason: the load-bearing claim of this class is that the STORE enforces
        // If-None-Match on PutObject, which is a comparatively recent MinIO feature. An
        // unpinned :latest could change that and either break this suite or, worse, quietly
        // change what conditionalCreateRefusesTheSecondWriter proves while still passing.
        // Measured against RELEASE.2025-09-07T16-13-09Z; the digest is what fixes it.
        minio = new GenericContainer<>(DockerImageName.parse(
                "quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e"
                        + "708c1e2960462bd8936e"))
                .withCommand("server", "/data")
                .withEnv("MINIO_ROOT_USER", USER)
                .withEnv("MINIO_ROOT_PASSWORD", PASSWORD)
                .withExposedPorts(9000)
                .waitingFor(Wait.forHttp("/minio/health/live").forPort(9000));
        minio.start();

        client = S3Client.builder()
                .endpointOverride(URI.create(
                        "http://" + minio.getHost() + ":" + minio.getMappedPort(9000)))
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(USER, PASSWORD)))
                // Named, not discovered: several HTTP implementations are on this
                // classpath through ContainerProxy's own SDK dependencies.
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
        client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        store = new S3ObjectStore(client);
    }

    @AfterAll
    static void stopMinio() {
        if (client != null) {
            client.close();
        }
        if (minio != null) {
            minio.stop();
        }
    }

    private static String key(String name) {
        return ObjectKeys.bundleObject(UUID.randomUUID(), UUID.randomUUID(), name);
    }

    @Test
    @DisplayName("bytes survive a round trip and the digest is ours, not the ETag")
    void roundTripAndDigest() {
        byte[] content = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
        String k = key(ObjectKeys.BUNDLE_MANIFEST);

        StoredObject written = store.put(BUCKET, k, content, "application/json");
        assertEquals(content.length, written.size());
        assertEquals(S3ObjectStore.sha256(content), written.sha256().orElseThrow());
        assertEquals(64, written.sha256().orElseThrow().length(), "SHA-256 hex is 64 characters");
        assertEquals(written.sha256().orElseThrow().toLowerCase(java.util.Locale.ROOT), written.sha256().orElseThrow(),
                "the manifest schema's sha256 pattern accepts lower-case hex only");

        // The ETag is recorded and must never be mistaken for the content hash. MinIO
        // returns MD5 for a single-part upload, so this also pins that they differ.
        assertNotEquals(written.sha256().orElseThrow(), stripQuotes(written.etag()),
                "the ETag must not be treated as, or equal, the SHA-256");

        byte[] read = store.readVerified(BUCKET, k, written.sha256().orElseThrow());
        assertArrayEquals(content, read);

        try (InputStream in = store.open(BUCKET, k)) {
            assertArrayEquals(content, in.readAllBytes());
        } catch (Exception e) {
            throw new AssertionError("open() could not read back what put() wrote", e);
        }
    }

    @Test
    @DisplayName("a digest that does not match is a failure, not a shrug")
    void mismatchedDigestFails() {
        byte[] content = "payload".getBytes(StandardCharsets.UTF_8);
        String k = key(ObjectKeys.BUNDLE_ARCHIVE);
        store.put(BUCKET, k, content, "application/gzip");

        String wrong = S3ObjectStore.sha256("something else".getBytes(StandardCharsets.UTF_8));
        ObjectStoreException e = assertThrows(ObjectStoreException.class,
                () -> store.readVerified(BUCKET, k, wrong));
        assertTrue(e.getMessage().contains("digest mismatch"), e.getMessage());
        // The message has to carry both digests, or an operator cannot tell a corrupted
        // object from a wrong expectation.
        assertTrue(e.getMessage().contains(wrong), e.getMessage());
    }

    @Test
    @DisplayName("putIfAbsent creates once and then refuses, without rewriting")
    void conditionalCreateRefusesTheSecondWriter() {
        String k = ObjectKeys.logChunk(UUID.randomUUID(), UUID.randomUUID(), 1);
        byte[] first = "{\"line\":1}".getBytes(StandardCharsets.UTF_8);
        byte[] second = "{\"line\":999}".getBytes(StandardCharsets.UTF_8);

        Optional<StoredObject> created = store.putIfAbsent(BUCKET, k, first, "application/x-ndjson");
        assertTrue(created.isPresent(), "the first writer must create the chunk");

        Optional<StoredObject> refused = store.putIfAbsent(BUCKET, k, second, "application/x-ndjson");
        assertTrue(refused.isEmpty(), "a second writer at the same sequence must be refused");

        // The refusal is worthless if the bytes changed anyway. This is the property the
        // plan states: "rejects an attempt to replace different bytes at an existing
        // sequence".
        assertArrayEquals(first, store.readVerified(BUCKET, k, created.get().sha256().orElseThrow()),
                "the original chunk bytes must be untouched after a refused write");
    }

    @Test
    @DisplayName("an absent object is absent, not an exception, on head")
    void headOfAbsentObject() {
        assertTrue(store.head(BUCKET, key(ObjectKeys.BUNDLE_RECEIPT)).isEmpty());

        String k = key(ObjectKeys.BUNDLE_RECEIPT);
        StoredObject written = store.put(BUCKET, k, "{}".getBytes(StandardCharsets.UTF_8),
                "application/json");
        Optional<StoredObject> found = store.head(BUCKET, k);
        assertTrue(found.isPresent());
        assertEquals(2, found.get().size());
        // The digest we recorded on the object survives independently of any database row.
        assertEquals(written.sha256(), found.get().sha256(),
                "the SHA-256 stored as object metadata must come back on HEAD");
    }

    @Test
    @DisplayName("reading an object that is not there fails explicitly")
    void openOfAbsentObjectFails() {
        ObjectStoreException e = assertThrows(ObjectStoreException.class,
                () -> store.open(BUCKET, key(ObjectKeys.BUNDLE_ARCHIVE)));
        assertTrue(e.getMessage().contains("no object at"), e.getMessage());
    }

    @Test
    @DisplayName("an unreachable store is a storage failure, never a silent fallback")
    void storageOutageIsExplicit() {
        // The plan requires a MinIO outage to be "an explicit storage failure" with "no
        // filesystem durability fallback". Pointed at a closed port rather than by stopping
        // the shared container, so this test does not disturb the others.
        try (S3Client broken = S3Client.builder()
                .endpointOverride(URI.create("http://127.0.0.1:1"))
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(USER, PASSWORD)))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
                .build()) {
            ObjectStore down = new S3ObjectStore(broken);
            assertThrows(ObjectStoreException.class,
                    () -> down.put(BUCKET, key(ObjectKeys.BUNDLE_MANIFEST),
                            "x".getBytes(StandardCharsets.UTF_8), "application/json"));
            assertThrows(ObjectStoreException.class,
                    () -> down.readVerified(BUCKET, key(ObjectKeys.BUNDLE_MANIFEST), "0".repeat(64)));
            // head() must not report "absent" when the truth is "cannot tell". Absent is a
            // fact a caller acts on; unreachable is not.
            assertThrows(ObjectStoreException.class,
                    () -> down.head(BUCKET, key(ObjectKeys.BUNDLE_MANIFEST)));
        }
    }

    @Test
    @DisplayName("keys needing URL encoding round-trip as themselves")
    void awkwardKeysRoundTrip() {
        // T1(b) pinned this set for the descriptor and ObjectKeysTest pins it for the key
        // builder; this is the half neither can prove, because it needs a real store to
        // encode the key on the wire and give it back unchanged.
        UUID c = UUID.randomUUID(), v = UUID.randomUUID(), r = UUID.randomUUID();
        String[] names = {
                "a file with spaces.html", "100%.html", "100%25.html", "résumé.pdf",
                "日本語/ページ.html", "plus+and&amp.html",
                "quote'apostrophe.html", "hash#fragment.html",
        };
        for (String name : names) {
            String k = ObjectKeys.renditionFile(c, v, r, name);
            byte[] content = name.getBytes(StandardCharsets.UTF_8);
            StoredObject written = store.put(BUCKET, k, content, "text/html");
            assertEquals(k, written.key(), "the key changed on the way in: " + name);

            Optional<StoredObject> found = store.head(BUCKET, k);
            assertTrue(found.isPresent(), "could not find the object back under " + k);
            assertArrayEquals(content, store.readVerified(BUCKET, k, written.sha256().orElseThrow()),
                    "content did not survive for " + name);
        }
    }

    @Test
    @DisplayName("nothing in this bucket is readable without credentials")
    void bucketIsNotPublic() throws Exception {
        String k = key(ObjectKeys.BUNDLE_MANIFEST);
        store.put(BUCKET, k, "secret".getBytes(StandardCharsets.UTF_8), "application/json");

        // A plain HTTP GET with no signature. The plan requires buckets private and
        // "no public/cross-key read"; a default-public bucket would make every other test
        // here pass while the artifacts were world-readable.
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) URI.create(
                        "http://" + minio.getHost() + ":" + minio.getMappedPort(9000)
                                + "/" + BUCKET + "/" + k)
                .toURL().openConnection();
        conn.setRequestMethod("GET");
        int status = conn.getResponseCode();
        assertFalse(status >= 200 && status < 300,
                "an unauthenticated GET returned " + status + "; the bucket is public");
    }

    @Test
    @DisplayName("a large object survives the streaming path with its digest intact")
    void largeObjectRoundTripsThroughTheStreamingPath() {
        // NOT a detector of buffering, and it was named as one until f440ce4-F1. A
        // putStreaming implemented as readAllBytes() then put() PASSES this test; the suite
        // catches that mutation only through declaredLengthIsAClaimThatIsChecked, because a
        // buffering implementation ignores declaredLength. A tick earned by another branch
        // is not coverage of this one.
        //
        // Non-buffering rests on RequestBody.fromInputStream with an explicit length, which
        // is by construction. No cheap deterministic assertion exists for it: heap sampling
        // around the call is flaky and an object large enough to OOM a buffering
        // implementation would be slow and host-dependent. Naming the limit is better than
        // a fragile assertion, as caseCollisionsAreLeftToTheFileListOwner does for its own.
        //
        // What this DOES assert is worth having: 32 MiB through the streaming API, with the
        // digest computed in flight equal to the digest of the same bytes computed whole,
        // and every byte arriving at the far end.
        int size = 32 * 1024 * 1024;
        String k = key(ObjectKeys.BUNDLE_ARCHIVE);

        byte[] expected = new byte[size];
        for (int i = 0; i < size; i++) {
            expected[i] = (byte) (i * 31);
        }
        String expectedDigest = S3ObjectStore.sha256(expected);

        // A source that generates its bytes rather than holding them, so if the store
        // buffered the whole object it would be the store doing it, not this test.
        StoredObject written = store.putStreaming(BUCKET, k, generated(size), size,
                "application/gzip");
        assertEquals(size, written.size());
        assertEquals(expectedDigest, written.sha256().orElseThrow(),
                "the digest computed while streaming must equal the digest of the bytes");

        // And back out again without materialising it either.
        CountingSink sink = new CountingSink();
        StoredObject read = store.readVerifiedTo(BUCKET, k, expectedDigest, sink);
        assertEquals(size, read.size());
        assertEquals(expectedDigest, read.sha256().orElseThrow());
        assertEquals(size, sink.count, "every byte must reach the sink");
        assertEquals(expectedDigest, sink.digestHex(),
                "the bytes that reached the sink must be the bytes that were stored");
    }

    @Test
    @DisplayName("head() has a digest for a buffered put and none for a streamed one")
    void headDigestIsAbsentForStreamedObjects() {
        // The asymmetry is real and was explained only in a javadoc. Asserted here so a
        // caller meets it in the suite, and so that if putStreaming ever learns to record
        // the digest, this fails and says the receipt is no longer the only record.
        byte[] content = "same bytes either way".getBytes(StandardCharsets.UTF_8);
        String expected = S3ObjectStore.sha256(content);

        String buffered = key(ObjectKeys.BUNDLE_MANIFEST);
        store.put(BUCKET, buffered, content, "application/json");
        assertEquals(Optional.of(expected), store.head(BUCKET, buffered).orElseThrow().sha256(),
                "a buffered put records its digest as object metadata");

        String streamed = key(ObjectKeys.BUNDLE_ARCHIVE);
        StoredObject written = store.putStreaming(BUCKET, streamed,
                new ByteArrayInputStream(content), content.length, "application/gzip");
        assertEquals(Optional.of(expected), written.sha256(),
                "the write itself still returns the digest it computed in flight");
        assertEquals(Optional.empty(), store.head(BUCKET, streamed).orElseThrow().sha256(),
                "a streamed put cannot record the digest as metadata: headers are sent "
                        + "before the body is read, so receipt.json is the durable record");

        // And the bytes are verifiable anyway, from the digest the write returned.
        assertArrayEquals(content,
                store.readVerified(BUCKET, streamed, written.sha256().orElseThrow()));
    }

    @Test
    @DisplayName("a declared length that does not match the bytes read is refused")
    void declaredLengthIsAClaimThatIsChecked() {
        // spec/admin-transport-v1.json, bundle.upload: "Content-Length is a claim, checked
        // against the bytes actually read." A short body under an honest-looking header is
        // how a truncated upload becomes a stored object nobody notices.
        byte[] content = "only twenty-nine bytes here.".getBytes(StandardCharsets.UTF_8);

        // Over-declared: the SDK runs out of bytes and throws first, so this pins the
        // SDK's behaviour rather than ours. If it ever stops throwing, this fails and the
        // short-body direction becomes ours to catch.
        ObjectStoreException tooLong = assertThrows(ObjectStoreException.class,
                () -> store.putStreaming(BUCKET, key(ObjectKeys.BUNDLE_ARCHIVE),
                        new ByteArrayInputStream(content), content.length + 100,
                        "application/gzip"));
        assertTrue(tooLong.getMessage().contains("could not write"), tooLong.getMessage());

        // The dangerous direction. The SDK stops at exactly the declared length, so the
        // byte count matches perfectly and only asking the source whether it has more
        // reveals the truncation. Without that check this stored a short bundle silently.
        String k = key(ObjectKeys.BUNDLE_ARCHIVE);
        ObjectStoreException tooShort = assertThrows(ObjectStoreException.class,
                () -> store.putStreaming(BUCKET, k,
                        new ByteArrayInputStream(content), content.length - 5,
                        "application/gzip"));
        assertTrue(tooShort.getMessage().contains("more bytes than that"),
                tooShort.getMessage());
    }

    @Test
    @DisplayName("a streamed read with the wrong digest fails after the bytes have moved")
    void streamedReadVerifiesAndSaysSoLate() {
        byte[] content = "streamed payload".getBytes(StandardCharsets.UTF_8);
        String k = key(ObjectKeys.BUNDLE_ARCHIVE);
        store.putStreaming(BUCKET, k, new ByteArrayInputStream(content), content.length,
                "application/gzip");

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        String wrong = S3ObjectStore.sha256("other".getBytes(StandardCharsets.UTF_8));
        ObjectStoreException e = assertThrows(ObjectStoreException.class,
                () -> store.readVerifiedTo(BUCKET, k, wrong, sink));
        assertTrue(e.getMessage().contains("digest mismatch"), e.getMessage());
        // The documented consequence, asserted rather than only written down: the sink has
        // the bytes already, which is why its owner must discard it.
        assertArrayEquals(content, sink.toByteArray(),
                "the sink is expected to hold the bytes; the caller discards it");
    }

    /** Generates bytes on demand, so nothing here holds the object being streamed. */
    private static InputStream generated(int size) {
        return new InputStream() {
            private int position;

            @Override
            public int read() {
                return position >= size ? -1 : (byte) (position++ * 31) & 0xff;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (position >= size) {
                    return -1;
                }
                int n = Math.min(len, size - position);
                for (int i = 0; i < n; i++) {
                    b[off + i] = (byte) ((position + i) * 31);
                }
                position += n;
                return n;
            }
        };
    }

    /** Counts and digests without keeping anything. */
    private static final class CountingSink extends OutputStream {
        private final java.security.MessageDigest digest;
        private long count;

        CountingSink() {
            try {
                digest = java.security.MessageDigest.getInstance("SHA-256");
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        String digestHex() {
            return java.util.HexFormat.of().formatHex(digest.digest());
        }

        @Override
        public void write(int b) {
            digest.update((byte) b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) {
            digest.update(b, off, len);
            count += len;
        }
    }

    private static String stripQuotes(String etag) {
        return etag == null ? null : etag.replace("\"", "");
    }
}
