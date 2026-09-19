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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The log protocol against real MinIO, with the gap case as the centrepiece.
 *
 * <p>"Readers may lag but cannot observe a completion index pointing at absent chunks.
 * Prove this with late-writer tests." Both halves are here.
 */
class BuildLogWriterTest {

    private static final String BUCKET = "skald-test-logs";
    private static final String USER = "skald";
    private static final String PASSWORD = "skaldskald";

    private static GenericContainer<?> minio;
    private static S3Client client;
    private static ObjectStore store;
    private static BuildLogWriter logs;

    @BeforeAll
    static void startMinio() {
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
                .endpointOverride(URI())
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(USER, PASSWORD)))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
                .build();
        client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        store = new S3ObjectStore(client);
        logs = new BuildLogWriter(store, BUCKET);
    }

    private static java.net.URI URI() {
        return java.net.URI.create(
                "http://" + minio.getHost() + ":" + minio.getMappedPort(9000));
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

    private static byte[] line(long n) {
        return ("{\"seq\":" + n + "}\n").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("an index advertises a contiguous run, never the highest sequence present")
    void indexStopsAtTheFirstHole() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        logs.appendChunk(c, b, 1, line(1));
        logs.appendChunk(c, b, 2, line(2));
        // 3 never lands -- a failed PUT, or one still in flight.
        logs.appendChunk(c, b, 4, line(4));
        logs.appendChunk(c, b, 5, line(5));

        LogIndex index = logs.publishIndex(c, b, 1).orElseThrow();
        assertEquals(2, index.lastSequence(),
                "the run ends at the hole; 4 and 5 exist but cannot be advertised");
        assertEquals(line(1).length + line(2).length, index.bytes(),
                "bytes must cover the advertised run only");

        // The later chunks really are there, so this is the rule refusing rather than the
        // writes having failed. Without this the assertion above would also pass against a
        // store that dropped chunks 4 and 5.
        assertTrue(store.head(BUCKET, ObjectKeys.logChunk(c, b, 4)).isPresent());
        assertTrue(store.head(BUCKET, ObjectKeys.logChunk(c, b, 5)).isPresent());

        // Filling the hole lets the run continue past it.
        logs.appendChunk(c, b, 3, line(3));
        assertEquals(5, logs.publishIndex(c, b, 1).orElseThrow().lastSequence());
    }

    @Test
    @DisplayName("completion never points past a hole, and says the log is incomplete")
    void finalNeverPointsAtAnAbsentChunk() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        logs.appendChunk(c, b, 1, line(1));
        logs.appendChunk(c, b, 3, line(3));

        LogFinal record = logs.finalise(c, b, 1, "FAILED", false).orElseThrow();
        assertEquals(1, record.lastSequence(),
                "completion must not advertise chunk 3 across the hole at 2");
        assertFalse(record.complete(),
                "a gap means the LOG is incomplete, which is not the same as the build "
                        + "having failed");
        assertEquals("FAILED", record.outcome());
        assertFalse(record.truncated(), "a hole is a loss, not a decision to stop");

        // And the index agrees: a reader arriving after completion is not sent further.
        assertEquals(1, logs.readIndex(c, b).orElseThrow().lastSequence());
    }

    @Test
    @DisplayName("a complete log says so, and truncation is distinct from loss")
    void completeAndTruncatedAreDifferentThings() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        for (long n = 1; n <= 4; n++) {
            logs.appendChunk(c, b, n, line(n));
        }
        LogFinal record = logs.finalise(c, b, 1, "SUCCEEDED", true).orElseThrow();
        assertEquals(4, record.lastSequence());
        assertTrue(record.complete(), "no gaps, so the log is complete");
        assertTrue(record.truncated(),
                "the platform stopped recording on purpose; that is a decision, and it "
                        + "coexists with the log being complete up to that point");
    }

    @Test
    @DisplayName("a chunk sequence is written once; a second writer cannot replace it")
    void chunksAreWriteOnce() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        assertTrue(logs.appendChunk(c, b, 1, line(1)).isPresent());
        assertTrue(logs.appendChunk(c, b, 1, "{\"different\":true}\n"
                .getBytes(StandardCharsets.UTF_8)).isEmpty(),
                "a second writer at an existing sequence must be refused");
        assertArrayEquals(line(1), store.readVerified(BUCKET, ObjectKeys.logChunk(c, b, 1),
                S3ObjectStore.sha256(line(1))), "the original bytes must be untouched");
    }

    @Test
    @DisplayName("a fenced-out writer cannot move the index or publish completion")
    void lateWriterIsFenced() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        logs.appendChunk(c, b, 1, line(1));
        logs.appendChunk(c, b, 2, line(2));

        // Generation 5 holds the lease and publishes.
        assertEquals(2, logs.publishIndex(c, b, 5).orElseThrow().lastSequence());

        // Generation 3 is the old worker waking up. It appends a chunk -- which is allowed,
        // the chunk is create-only and harmless -- and then tries to publish.
        logs.appendChunk(c, b, 3, line(3));
        assertTrue(logs.publishIndex(c, b, 3).isEmpty(),
                "a stale generation must not republish the index");
        assertEquals(5, logs.readIndex(c, b).orElseThrow().generation(),
                "the published index must still belong to the current generation");
        assertEquals(2, logs.readIndex(c, b).orElseThrow().lastSequence());

        assertTrue(logs.finalise(c, b, 3, "SUCCEEDED", false).isEmpty(),
                "a stale generation must not publish completion");
        assertTrue(logs.readFinal(c, b).isEmpty(), "nothing was finalised");

        // The current generation still can, and sees the chunk the old one left behind.
        LogFinal record = logs.finalise(c, b, 5, "SUCCEEDED", false).orElseThrow();
        assertEquals(3, record.lastSequence());
        assertTrue(record.complete());
    }

    @Test
    @DisplayName("completion happens once")
    void finalIsWrittenOnce() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        logs.appendChunk(c, b, 1, line(1));
        LogFinal first = logs.finalise(c, b, 1, "SUCCEEDED", false).orElseThrow();
        assertTrue(logs.finalise(c, b, 1, "FAILED", false).isEmpty(),
                "a second completion must be refused, not overwrite the outcome");
        assertEquals(first, logs.readFinal(c, b).orElseThrow(),
                "the first outcome stands");
    }

    @Test
    @DisplayName("a listing covers every chunk, past one page")
    void listingIsNotTruncated() {
        // A truncated listing of chunks is indistinguishable from a log that stopped early,
        // so pagination is a correctness property here rather than a performance one.
        // MinIO pages at 1000 keys; 1050 crosses it with margin and keeps the 1050
        // sequential PUTs this needs from dominating the suite.
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        // Written in parallel: 1050 sequential round trips took about 160 seconds and
        // dominated the whole suite, and these are independent create-only PUTs, so the
        // ordering they would give is not a property anything here relies on. The S3
        // client is thread-safe.
        java.util.stream.LongStream.rangeClosed(1, 1050).parallel()
                .forEach(n -> logs.appendChunk(c, b, n, line(n)));
        List<StoredObject> chunks = store.list(BUCKET,
                ObjectKeys.logChunk(c, b, 1).replaceAll("/chunks/.*$", "/chunks/"));
        assertEquals(1050, chunks.size(), "every chunk must appear, across page boundaries");
        assertTrue(chunks.stream().allMatch(o -> o.sha256().isEmpty()),
                "a listing carries no digest, and must not invent one");

        Optional<LogIndex> index = logs.publishIndex(c, b, 1);
        assertEquals(1050, index.orElseThrow().lastSequence(),
                "the contiguous run must not stop at a page boundary");
    }
}
