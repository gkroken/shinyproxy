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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.shinyproxy.publisher.storage.HeadTailLog.Limits;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The kept build log against real MinIO: what is written, when, and what a storage fault does. */
class HeadTailLogTest {

    private static final String BUCKET = "skald-test-headtail";
    private static final ObjectMapper JSON = new ObjectMapper();
    /** Small bounds so a few hundred lines exercise every path. */
    private static final Limits SMALL = new Limits(2000, 2000, 100, Duration.ofSeconds(2), 1000, 3,
            Duration.ofMillis(10));
    private static GenericContainer<?> minio;
    private static S3Client client;
    private static ObjectStore store;

    @BeforeAll
    static void start() {
        minio = MinioTestContainer.create("skald", "skaldskald");
        minio.start();
        client = S3Client.builder()
                .endpointOverride(java.net.URI.create("http://" + minio.getHost() + ":" + minio.getMappedPort(9000)))
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("skald", "skaldskald")))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .build();
        client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        store = new S3ObjectStore(client);
    }

    @AfterAll
    static void stop() {
        if (client != null) {
            client.close();
        }
        if (minio != null) {
            minio.stop();
        }
    }

    /** Every record of the log, in sequence order, read back from the store. */
    private static List<JsonNode> records(UUID c, UUID b) throws Exception {
        List<JsonNode> out = new ArrayList<>();
        for (long seq = 1; store.head(BUCKET, ObjectKeys.logChunk(c, b, seq)).isPresent(); seq++) {
            try (InputStream in = store.open(BUCKET, ObjectKeys.logChunk(c, b, seq))) {
                for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                    out.add(JSON.readTree(line));
                }
            }
        }
        return out;
    }

    private static long chunks(UUID c, UUID b) {
        long n = 0;
        while (store.head(BUCKET, ObjectKeys.logChunk(c, b, n + 1)).isPresent()) {
            n++;
        }
        return n;
    }

    @Test
    void aSmallLogIsWrittenWholeAndComplete() throws Exception {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(store, BUCKET), c, b, 1, SMALL);
        for (int i = 1; i <= 10; i++) {
            log.line("line " + i, false);
        }
        LogFinal fin = log.finish("built").orElseThrow();
        assertTrue(fin.complete());
        assertFalse(fin.truncated());
        assertEquals("built", fin.outcome());
        List<JsonNode> r = records(c, b);
        assertEquals(10, r.size());
        for (int i = 0; i < 10; i++) {
            assertEquals(i + 1, r.get(i).path("n").asLong());
            assertEquals("line " + (i + 1), r.get(i).path("t").asText());
            assertFalse(r.get(i).has("cut"));
        }
        assertEquals("line 10", log.lastLine());
        // The follower may still deliver lines after the attempt ended: none may become a
        // chunk after final.json.
        long written = chunks(c, b);
        for (int i = 0; i < 50; i++) {
            log.line("late " + "x".repeat(80), false);
        }
        log.tick();
        assertEquals(written, chunks(c, b), "nothing is written after finish");
    }

    @Test
    void anOversizedLogKeepsItsHeadItsTailAndACutMarkerBetween() throws Exception {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(store, BUCKET), c, b, 1, SMALL);
        for (int i = 1; i <= 1000; i++) {
            log.line("line " + i, false);
        }
        LogFinal fin = log.finish("failed:BUILD_FAILED").orElseThrow();
        assertTrue(fin.complete());
        assertTrue(fin.truncated());
        List<JsonNode> r = records(c, b);
        int marker = -1;
        for (int i = 0; i < r.size(); i++) {
            if (r.get(i).path("cut").isObject()) {
                assertEquals(-1, marker, "one marker");
                marker = i;
            }
        }
        assertTrue(marker > 0, "a marker after the head");
        // The head: lines 1..k, contiguous. The tail: the LAST lines, contiguous, ending at 1000.
        for (int i = 0; i < marker; i++) {
            assertEquals(i + 1, r.get(i).path("n").asLong());
        }
        long dropped = r.get(marker).path("cut").path("lines").asLong();
        long first = r.get(marker + 1).path("n").asLong();
        assertEquals(marker + dropped + 1, first, "the marker counts exactly the lines between head and tail");
        for (int i = marker + 1; i < r.size(); i++) {
            assertEquals(first + (i - marker - 1), r.get(i).path("n").asLong());
        }
        assertEquals(1000, r.get(r.size() - 1).path("n").asLong(), "the tail ends at the last line");
        assertEquals(1000, marker + dropped + (r.size() - marker - 1));
        // Bounded: head and tail each within their budget.
        long headBytes = 0;
        long tailBytes = 0;
        for (int i = 0; i < r.size(); i++) {
            long size = (r.get(i).toString() + "\n").getBytes(StandardCharsets.UTF_8).length;
            if (i < marker) {
                headBytes += size;
            } else if (i > marker) {
                tailBytes += size;
            }
        }
        assertTrue(headBytes <= SMALL.headBytes(), "head " + headBytes);
        assertTrue(tailBytes <= SMALL.tailBytes(), "tail " + tailBytes);
        assertTrue(tailBytes > SMALL.tailBytes() - 100, "the tail is used, not emptied: " + tailBytes);
    }

    @Test
    void theHeadIsReadableWhileTheBuildRuns() throws Exception {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        AtomicLong now = new AtomicLong();
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(store, BUCKET), c, b, 1, SMALL, now::get);
        log.line("one", false);
        log.line("two", false);
        log.tick();
        assertEquals(0, chunks(c, b), "not due yet: under a chunk, and under flushEvery");
        now.addAndGet(Duration.ofSeconds(2).toNanos());
        log.tick();
        assertEquals(1, chunks(c, b), "due by time");
        assertEquals(1, new BuildLogWriter(store, BUCKET).readIndex(c, b).orElseThrow().lastSequence(),
                "and advertised");
        // By size: a chunk is written as soon as the next record would overflow it.
        for (int i = 0; i < 30; i++) {
            log.line("x".repeat(60), false);
        }
        assertTrue(chunks(c, b) >= 2, "due by size");
        assertTrue(log.finish("built").orElseThrow().complete());
    }

    @Test
    void aCutLineSaysSo() throws Exception {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(store, BUCKET), c, b, 1, SMALL);
        log.line("short", true);
        log.line("esc " + (char) 0x1b + "[31m", false);
        log.finish("built").orElseThrow();
        List<JsonNode> r = records(c, b);
        assertTrue(r.get(0).path("cut").asBoolean());
        assertEquals("esc " + (char) 0x1b + "[31m", r.get(1).path("t").asText());
        try (InputStream in = store.open(BUCKET, ObjectKeys.logChunk(c, b, 1))) {
            String raw = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            assertFalse(raw.indexOf((char) 0x1b) >= 0, "a control character is stored escaped, never raw");
        }
    }

    @Test
    void aTransientStoreFailureIsRetried() throws Exception {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        AtomicInteger failures = new AtomicInteger(2);
        ObjectStore flaky = new ForwardingObjectStore(store) {
            @Override
            public Optional<StoredObject> putIfAbsent(String bucket, String key, byte[] content, String type) {
                if (key.contains("/chunks/") && failures.getAndDecrement() > 0) {
                    throw new ObjectStoreException("simulated 503");
                }
                return super.putIfAbsent(bucket, key, content, type);
            }
        };
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(flaky, BUCKET), c, b, 1, SMALL);
        log.line("survives", false);
        LogFinal fin = log.finish("built").orElseThrow();
        assertFalse(log.failed());
        assertTrue(fin.complete());
        assertEquals("survives", records(c, b).get(0).path("t").asText());
    }

    /** A store whose first chunk put is APPLIED and then reported as "outcome unknown". */
    private static ObjectStore landsThenThrows(ObjectStore under, Runnable afterLanding) {
        AtomicInteger once = new AtomicInteger(1);
        return new ForwardingObjectStore(under) {
            @Override
            public Optional<StoredObject> putIfAbsent(String bucket, String key, byte[] content, String type) {
                Optional<StoredObject> r = super.putIfAbsent(bucket, key, content, type);
                if (key.contains("/chunks/") && once.getAndDecrement() > 0) {
                    afterLanding.run();
                    throw new ObjectStoreException("outcome unknown: simulated timeout after the request began");
                }
                return r;
            }
        };
    }

    @Test
    void anUnknownOutcomeThatLandedIsThisWritersOwnChunk() throws Exception {
        // 0adc78e-F1: the put landed, then the store said "outcome unknown". The retry's
        // create-only put answers "exists"; the bytes are this writer's, so the log goes on.
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(landsThenThrows(store, () -> { }), BUCKET), c, b, 1, SMALL);
        log.line("written once", false);
        LogFinal fin = log.finish("built").orElseThrow(() -> new AssertionError(log.failure()));
        assertFalse(log.failed(), log.failure());
        assertTrue(fin.complete());
        assertEquals(1, chunks(c, b));
        assertEquals("written once", records(c, b).get(0).path("t").asText());
    }

    @Test
    void anUnknownOutcomeWithDifferentBytesThereIsNotOurs() {
        // The attempt "landed", but by the time of the retry a different body sits at the
        // sequence: not this writer's, so the log fails.
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        ObjectStore swapped = landsThenThrows(store, () -> {
            client.deleteObject(r -> r.bucket(BUCKET).key(ObjectKeys.logChunk(c, b, 1)));
            store.putIfAbsent(BUCKET, ObjectKeys.logChunk(c, b, 1),
                    "{\"n\":1,\"t\":\"theirs\"}\n".getBytes(StandardCharsets.UTF_8), "application/x-ndjson");
        });
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(swapped, BUCKET), c, b, 1, SMALL);
        log.line("mine", false);
        assertEquals(Optional.empty(), log.finish("built"));
        assertTrue(log.failure().contains("not this writer's"), log.failure());
    }

    @Test
    void aStoredChunkIsOursOnlyIfItIsExactlyOurBytes() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        BuildLogWriter writer = new BuildLogWriter(store, BUCKET);
        byte[] ours = "{\"n\":1,\"t\":\"a\"}\n".getBytes(StandardCharsets.UTF_8);
        byte[] longer = "{\"n\":1,\"t\":\"a\"}\n{\"n\":2,\"t\":\"b\"}\n".getBytes(StandardCharsets.UTF_8);
        writer.appendChunk(c, b, 1, longer);
        assertFalse(writer.chunkEquals(c, b, 1, ours), "a chunk that merely starts with our bytes is not ours");
        assertTrue(writer.chunkEquals(c, b, 1, longer));
    }

    @Test
    void anUnknownOutcomeThatCannotBeReadBackIsReportedAsUnknown() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        ObjectStore unreadable = new ForwardingObjectStore(landsThenThrows(store, () -> { })) {
            @Override
            public InputStream open(String bucket, String key) {
                throw new ObjectStoreException("simulated read failure");
            }
        };
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(unreadable, BUCKET), c, b, 1, SMALL);
        log.line("mine", false);
        assertEquals(Optional.empty(), log.finish("built"));
        assertTrue(log.failure().contains("outcome unknown") && log.failure().contains("could not be read back"),
                log.failure());
    }

    @Test
    void aStoreThatStaysDownFailsTheLog() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        AtomicInteger tries = new AtomicInteger();
        ObjectStore down = new ForwardingObjectStore(store) {
            @Override
            public Optional<StoredObject> putIfAbsent(String bucket, String key, byte[] content, String type) {
                if (key.contains("/chunks/")) {
                    tries.incrementAndGet();
                    throw new ObjectStoreException("simulated outage");
                }
                return super.putIfAbsent(bucket, key, content, type);
            }
        };
        AtomicLong now = new AtomicLong();
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(down, BUCKET), c, b, 1, SMALL, now::get);
        log.line("lost", false);
        now.addAndGet(Duration.ofSeconds(2).toNanos());
        log.tick();
        assertTrue(log.failed(), "the build must be told");
        assertEquals(3, tries.get(), "bounded: writeAttempts tries");
        assertTrue(log.failure().contains("simulated outage"), log.failure());
        log.line("more", false);
        assertEquals(Optional.empty(), log.finish("built"), "no final.json for a log that failed");
        assertEquals(3, tries.get(), "nothing more is tried once failed");
        assertTrue(new BuildLogWriter(store, BUCKET).readFinal(c, b).isEmpty());
    }

    @Test
    void aChunkSomeoneElseWroteFailsTheLog() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        new BuildLogWriter(store, BUCKET).appendChunk(c, b, 1, "{\"n\":1,\"t\":\"theirs\"}\n".getBytes(StandardCharsets.UTF_8));
        HeadTailLog log = new HeadTailLog(new BuildLogWriter(store, BUCKET), c, b, 1, SMALL);
        log.line("mine", false);
        assertEquals(Optional.empty(), log.finish("built"));
        assertTrue(log.failure().contains("already exists"), log.failure());
    }

    @Test
    void aNewerGenerationsLogIsNotFinishedByAnOlderWriter() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        BuildLogWriter writer = new BuildLogWriter(store, BUCKET);
        HeadTailLog old = new HeadTailLog(writer, c, b, 1, SMALL);
        old.line("old", false);
        old.tick();
        writer.publishIndex(c, b, 2);
        assertEquals(Optional.empty(), old.finish("built"), "final.json refused to generation 1");
    }

    @Test
    void limitsThatCouldNeverWriteALineAreRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> new Limits(2000, 2000, 1000, Duration.ofSeconds(2), 1000, 3, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new Limits(0, 2000, 10, Duration.ofSeconds(2), 1000, 3, Duration.ZERO));
        assertTrue(Limits.defaults().headBytes() == 1 << 20);
    }
}
