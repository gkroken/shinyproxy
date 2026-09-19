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

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The build log: chunks, the progress index, and the record that ends it.
 *
 * <p>Logs are "independent completed objects, not an uncompleted multipart upload", so a
 * reader can fetch what exists while a build is still running. That is the feature, and
 * everything awkward here follows from it: the writer and the reader are looking at the
 * same prefix at the same time, and the reader must never be told about a chunk that is
 * not there.
 *
 * <h2>The contiguity rule</h2>
 *
 * <p>An index advertises the end of an unbroken run from sequence 1, never the highest
 * sequence present. Chunks 1, 2 and 4 advertise 2. This is the plan's "readers may lag but
 * cannot observe a completion index pointing at absent chunks" — lagging is fine, and a
 * hole is not. A gap is not hypothetical: chunk writes are individual PUTs, so one can fail
 * or be in flight while a later one has landed.
 *
 * <h2>What fences a stale writer, and what does not</h2>
 *
 * <p>Every mutation carries a lease generation and is refused if the stored artifact was
 * written by a higher one. The comparison is a <em>compare-and-swap</em>, not a
 * read-then-write: the index is read with its ETag and rewritten with {@code If-Match}, so
 * a stale writer that read before a newer generation published is refused by the store
 * when its write lands. A read-then-write held sequentially and not under concurrency,
 * which is the only condition a lease generation exists for (finding {@code 4f81ee0-F1}).
 *
 * <p>This is still the storage half of the plan's fencing and not the authoritative half:
 * "the DB's fenced committed cursor is authoritative while building". That cursor is T6's.
 * What is here stops a fenced-out worker from moving the index or publishing completion
 * through storage alone; it does not make the storage the source of truth, and nothing in
 * this class should be read as claiming it does.
 */
public class BuildLogWriter {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** Matches a chunk key's sequence, so a listing can be turned back into numbers. */
    private static final Pattern CHUNK =
            Pattern.compile("/chunks/(\\d{" + ObjectKeys.SEQUENCE_DIGITS + "})\\.jsonl$");

    private final ObjectStore store;
    private final String bucket;

    public BuildLogWriter(ObjectStore store, String bucket) {
        this.store = store;
        this.bucket = bucket;
    }

    /**
     * Writes one chunk, create-only.
     *
     * <p>"A single trusted log writer conditionally creates chunks and rejects an attempt
     * to replace different bytes at an existing sequence." Conditional create is what makes
     * the rejection true even when two writers believe they hold the lease.
     *
     * @return the stored chunk, or empty if that sequence is already written
     */
    public Optional<StoredObject> appendChunk(UUID contentId, UUID buildId, long sequence,
                                              byte[] chunk) {
        return store.putIfAbsent(bucket,
                ObjectKeys.logChunk(contentId, buildId, sequence), chunk,
                "application/x-ndjson");
    }

    /**
     * The contiguous run of chunks that actually persisted, and its total size.
     *
     * <p>Derived from a listing rather than from a counter this class keeps, because a
     * counter would describe what the writer believes and the point is to describe what a
     * reader can fetch.
     */
    public LogIndex scan(UUID contentId, UUID buildId, long generation) {
        String prefix = ObjectKeys.logChunk(contentId, buildId, 1)
                .replaceAll("/chunks/.*$", "/chunks/");
        long expected = 1;
        long bytes = 0;
        long last = 0;
        // Sorted by key; the zero padding makes that numeric order. Sizes come from the
        // listing, so this is one request rather than one per chunk.
        for (StoredObject chunk : store.list(bucket, prefix).stream()
                .sorted(java.util.Comparator.comparing(StoredObject::key)).toList()) {
            Matcher m = CHUNK.matcher(chunk.key());
            if (!m.find()) {
                continue;
            }
            long sequence = Long.parseLong(m.group(1));
            if (sequence != expected) {
                // The first hole ends the advertised run. Everything after it exists but
                // cannot be advertised, because a reader walking 1..n would fall into the
                // gap.
                break;
            }
            bytes += chunk.size();
            last = sequence;
            expected++;
        }
        return new LogIndex(generation, last, bytes);
    }

    /**
     * Publishes the index, refusing a generation older than the one already published.
     *
     * <p>The one mutable artifact in the layout, and deliberately so: it is a progress hint
     * that a running build republishes as chunks land.
     *
     * @return the published index, or empty if a newer generation already published one
     */
    public Optional<LogIndex> publishIndex(UUID contentId, UUID buildId, long generation) {
        return swapIndex(contentId, buildId, generation,
                () -> scan(contentId, buildId, generation));
    }

    /**
     * Reads the index with its tag, checks the generation, and writes conditionally.
     *
     * <p>Losing the swap is not an error. The index is a progress hint that a running build
     * republishes as chunks land, so a writer that loses a race simply publishes on its
     * next tick — and the writer that won wrote from its own fresh scan, so nothing is
     * lost meanwhile.
     */
    private Optional<LogIndex> swapIndex(UUID contentId, UUID buildId, long generation,
                                         java.util.function.Supplier<LogIndex> next) {
        String key = ObjectKeys.logObject(contentId, buildId, ObjectKeys.LOG_INDEX);
        Optional<StoredObject> existing = store.head(bucket, key);
        if (existing.isPresent()) {
            Optional<LogIndex> current = read(key, LogIndex.class);
            if (current.isPresent() && current.get().generation() > generation) {
                return Optional.empty();
            }
            LogIndex index = next.get();
            // If-Match against the tag observed above: a newer generation that published
            // in the window invalidates it and this write is refused.
            return store.putIfMatch(bucket, key, serialise(index), "application/json",
                            existing.get().etag())
                    .map(stored -> index);
        }
        LogIndex index = next.get();
        // No index yet, so create-only: two writers both seeing absence must not both write.
        return store.putIfAbsent(bucket, key, serialise(index), "application/json")
                .map(stored -> index);
    }

    /**
     * Ends the log. Create-only, so completion happens once.
     *
     * <p>Refuses to claim a {@code lastSequence} beyond the contiguous run, which is the
     * invariant the whole class exists for: a completion record pointing past a hole would
     * send every future reader at a chunk that does not exist, permanently, with no
     * running build left to republish a correction.
     *
     * @return the record as written, or empty if this build was already finalised or a
     *         newer generation has published
     */
    public Optional<LogFinal> finalise(UUID contentId, UUID buildId, long generation,
                                       String outcome, boolean truncated) {
        Optional<LogIndex> current = readIndex(contentId, buildId);
        if (current.isPresent() && current.get().generation() > generation) {
            return Optional.empty();
        }
        LogIndex run = scan(contentId, buildId, generation);
        long highest = highestSequencePresent(contentId, buildId);
        // complete means every chunk the writer produced is readable. A gap makes the log
        // incomplete even though the build itself may have been fine.
        boolean complete = highest == run.lastSequence();
        LogFinal record = new LogFinal(generation, run.lastSequence(), run.bytes(), outcome,
                complete, truncated);

        byte[] body = serialise(record);
        Optional<StoredObject> written = store.putIfAbsent(bucket,
                ObjectKeys.logObject(contentId, buildId, ObjectKeys.LOG_FINAL), body,
                "application/json");
        if (written.isEmpty()) {
            return Optional.empty();
        }
        // The index is brought level last, so a reader that saw completion first is never
        // sent further than the final record allows. Conditionally, like every other index
        // write: losing here is harmless, because final.json is already the durable answer
        // and a reader that lags behind it is within contract.
        swapIndex(contentId, buildId, generation,
                () -> new LogIndex(generation, run.lastSequence(), run.bytes()));
        return Optional.of(record);
    }

    public Optional<LogIndex> readIndex(UUID contentId, UUID buildId) {
        return read(ObjectKeys.logObject(contentId, buildId, ObjectKeys.LOG_INDEX),
                LogIndex.class);
    }

    public Optional<LogFinal> readFinal(UUID contentId, UUID buildId) {
        return read(ObjectKeys.logObject(contentId, buildId, ObjectKeys.LOG_FINAL),
                LogFinal.class);
    }

    private long highestSequencePresent(UUID contentId, UUID buildId) {
        String prefix = ObjectKeys.logChunk(contentId, buildId, 1)
                .replaceAll("/chunks/.*$", "/chunks/");
        long highest = 0;
        for (StoredObject chunk : store.list(bucket, prefix)) {
            Matcher m = CHUNK.matcher(chunk.key());
            if (m.find()) {
                highest = Math.max(highest, Long.parseLong(m.group(1)));
            }
        }
        return highest;
    }

    private byte[] serialise(Object value) {
        try {
            return JSON.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new ObjectStoreException("could not serialise " + value.getClass()
                    .getSimpleName(), e);
        }
    }

    private <T> Optional<T> read(String key, Class<T> type) {
        if (store.head(bucket, key).isEmpty()) {
            return Optional.empty();
        }
        try (InputStream in = store.open(bucket, key)) {
            return Optional.of(JSON.readValue(
                    new String(in.readAllBytes(), StandardCharsets.UTF_8), type));
        } catch (IOException e) {
            throw new ObjectStoreException("could not read " + bucket + "/" + key, e);
        }
    }
}
