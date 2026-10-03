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
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Optional;
import java.util.UUID;
import java.util.function.LongSupplier;

/**
 * One attempt's build log as it is kept: the HEAD, written live, and the TAIL, held in
 * memory and written when the attempt ends, with a cut marker between them if anything
 * in the middle was dropped (user decision 2026-10-02: an oversized log keeps head AND
 * tail, because a failed build's error is usually at its end).
 *
 * <p><b>Records.</b> Each chunk is JSON lines. A log line is {@code {"n":<line number from
 * 1>,"t":"<text>"}}, with {@code "cut":true} when the line was longer than the line limit
 * and was shortened. The marker is {@code {"cut":{"lines":L,"bytes":B}}}: L lines and B
 * record bytes were dropped between the head and the tail. Text is JSON-escaped, so a
 * terminal control sequence is stored as an escape, never raw; viewers still neutralise it
 * on display (T8).
 *
 * <p><b>Live, then not.</b> Head records are flushed as chunks at most every
 * {@code flushEvery} or {@code chunkBytes}, so an admin can read a running build. Once
 * the head budget is used, further records go only to the tail buffer, which keeps the
 * newest {@code tailBytes}. A reader then sees nothing new until the attempt ends: chunks
 * are immutable, so the middle can be dropped only by never writing it.
 *
 * <p><b>Storage failure.</b> A chunk write is retried a bounded number of times. If it
 * still fails, or a chunk already exists at the sequence (a writer this one does not
 * know), the log is {@link #failed()}: the caller must stop the build and report a log
 * failure rather than a silent success. The buffers are the only scratch space, and both
 * are bounded.
 *
 * <p>Thread-safe: the log follower feeds lines while the build's poll calls {@link #tick}.
 */
public final class HeadTailLog {

    /** The bounds. The defaults are this track's production values (T5 F6 carry (2)). */
    public record Limits(int headBytes, int tailBytes, int lineBytes, Duration flushEvery, int chunkBytes,
                         int writeAttempts, Duration retryPause) {

        public Limits {
            if (headBytes < 1 || tailBytes < 1 || lineBytes < 1 || chunkBytes < 1 || writeAttempts < 1
                    || flushEvery.isNegative() || retryPause.isNegative()) {
                throw new IllegalArgumentException("log limits must be positive");
            }
            // The largest record (a line of lineBytes that escapes to 6 bytes per byte, plus
            // its frame) must fit one chunk, or it could never be written.
            if ((long) lineBytes * 6 + 64 > chunkBytes) {
                throw new IllegalArgumentException("a line of " + lineBytes + " bytes may not fit a chunk of "
                        + chunkBytes);
            }
        }

        /** 1 MiB of head, 1 MiB of tail, 4 KiB lines, a chunk per 2 s or 256 KiB, 3 tries 1 s apart. */
        public static Limits defaults() {
            return new Limits(1 << 20, 1 << 20, 4096, Duration.ofSeconds(2), 256 << 10, 3, Duration.ofSeconds(1));
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final BuildLogWriter writer;
    private final UUID contentId;
    private final UUID buildId;
    private final long generation;
    private final Limits limits;
    private final LongSupplier nanoTime;

    private final ByteArrayOutputStream pending = new ByteArrayOutputStream();
    private long pendingSince = -1;
    private long sequence;
    private long headUsed;
    private boolean tailMode;
    private final ArrayDeque<byte[]> tail = new ArrayDeque<>();
    private long tailUsed;
    private long lines;
    private long droppedLines;
    private long droppedBytes;
    private String lastLine = "";
    private String failure;
    private boolean finished;

    public HeadTailLog(BuildLogWriter writer, UUID contentId, UUID buildId, long generation, Limits limits) {
        this(writer, contentId, buildId, generation, limits, System::nanoTime);
    }

    HeadTailLog(BuildLogWriter writer, UUID contentId, UUID buildId, long generation, Limits limits,
                LongSupplier nanoTime) {
        this.writer = writer;
        this.contentId = contentId;
        this.buildId = buildId;
        this.generation = generation;
        this.limits = limits;
        this.nanoTime = nanoTime;
    }

    /** Adds one line (without its newline); {@code cut} says it was shortened. Ignored once finished. */
    public synchronized void line(String text, boolean cut) {
        if (finished) {
            return;
        }
        lines++;
        lastLine = text;
        ObjectNode r = JSON.createObjectNode().put("n", lines).put("t", text);
        if (cut) {
            r.put("cut", true);
        }
        byte[] record = (r.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        if (!tailMode && headUsed + record.length > limits.headBytes()) {
            tailMode = true;
        }
        if (tailMode) {
            tail.addLast(record);
            tailUsed += record.length;
            while (tailUsed > limits.tailBytes() && tail.size() > 1) {
                byte[] gone = tail.removeFirst();
                tailUsed -= gone.length;
                droppedLines++;
                droppedBytes += gone.length;
            }
            return;
        }
        headUsed += record.length;
        if (pending.size() + record.length > limits.chunkBytes()) {
            flush();
        }
        if (pendingSince < 0) {
            pendingSince = nanoTime.getAsLong();
        }
        pending.writeBytes(record);
        tick();
    }

    /** Flushes the pending head records if they are due. Called on every line and by the build's poll. */
    public synchronized void tick() {
        if (finished || pending.size() == 0) {
            return;
        }
        if (pending.size() >= limits.chunkBytes()
                || nanoTime.getAsLong() - pendingSince >= limits.flushEvery().toNanos()) {
            flush();
        }
    }

    /** True once a chunk could not be persisted: the build must stop and report it. */
    public synchronized boolean failed() {
        return failure != null;
    }

    /** Why the log failed, or null. */
    public synchronized String failure() {
        return failure;
    }

    /** The last line added, for a failure's detail. */
    public synchronized String lastLine() {
        return lastLine;
    }

    /**
     * Ends the log: the rest of the head, the cut marker if anything was dropped, the tail,
     * then final.json with {@code outcome}. Empty if the log failed, or if final.json could
     * not be written (another writer finished it, or a newer generation published).
     */
    public synchronized Optional<LogFinal> finish(String outcome) {
        // A bad outcome is the caller's bug, not a storage failure: refused before anything
        // is written, and never turned into failed().
        LogFinal.requireOutcome(outcome);
        if (finished) {
            throw new IllegalStateException("the log is already finished");
        }
        flush();
        if (droppedLines > 0) {
            ObjectNode cut = JSON.createObjectNode();
            cut.putObject("cut").put("lines", droppedLines).put("bytes", droppedBytes);
            pending.writeBytes((cut.toString() + "\n").getBytes(StandardCharsets.UTF_8));
        }
        while (!tail.isEmpty()) {
            byte[] record = tail.peekFirst();
            if (pending.size() + record.length > limits.chunkBytes()) {
                flush();
            }
            pending.writeBytes(tail.removeFirst());
        }
        flush();
        finished = true;
        if (failure != null) {
            return Optional.empty();
        }
        try {
            return writer.finalise(contentId, buildId, generation, outcome, droppedLines > 0);
        } catch (RuntimeException e) {
            failure = "final.json: " + e.getMessage();
            return Optional.empty();
        }
    }

    /** Writes the pending records as the next chunk, retrying a bounded number of times. */
    private void flush() {
        if (pending.size() == 0 || failure != null) {
            return;
        }
        byte[] chunk = pending.toByteArray();
        String last = null;
        boolean unknown = false;
        for (int attempt = 1; attempt <= limits.writeAttempts(); attempt++) {
            try {
                if (writer.appendChunk(contentId, buildId, sequence + 1, chunk).isEmpty()) {
                    // "Exists". After an attempt that threw, that may be this writer's own
                    // write: the store retries only failures that prove nothing was applied,
                    // so what reaches here is "outcome unknown" (0adc78e-F1). Equal bytes are
                    // ours: this writer alone numbers chunks under its generation, and every
                    // record carries its line number. Anything else is not ours to go on.
                    if (!unknown) {
                        failure = "chunk " + (sequence + 1) + " already exists";
                        return;
                    }
                    boolean ours;
                    try {
                        ours = writer.chunkEquals(contentId, buildId, sequence + 1, chunk);
                    } catch (RuntimeException e) {
                        failure = "chunk " + (sequence + 1) + ": outcome unknown (" + last
                                + "), and it could not be read back: " + e.getMessage();
                        return;
                    }
                    if (!ours) {
                        failure = "chunk " + (sequence + 1) + " already exists, and is not this writer's";
                        return;
                    }
                }
                sequence++;
                pending.reset();
                pendingSince = -1;
                try {
                    writer.publishIndex(contentId, buildId, generation);
                } catch (RuntimeException e) {
                    // The index is a progress hint, republished on the next flush; the chunk
                    // is what had to persist.
                }
                return;
            } catch (RuntimeException e) {
                last = e.getMessage();
                unknown = true;
            }
            if (attempt < limits.writeAttempts()) {
                try {
                    Thread.sleep(limits.retryPause().toMillis() * attempt);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        failure = "chunk " + (sequence + 1) + " could not be written: " + last;
    }
}
