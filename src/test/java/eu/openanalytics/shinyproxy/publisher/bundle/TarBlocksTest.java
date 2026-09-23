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
package eu.openanalytics.shinyproxy.publisher.bundle;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The block layer: where an archive ends, how much of it there may be, and how long it may
 * take.
 *
 * <p>Two fixtures anchor this. {@code bomb-truncated-tar} is a gzip of the first kilobyte of
 * a tar body — an archive with no end-of-archive marker, which must not read as a shorter
 * archive. {@code bomb-many-empty-entries} is {@code max_entries + 100} empty files, which
 * cost one header each and almost no bytes, so a cap counted in bytes never fires on it.
 */
public class TarBlocksTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    @Test
    public void anArchiveEndsWithTwoZeroBlocksAndNothingElse() {
        byte[] archive = concat(block('a'), marker());
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS);

        assertArrayEquals(block('a'), blocks.nextHeader());
        assertNull(blocks.nextHeader(), "the marker ends the archive");
        assertNull(blocks.nextHeader(), "and it stays ended");
        assertEquals(1, blocks.entries());
    }

    @Test
    public void paddingAfterTheMarkerIsAllowedAndAnythingElseIsNot() {
        // Real tars pad to a 10 KiB record, so zeros after the marker are ordinary.
        byte[] padded = concat(concat(block('a'), marker()), zeros(4096));
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(padded), LIMITS);
        assertNotNull(blocks.nextHeader());
        assertNull(blocks.nextHeader());

        byte[] appended = concat(concat(block('a'), marker()), block('b'));
        TarBlocks second = new TarBlocks(new ByteArrayInputStream(appended), LIMITS);
        assertNotNull(second.nextHeader());
        BundleRejection ex = assertThrows(BundleRejection.class, second::nextHeader);
        assertEquals(BundleRule.ARCHIVE_TRAILING_DATA, ex.rule());
    }

    @Test
    public void anArchiveWithNoMarkerIsNotAShorterArchive() {
        // bomb-truncated-tar.
        byte[] halfAnArchive = concat(block('a'), block('b'));
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(halfAnArchive), LIMITS);
        assertNotNull(blocks.nextHeader());
        assertNotNull(blocks.nextHeader());
        BundleRejection ex = assertThrows(BundleRejection.class, blocks::nextHeader);
        assertEquals(BundleRule.ARCHIVE_NO_END_MARKER, ex.rule());
        assertTrue(ex.getMessage().contains("2 entries"), ex.getMessage());
    }

    @Test
    public void oneZeroBlockIsNeitherAnEndNorAHeader() {
        byte[] singleZero = concat(concat(block('a'), zeros(512)), block('b'));
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(singleZero), LIMITS);
        assertNotNull(blocks.nextHeader());
        BundleRejection ex = assertThrows(BundleRejection.class, blocks::nextHeader);
        assertEquals(BundleRule.ARCHIVE_NO_END_MARKER, ex.rule());
        assertTrue(ex.getMessage().contains("middle of the archive"), ex.getMessage());

        // A single zero block at the very end is a truncated marker, not a marker.
        byte[] oneBlockMarker = concat(block('a'), zeros(512));
        TarBlocks second = new TarBlocks(new ByteArrayInputStream(oneBlockMarker), LIMITS);
        assertNotNull(second.nextHeader());
        assertEquals(BundleRule.ARCHIVE_NO_END_MARKER,
                assertThrows(BundleRejection.class, second::nextHeader).rule());
    }

    @Test
    public void aPartialBlockIsATruncatedArchive() {
        byte[] partial = concat(block('a'), new byte[100]);
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(partial), LIMITS);
        assertNotNull(blocks.nextHeader());
        BundleRejection ex = assertThrows(BundleRejection.class, blocks::nextHeader);
        assertEquals(BundleRule.ARCHIVE_TAR_TRUNCATED, ex.rule());
        assertTrue(ex.getMessage().contains("100 bytes into a 512-byte block"), ex.getMessage());
    }

    @Test
    public void contentIsBoundedByItsDeclaredSizeAndThePaddingIsConsumed() throws Exception {
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] archive = concat(concat(block('a'), padded(payload)),
                                concat(block('b'), marker()));
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS);

        assertArrayEquals(block('a'), blocks.nextHeader());
        assertArrayEquals(payload, drain(blocks.content(payload.length)));
        // The next header is 'b', which is only true if the 507 bytes of padding were eaten.
        assertArrayEquals(block('b'), blocks.nextHeader());
        assertNull(blocks.nextHeader());
        assertEquals(payload.length, blocks.contentBytes());
    }

    @Test
    public void aCallerThatIgnoresTheContentDoesNotLoseTheArchive() throws Exception {
        // The same rule as GzipMember.close: a guarantee that holds only when the consumer
        // cooperates is not a guarantee. Here the consumer reads nothing at all.
        byte[] payload = new byte[1000];
        byte[] archive = concat(concat(block('a'), padded(payload)),
                                concat(block('b'), marker()));
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS);

        assertArrayEquals(block('a'), blocks.nextHeader());
        blocks.content(payload.length);                 // handed out, never read
        assertArrayEquals(block('b'), blocks.nextHeader());
        assertEquals(payload.length, blocks.contentBytes(),
                "the skipped bytes still count against the expanded bound");

        // And a consumer that reads half of it.
        TarBlocks partial = new TarBlocks(new ByteArrayInputStream(archive), LIMITS);
        assertArrayEquals(block('a'), partial.nextHeader());
        InputStream content = partial.content(payload.length);
        assertEquals(400, content.read(new byte[400], 0, 400));
        assertArrayEquals(block('b'), partial.nextHeader());
    }

    @Test
    public void aMemberThatOverrunsTheArchiveIsTruncation() {
        byte[] archive = concat(block('a'), zeros(200));
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS);
        assertNotNull(blocks.nextHeader());
        InputStream content = blocks.content(5000);
        assertEquals(BundleRule.ARCHIVE_TAR_TRUNCATED, assertThrows(BundleRejection.class,
                () -> drain(content)).rule());
    }

    @Test
    public void theEntryBoundCountsHeadersAndIsAPair() {
        ExtractionLimits three = ExtractionLimits.fromOverrides(Map.of("max_entries", "3"));

        TarBlocks atLimit = new TarBlocks(new ByteArrayInputStream(
                concat(concat(block('a'), block('b')), concat(block('c'), marker()))), three);
        assertNotNull(atLimit.nextHeader());
        assertNotNull(atLimit.nextHeader());
        assertNotNull(atLimit.nextHeader());
        assertNull(atLimit.nextHeader());

        TarBlocks overLimit = new TarBlocks(new ByteArrayInputStream(
                concat(concat(block('a'), block('b')),
                       concat(concat(block('c'), block('d')), marker()))), three);
        overLimit.nextHeader();
        overLimit.nextHeader();
        overLimit.nextHeader();
        BundleRejection ex = assertThrows(BundleRejection.class, overLimit::nextHeader);
        assertEquals(BundleRule.ENTRY_COUNT_EXCEEDED, ex.rule());

        // bomb-many-empty-entries: the headers cost almost no bytes, so a cap counted in
        // bytes would never fire. This asserts the bound is on headers by exceeding it with
        // an archive whose content is empty.
        assertEquals(0, overLimit.contentBytes());
    }

    @Test
    public void theExpandedBoundCountsBytesThatArrived() throws Exception {
        byte[] payload = new byte[1000];
        byte[] archive = concat(concat(block('a'), padded(payload)), marker());
        ExtractionLimits small = ExtractionLimits.fromOverrides(
                Map.of("max_expanded_bytes", "999"));

        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), small);
        blocks.nextHeader();
        InputStream content = blocks.content(payload.length);
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED, assertThrows(BundleRejection.class,
                () -> drain(content)).rule());

        // The accepted half of the pair, at exactly the bound.
        ExtractionLimits exact = ExtractionLimits.fromOverrides(
                Map.of("max_expanded_bytes", "1000"));
        TarBlocks ok = new TarBlocks(new ByteArrayInputStream(archive), exact);
        ok.nextHeader();
        assertEquals(1000, drain(ok.content(payload.length)).length);
    }

    @Test
    public void theDeadlineIsEnforcedWithoutWaitingForIt() throws Exception {
        // The clock is injected, so this measures the rule rather than the wall clock.
        AtomicLong now = new AtomicLong(0);
        byte[] archive = concat(concat(block('a'), block('b')), marker());
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS,
                now::get);

        assertNotNull(blocks.nextHeader());
        now.set(LIMITS.extractionDeadlineSeconds() * 1_000_000_000L - 1);
        assertNotNull(blocks.nextHeader(), "a nanosecond before the deadline is inside it");

        now.set(LIMITS.extractionDeadlineSeconds() * 1_000_000_000L);
        BundleRejection ex = assertThrows(BundleRejection.class, blocks::nextHeader);
        assertEquals(BundleRule.EXTRACTION_DEADLINE_EXCEEDED, ex.rule());
        assertTrue(ex.getMessage().contains("60-second"), ex.getMessage());
    }

    @Test
    public void theDeadlineAlsoStopsALongSingleMember() throws Exception {
        // A bound checked only between headers is no bound at all against one enormous
        // member, which is the shape a bomb takes.
        AtomicLong now = new AtomicLong(0);
        byte[] payload = new byte[100_000];
        byte[] archive = concat(concat(block('a'), padded(payload)), marker());
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS, now::get);

        blocks.nextHeader();
        InputStream content = blocks.content(payload.length);
        assertEquals(8192, content.read(new byte[8192], 0, 8192));
        now.set(LIMITS.extractionDeadlineSeconds() * 1_000_000_000L + 1);
        assertEquals(BundleRule.EXTRACTION_DEADLINE_EXCEEDED, assertThrows(BundleRejection.class,
                () -> content.read(new byte[8192], 0, 8192)).rule());
    }

    @Test
    public void aZeroTailIsBoundedBySomethingOtherThanTheClock() {
        // e079be4-F1. Padding is neither an entry nor content, so before this it was the one
        // region of an archive that no size bound reached: 256 MiB of trailing zeros was
        // accepted in 179 ms, and at that rate the deadline alone permits tens of gigabytes
        // of tail from an upload well inside max_compressed_bytes.
        ExtractionLimits four = ExtractionLimits.fromOverrides(Map.of("max_entries", "4"));

        // Four blocks of padding is the accepted half: real archives pad to a 10 KiB record.
        byte[] within = concat(concat(block('a'), marker()), zeros(4 * TarHeader.BLOCK));
        TarBlocks ok = new TarBlocks(new ByteArrayInputStream(within), four);
        assertNotNull(ok.nextHeader());
        assertNull(ok.nextHeader());

        byte[] beyond = concat(concat(block('a'), marker()), zeros(5 * TarHeader.BLOCK));
        TarBlocks over = new TarBlocks(new ByteArrayInputStream(beyond), four);
        assertNotNull(over.nextHeader());
        BundleRejection ex = assertThrows(BundleRejection.class, over::nextHeader);
        assertEquals(BundleRule.ENTRY_COUNT_EXCEEDED, ex.rule());
        assertTrue(ex.getMessage().contains("padding"),
                "the rejection has to say it is about the tail rather than about members: "
                        + ex.getMessage());

        // And the clock is not what stopped it: this clock never moves.
        TarBlocks frozen = new TarBlocks(new ByteArrayInputStream(beyond), four, () -> 0L);
        frozen.nextHeader();
        assertEquals(BundleRule.ENTRY_COUNT_EXCEEDED,
                assertThrows(BundleRejection.class, frozen::nextHeader).rule());
    }

    @Test
    public void aNegativeContentSizeIsACallerErrorRatherThanASkewedStream() {
        // e079be4-F2. Unguarded, content(-1) makes the padding computation consume one byte,
        // so every later block starts one byte late and the archive fails as truncated —
        // a real defect reported as something else entirely.
        byte[] archive = concat(concat(block('a'), block('B')), marker());
        TarBlocks blocks = new TarBlocks(new ByteArrayInputStream(archive), LIMITS);
        assertNotNull(blocks.nextHeader());

        assertThrows(IllegalArgumentException.class, () -> blocks.content(-1));

        // The control: zero is a legitimate size, and the stream stays aligned across it.
        assertEquals(0, drainQuietly(blocks.content(0)).length);
        assertEquals('B', blocks.nextHeader()[0],
                "the next header did not start where it should, so the guard is hiding a"
                        + " skew rather than preventing one");
    }

    private static byte[] drainQuietly(InputStream in) {
        try {
            return drain(in);
        } catch (IOException ex) {
            throw new AssertionError(ex);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] drain(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer, 0, buffer.length)) >= 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    /** A 512-byte block of one repeated non-zero byte, standing in for a header. */
    private static byte[] block(char fill) {
        byte[] out = new byte[TarHeader.BLOCK];
        java.util.Arrays.fill(out, (byte) fill);
        return out;
    }

    private static byte[] zeros(int count) {
        return new byte[count];
    }

    private static byte[] marker() {
        return new byte[2 * TarHeader.BLOCK];
    }

    /** Content padded to a block boundary, as tar stores it. */
    private static byte[] padded(byte[] content) {
        int padding = (TarHeader.BLOCK - (content.length % TarHeader.BLOCK)) % TarHeader.BLOCK;
        return java.util.Arrays.copyOf(content, content.length + padding);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] out = java.util.Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }
}
