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
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gzip envelope, including the two shapes {@code GZIPInputStream} would have accepted.
 *
 * <p>Concatenated members and trailing bytes are the reason this layer exists rather than
 * being delegated: the stock reader joins members silently, so a bundle containing two would
 * mean one thing to it and another to any reader that stops at the first. Both fixtures are
 * in T2's corpus and both are asserted here against the same construction the corpus uses —
 * {@code archive + archive} and {@code archive + b"trailing, not padding\n"}.
 */
public class GzipMemberTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();
    private static final byte[] PAYLOAD =
            "the tar stream would be here\n".repeat(50).getBytes(StandardCharsets.UTF_8);

    @Test
    public void anOrdinaryMemberRoundTrips() throws Exception {
        assertArrayEquals(PAYLOAD, readFully(gzip(PAYLOAD), LIMITS));
    }

    @Test
    public void aSecondMemberIsRefusedRatherThanJoined() {
        byte[] one = gzip(PAYLOAD);
        byte[] two = concat(one, one);

        // The control: java.util.zip would read this as one stream of twice the payload.
        // That is the behaviour being refused, so it is worth showing it is what happens.
        assertEquals(PAYLOAD.length * 2, stockGzipLength(two),
                "if the stock reader stopped at the first member there would be nothing to"
                        + " protect against here");

        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> readFully(two, LIMITS));
        assertEquals(BundleRule.ARCHIVE_MULTIPLE_MEMBERS, ex.rule());
    }

    @Test
    public void bytesAfterTheMemberAreRefused() {
        byte[] appended = concat(gzip(PAYLOAD),
                "trailing, not padding\n".getBytes(StandardCharsets.UTF_8));
        BundleRejection ex = assertThrows(BundleRejection.class, () -> readFully(appended, LIMITS));
        assertEquals(BundleRule.ARCHIVE_TRAILING_DATA, ex.rule());
        assertTrue(ex.getMessage().contains("trailing"), ex.getMessage());
    }

    @Test
    public void aTruncatedMemberIsNotAShortOne() {
        byte[] whole = gzip(PAYLOAD);
        byte[] half = java.util.Arrays.copyOf(whole, whole.length / 2);
        assertEquals(BundleRule.ARCHIVE_GZIP_TRUNCATED,
                assertThrows(BundleRejection.class, () -> readFully(half, LIMITS)).rule());

        // One byte short of the trailer is the same defect at the other end of the member.
        byte[] almost = java.util.Arrays.copyOf(whole, whole.length - 1);
        assertEquals(BundleRule.ARCHIVE_GZIP_TRUNCATED,
                assertThrows(BundleRejection.class, () -> readFully(almost, LIMITS)).rule());
    }

    @Test
    public void theTrailerIsCheckedRatherThanSkipped() {
        byte[] badCrc = gzip(PAYLOAD);
        badCrc[badCrc.length - 8] ^= 0x01;
        assertEquals(BundleRule.ARCHIVE_GZIP_CORRUPT,
                assertThrows(BundleRejection.class, () -> readFully(badCrc, LIMITS)).rule());

        byte[] badSize = gzip(PAYLOAD);
        badSize[badSize.length - 4] ^= 0x01;
        BundleRejection ex = assertThrows(BundleRejection.class, () -> readFully(badSize, LIMITS));
        assertEquals(BundleRule.ARCHIVE_GZIP_CORRUPT, ex.rule());
        assertTrue(ex.getMessage().contains("uncompressed bytes"), ex.getMessage());
    }

    @Test
    public void whatIsNotAGzipMemberIsSaidSo() {
        assertEquals(BundleRule.ARCHIVE_NOT_GZIP, assertThrows(BundleRejection.class,
                () -> readFully("PK\u0003\u0004 a zip file".getBytes(StandardCharsets.UTF_8),
                        LIMITS)).rule());

        // The magic and the method need separate cases. A zip file fails both at once, so a
        // parser that had lost its magic check would still refuse it on the method and the
        // assertion above would pass while nothing tested the magic. This member's method
        // byte is a valid 8; only the magic is wrong.
        byte[] wrongMagic = gzip(PAYLOAD);
        wrongMagic[1] = (byte) 0x8C;
        assertEquals(8, wrongMagic[2], "the method byte must stay valid or this proves nothing");
        BundleRejection magic = assertThrows(BundleRejection.class,
                () -> readFully(wrongMagic, LIMITS));
        assertEquals(BundleRule.ARCHIVE_NOT_GZIP, magic.rule());
        assertTrue(magic.getMessage().contains("magic"), magic.getMessage());

        byte[] wrongMethod = gzip(PAYLOAD);
        wrongMethod[2] = 9;
        assertEquals(BundleRule.ARCHIVE_NOT_GZIP,
                assertThrows(BundleRejection.class, () -> readFully(wrongMethod, LIMITS)).rule());

        byte[] reservedFlags = gzip(PAYLOAD);
        reservedFlags[3] |= (byte) 0x20;
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> readFully(reservedFlags, LIMITS));
        assertEquals(BundleRule.ARCHIVE_NOT_GZIP, ex.rule());
        assertTrue(ex.getMessage().contains("reserved"), ex.getMessage());
    }

    @Test
    public void theOptionalHeaderFieldsAreSkippedNotMisread() throws Exception {
        // The corpus writes its members with a stored filename, and one fixture pair uses
        // that filename's length as a byte-exact lever. A parser that ignored FNAME would
        // read the name as deflate data and fail on an archive that is perfectly valid.
        assertArrayEquals(PAYLOAD, readFully(gzipWithName(PAYLOAD, "bundle.tar"), LIMITS));
        assertArrayEquals(PAYLOAD, readFully(gzipWithExtraAndComment(PAYLOAD), LIMITS));
    }

    @Test
    public void bothSizeBoundsStraddleTheirLimit() throws Exception {
        byte[] member = gzip(PAYLOAD);

        ExtractionLimits exact = limits("max_compressed_bytes", member.length);
        assertArrayEquals(PAYLOAD, readFully(member, exact), "a member of exactly the bound");
        GzipMember.checkUploadSize(member.length, exact);

        ExtractionLimits tooSmall = limits("max_compressed_bytes", member.length - 1);
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_COMPRESSED, assertThrows(BundleRejection.class,
                () -> readFully(member, tooSmall)).rule());
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_COMPRESSED, assertThrows(BundleRejection.class,
                () -> GzipMember.checkUploadSize(member.length, tooSmall)).rule(),
                "the front-door check and the streaming one must agree about the same member");

        ExtractionLimits expandedExact = limits("max_expanded_bytes", PAYLOAD.length);
        assertArrayEquals(PAYLOAD, readFully(member, expandedExact));
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED, assertThrows(BundleRejection.class,
                () -> readFully(member, limits("max_expanded_bytes", PAYLOAD.length - 1))).rule());
    }

    @Test
    public void anExpansionBombDiesWhileExpandingRatherThanAfterwards() {
        byte[] bomb = gzip(new byte[64 * 1024 * 1024]);
        assertTrue(bomb.length < 128 * 1024,
                "the fixture is only interesting if it is small: " + bomb.length);

        ExtractionLimits tight = limits("max_expanded_bytes", 1024);
        GzipMember member = GzipMember.open(new ByteArrayInputStream(bomb), tight);
        BundleRejection ex = assertThrows(BundleRejection.class, () -> drain(member));
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED, ex.rule());
        assertTrue(member.expandedBytes() < 1024 * 1024,
                "it produced " + member.expandedBytes() + " bytes before stopping, which is"
                        + " most of the way through a bomb it was supposed to refuse early");
    }

    // ------------------------------------------------------------------ helpers

    private static ExtractionLimits limits(String bound, long value) {
        return ExtractionLimits.fromOverrides(Map.of(bound, Long.toString(value)));
    }

    private static byte[] readFully(byte[] archive, ExtractionLimits limits) throws IOException {
        try (GzipMember member = GzipMember.open(new ByteArrayInputStream(archive), limits)) {
            return drain(member);
        }
    }

    private static byte[] drain(GzipMember member) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = member.read(buffer, 0, buffer.length)) >= 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private static byte[] gzip(byte[] data) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
                gz.write(data);
            }
            return out.toByteArray();
        } catch (IOException ex) {
            throw new AssertionError(ex);
        }
    }

    /** A member carrying FNAME, which {@code GZIPOutputStream} never writes and gzip(1) does. */
    private static byte[] gzipWithName(byte[] data, String name) {
        return handBuilt(data, 8, concat(name.getBytes(StandardCharsets.UTF_8), new byte[] {0}));
    }

    /** A member carrying FEXTRA and FCOMMENT. */
    private static byte[] gzipWithExtraAndComment(byte[] data) {
        byte[] extra = new byte[] {4, 0, 'a', 'b', 'c', 'd'};      // length 4, then 4 bytes
        byte[] comment = "a comment\0".getBytes(StandardCharsets.UTF_8);
        return handBuilt(data, 4 | 16, concat(extra, comment));
    }

    private static byte[] handBuilt(byte[] data, int flags, byte[] optional) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new byte[] {0x1F, (byte) 0x8B, 8, (byte) flags, 0, 0, 0, 0, 0, 0});
            out.write(optional);
            Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
            try (DeflaterOutputStream deflated = new DeflaterOutputStream(out, deflater)) {
                deflated.write(data);
            }
            deflater.end();
            CRC32 crc = new CRC32();
            crc.update(data);
            out.write(littleEndian(crc.getValue()));
            out.write(littleEndian(data.length));
            return out.toByteArray();
        } catch (IOException ex) {
            throw new AssertionError(ex);
        }
    }

    private static byte[] littleEndian(long value) {
        return new byte[] {(byte) value, (byte) (value >> 8), (byte) (value >> 16),
                           (byte) (value >> 24)};
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] out = java.util.Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }

    /** What {@code java.util.zip} makes of the same bytes, used as a control. */
    private static int stockGzipLength(byte[] archive) {
        try (InputStream in = new java.util.zip.GZIPInputStream(new ByteArrayInputStream(archive))) {
            return in.readAllBytes().length;
        } catch (IOException ex) {
            throw new AssertionError(ex);
        }
    }
}
