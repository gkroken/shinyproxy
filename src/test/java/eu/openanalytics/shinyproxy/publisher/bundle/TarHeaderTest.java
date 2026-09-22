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

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The header parser, fed headers built the way T2's corpus builds them.
 *
 * <p>{@code header(...)} below is a transliteration of {@code raw_header} in
 * {@code dev/fixtures/bundles/generate.py}, down to the checksum being written as six octal
 * digits followed by NUL and space. The corpus can express a negative size, an overflowing
 * one and a checksum that is simply wrong, because no tar writer will do any of that for
 * you — and those are exactly the headers an extractor's arithmetic has to survive.
 */
public class TarHeaderTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    @Test
    public void anOrdinaryHeaderParses() {
        TarHeader header = TarHeader.parse(header("app/app.R", "00000000123", '0'), LIMITS);
        assertEquals(TarHeader.Kind.REGULAR, header.kind());
        assertEquals(0123, header.size(), "the size field is octal, not decimal");
        assertEquals(0644, header.mode());
        assertEquals("app/app.R", nameOf(header));

        TarHeader implicit = TarHeader.parse(header("app/app.R", "00000000000", (char) 0), LIMITS);
        assertEquals(TarHeader.Kind.REGULAR, implicit.kind(),
                "a NUL typeflag is the old spelling of a regular file");
    }

    @Test
    public void theFourKindsAreTheOnlyWayOut() {
        assertEquals(TarHeader.Kind.REGULAR,
                TarHeader.parse(header("app/a", "00000000000", '0'), LIMITS).kind());
        assertEquals(TarHeader.Kind.DIRECTORY,
                TarHeader.parse(header("app/d/", "00000000000", '5'), LIMITS).kind());
        assertEquals(TarHeader.Kind.PAX_EXTENDED,
                TarHeader.parse(header("app/a", "00000000064", 'x'), LIMITS).kind());
        assertEquals(TarHeader.Kind.GNU_LONG_NAME,
                TarHeader.parse(header("././@LongLink", "00000000064", 'L'), LIMITS).kind());

        for (char flag : new char[] {'1', '2', '3', '4', '6', '7', 'g', 'K', 'S',
                                     'D', 'M', 'N', 'V'}) {
            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> TarHeader.parse(header("app/x", "00000000000", flag), LIMITS),
                    "typeflag '" + flag + "' was accepted");
            assertEquals(BundleRule.ENTRY_TYPE_NOT_ALLOWED, ex.rule(), "typeflag " + flag);
        }

        // type-unknown-typeflag: a flag no standard defines, and the corpus's own 'Z'.
        BundleRejection unknown = assertThrows(BundleRejection.class,
                () -> TarHeader.parse(header("app/mystery.bin", "00000000004", 'Z'), LIMITS));
        assertEquals(BundleRule.ENTRY_TYPE_UNKNOWN, unknown.rule());
    }

    @Test
    public void aWrongChecksumIsNotAnEndOfArchive() {
        // bomb-bad-checksum. The library behaviour this replaces reads an unparseable header
        // as the end of the archive and returns cleanly, which is an accept.
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> TarHeader.parse(badChecksum("app/bad.txt", "00000000004"), LIMITS));
        assertEquals(BundleRule.HEADER_CHECKSUM_MISMATCH, ex.rule());
        assertTrue(ex.getMessage().contains("not a number"),
                "the corpus writes '9999999', which is not octal: " + ex.getMessage());

        // And a checksum that IS a number and is simply wrong. Without this case the sum
        // comparison has nothing testing it: removing the comparison entirely survived,
        // because the only bad checksum in the suite was caught by the octal parse instead.
        byte[] wrongSum = header("app/bad.txt", "00000000004", '0');
        long sum = 0;
        for (int i = 0; i < TarHeader.BLOCK; i++) {
            sum += (i >= 148 && i < 156) ? ' ' : (wrongSum[i] & 0xFF);
        }
        writeField(wrongSum, 148, 8, String.format("%06o\0 ", sum + 1));
        BundleRejection off = assertThrows(BundleRejection.class,
                () -> TarHeader.parse(wrongSum, LIMITS),
                "a header off by one in its checksum was accepted");
        assertEquals(BundleRule.HEADER_CHECKSUM_MISMATCH, off.rule());
        assertTrue(off.getMessage().contains("sum to"), off.getMessage());
    }

    @Test
    public void theSignedChecksumSpellingIsAcceptedToo() {
        // A byte above 0x7f makes the two sums differ, which is the only case where the
        // fallback is doing anything. Without such a byte this test would pass against a
        // parser that had no fallback at all.
        byte[] block = header("app/café.txt", "00000000000", '0');
        long unsigned = 0;
        long signed = 0;
        for (int i = 0; i < TarHeader.BLOCK; i++) {
            int masked = (i >= 148 && i < 156) ? ' ' : (block[i] & 0xFF);
            unsigned += masked;
            signed += (i >= 148 && i < 156) ? ' ' : block[i];
        }
        assertTrue(signed != unsigned, "the fixture has no high-bit byte, so it proves nothing");

        writeField(block, 148, 8, String.format("%06o\0 ", signed));
        assertEquals(TarHeader.Kind.REGULAR, TarHeader.parse(block, LIMITS).kind());
    }

    @Test
    public void aNegativeSizeIsNotANumber() {
        // bomb-declared-size-negative: written straight into the field, since no tar writer
        // emits it. Arithmetic that trusts it underflows a running total.
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> TarHeader.parse(header("app/neg.bin", "-0000000001", '0'), LIMITS));
        assertEquals(BundleRule.HEADER_MALFORMED_NUMBER, ex.rule());
        // Which branch refused it matters. The overflow guard reports the same rule with a
        // different message, and removing the octal check entirely used to leave this test
        // passing through that guard instead — a case passing for a reason it was not
        // written to test.
        assertTrue(ex.getMessage().contains("is not octal"),
                "refused by the wrong branch: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("size"), ex.getMessage());
    }

    @Test
    public void anEnormousSizeIsReadCorrectlyAndThenRefused() {
        // bomb-declared-size-overflow: all sevens, near 2^36. Refused under the default
        // bound — and parsed correctly under a raised one, which is the half that shows the
        // number was understood rather than merely rejected.
        assertEquals(BundleRule.ENTRY_TOO_LARGE, assertThrows(BundleRejection.class,
                () -> TarHeader.parse(header("app/huge.bin", "77777777777", '0'), LIMITS)).rule());

        ExtractionLimits raised = ExtractionLimits.fromOverrides(Map.of("max_file_bytes",
                Long.toString(ExtractionLimits.declaration(
                        ExtractionLimits.Bound.MAX_FILE_BYTES).absoluteMax())));
        assertEquals(077777777777L,
                TarHeader.parse(header("app/huge.bin", "77777777777", '0'), raised).size());
    }

    @Test
    public void thePerFileBoundIsAPair() {
        long max = LIMITS.maxFileBytes();
        assertEquals(max, TarHeader.parse(
                header("app/at.bin", String.format("%011o", max), '0'), LIMITS).size());
        assertEquals(BundleRule.ENTRY_TOO_LARGE, assertThrows(BundleRejection.class,
                () -> TarHeader.parse(header("app/over.bin", String.format("%011o", max + 1),
                        '0'), LIMITS)).rule());
    }

    @Test
    public void base256NumbersAreRefusedRatherThanMisread() {
        byte[] block = header("app/a", "00000000000", '0');
        block[124] = (byte) 0x80;
        // The checksum has to be recomputed, or this case is refused for the checksum and
        // the base-256 rule is never reached — which is what the first version did. A real
        // GNU archive using base-256 has a valid checksum over it.
        reChecksum(block);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> TarHeader.parse(block, LIMITS));
        assertEquals(BundleRule.HEADER_BASE256_NUMBER, ex.rule());
    }

    @Test
    public void privilegedModeBitsNeverSurviveTheHeader() {
        for (int mode : new int[] {04755, 02755, 01755}) {
            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> TarHeader.parse(header("app/bin/run.sh", "00000000000", '0',
                            String.format("%07o", mode), false), LIMITS),
                    String.format("mode 0%o was accepted", mode));
            assertEquals(BundleRule.ENTRY_MODE_PRIVILEGED, ex.rule());
        }
        // pos-executable-bit: an ordinary executable is not a privileged one.
        assertEquals(0755, TarHeader.parse(header("app/bin/run.sh", "00000000000", '0',
                "0000755", false), LIMITS).mode());
    }

    @Test
    public void aDirectoryDeclaringContentWouldMoveTheReadHead() {
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> TarHeader.parse(header("app/www/", "00000001000", '5'), LIMITS));
        assertEquals(BundleRule.ENTRY_DIRECTORY_WITH_CONTENT, ex.rule());
        assertEquals(TarHeader.Kind.DIRECTORY,
                TarHeader.parse(header("app/www/", "00000000000", '5'), LIMITS).kind());
    }

    @Test
    public void theMagicDecidesWhetherThisIsTarAtAll() {
        byte[] block = header("app/a", "00000000000", '0');
        writeField(block, 257, 6, "xxxxx\0");
        reChecksum(block);
        assertEquals(BundleRule.HEADER_NOT_USTAR,
                assertThrows(BundleRejection.class, () -> TarHeader.parse(block, LIMITS)).rule());

        byte[] gnu = header("app/a", "00000000000", '0');
        writeField(gnu, 257, 8, "ustar  \0");
        reChecksum(gnu);
        assertEquals(TarHeader.Kind.REGULAR, TarHeader.parse(gnu, LIMITS).kind(),
                "GNU's magic spelling is still tar, and the corpus is written in it");
    }

    @Test
    public void theEndOfArchiveMarkerIsNotAHeader() {
        byte[] zero = new byte[TarHeader.BLOCK];
        assertTrue(TarHeader.isAllZero(zero));
        assertFalse(TarHeader.isAllZero(header("app/a", "00000000000", '0')));
        assertThrows(BundleRejection.class, () -> TarHeader.parse(zero, LIMITS),
                "an all-zero block is the end marker and must not parse as a member");
    }

    // ------------------------------------------------------------------ helpers

    private static String nameOf(TarHeader header) {
        byte[] name = header.nameField();
        int end = 0;
        while (end < name.length && name[end] != 0) {
            end++;
        }
        return new String(name, 0, end, StandardCharsets.UTF_8);
    }

    private static byte[] header(String name, String sizeField, char typeFlag) {
        return header(name, sizeField, typeFlag, "0000644", false);
    }

    private static byte[] badChecksum(String name, String sizeField) {
        return header(name, sizeField, '0', "0000644", true);
    }

    /** A transliteration of raw_header() in dev/fixtures/bundles/generate.py. */
    private static byte[] header(String name, String sizeField, char typeFlag, String mode,
                                 boolean badChecksum) {
        byte[] block = new byte[TarHeader.BLOCK];
        writeField(block, 0, 100, name);
        writeField(block, 100, 8, mode + "\0");
        writeField(block, 108, 8, "0000000\0");
        writeField(block, 116, 8, "0000000\0");
        writeField(block, 124, 12, sizeField + "\0");
        writeField(block, 136, 12, "00000000000\0");
        block[156] = (byte) typeFlag;
        writeField(block, 257, 6, "ustar\0");
        writeField(block, 263, 2, "00");
        if (badChecksum) {
            writeField(block, 148, 8, "9999999\0");
        } else {
            reChecksum(block);
        }
        return block;
    }

    private static void reChecksum(byte[] block) {
        long sum = 0;
        for (int i = 0; i < TarHeader.BLOCK; i++) {
            sum += (i >= 148 && i < 156) ? ' ' : (block[i] & 0xFF);
        }
        writeField(block, 148, 8, String.format("%06o\0 ", sum));
    }

    private static void writeField(byte[] block, int offset, int length, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < length; i++) {
            block[offset + i] = i < bytes.length ? bytes[i] : 0;
        }
    }
}
