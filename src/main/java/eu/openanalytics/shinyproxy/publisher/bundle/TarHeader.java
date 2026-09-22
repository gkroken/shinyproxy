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

import java.util.Arrays;

/**
 * One 512-byte tar header, parsed by hand.
 *
 * <p><b>Why by hand.</b> T2 established it by demonstration rather than argument: an
 * extractor built on a tar library accepts {@code bomb-bad-checksum} and
 * {@code bomb-declared-size-negative} — a lenient parser reads an unparseable header as the
 * end of the archive and returns cleanly, which is an accept — accepts
 * {@code bomb-huge-pax-field} because the library never reports an extended header's own
 * size, and accepts {@code trav-pax-override} because it does not apply the override and so
 * never checks the effective path. The extraction contract's answer is that "any library
 * unable to expose these distinctions is unsuitable without an outer validator", so the
 * bytes are read here before anything else sees them.
 *
 * <p><b>Only four kinds get out of this class.</b> Everything else — links, devices, FIFOs,
 * sockets, contiguous files, sparse members, global PAX headers, unknown typeflags — is
 * refused at parse. A walk that never receives a symlink header cannot forget to handle one,
 * which is worth more than the flexibility of passing the typeflag along.
 *
 * <p><b>What is deliberately not accepted.</b> GNU's base-256 numeric encoding is refused.
 * It exists to express values that do not fit in the octal field: sizes above 8 GiB, and
 * uids or timestamps beyond the ordinary range. A bundle needs none of those — ownership is
 * stripped, timestamps are stripped, and the per-file bound defaults three orders of
 * magnitude below 8 GiB. Accepting it would mean parsing a second numeric format, with
 * sign handling, for no case this format has. An operator who raises the per-file bound
 * above 8 GiB will find such a member refused with this rule named, which is a better
 * outcome than a silently misread size.
 */
public record TarHeader(byte[] nameField, byte[] prefixField, Kind kind, int mode, long size) {

    /** The block size every tar structure is a multiple of. */
    public static final int BLOCK = 512;

    private static final int NAME = 0;
    private static final int MODE = 100;
    private static final int UID = 108;
    private static final int GID = 116;
    private static final int SIZE = 124;
    private static final int MTIME = 136;
    private static final int CHECKSUM = 148;
    private static final int TYPEFLAG = 156;
    private static final int LINKNAME = 157;
    private static final int MAGIC = 257;
    private static final int PREFIX = 345;

    private static final int SETUID = 04000;
    private static final int SETGID = 02000;
    private static final int STICKY = 01000;

    /** The four header kinds a bundle may contain. */
    public enum Kind {
        /** A regular file, whose content follows in the next blocks. */
        REGULAR,
        /** A directory header. */
        DIRECTORY,
        /** A PAX per-file extended header, whose records describe the member after it. */
        PAX_EXTENDED,
        /** A GNU long-name header, whose content is the name of the member after it. */
        GNU_LONG_NAME
    }

    /** True for the all-zero block that begins the end-of-archive marker. */
    public static boolean isAllZero(byte[] block) {
        for (byte b : block) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Parses one header block.
     *
     * @throws BundleRejection naming the rule, for anything this format does not carry
     */
    public static TarHeader parse(byte[] block, ExtractionLimits limits) {
        if (block.length != BLOCK) {
            throw new IllegalArgumentException("a tar header is " + BLOCK + " bytes, not "
                    + block.length);
        }
        if (isAllZero(block)) {
            throw new BundleRejection(BundleRule.HEADER_CHECKSUM_MISMATCH,
                    "an all-zero block was parsed as a header; it is the end-of-archive"
                            + " marker and belongs to the walk, not here");
        }

        verifyChecksum(block);
        verifyMagic(block);

        int mode = (int) octal(block, MODE, 8, "mode");
        if ((mode & (SETUID | SETGID | STICKY)) != 0) {
            throw new BundleRejection(BundleRule.ENTRY_MODE_PRIVILEGED,
                    String.format("mode 0%o carries a setuid, setgid or sticky bit, which an"
                            + " extracted bundle never needs and must never receive", mode));
        }
        // Parsed and discarded: ownership and timestamps are stripped, but a field that does
        // not parse means a header this parser does not understand, and understanding it is
        // the whole job.
        octal(block, UID, 8, "uid");
        octal(block, GID, 8, "gid");
        octal(block, MTIME, 12, "mtime");

        long size = octal(block, SIZE, 12, "size");
        Kind kind = kindOf(block[TYPEFLAG]);

        if (kind == Kind.DIRECTORY && size != 0) {
            throw new BundleRejection(BundleRule.ENTRY_DIRECTORY_WITH_CONTENT,
                    "a directory header declaring " + size + " bytes of content; the bytes"
                            + " would move the read head and the member after it would be"
                            + " read from the wrong place");
        }
        if (kind == Kind.REGULAR && size > limits.maxFileBytes()) {
            throw new BundleRejection(BundleRule.ENTRY_TOO_LARGE,
                    "a member declaring " + size + " bytes, over the configured "
                            + limits.maxFileBytes());
        }

        return new TarHeader(Arrays.copyOfRange(block, NAME, NAME + 100),
                Arrays.copyOfRange(block, PREFIX, PREFIX + 155), kind, mode, size);
    }

    private static void verifyChecksum(byte[] block) {
        long stored;
        try {
            stored = octal(block, CHECKSUM, 8, "checksum");
        } catch (BundleRejection ex) {
            // The corpus writes '9999999' here, and '9' is not an octal digit. A checksum
            // field that is not a number is a checksum that does not match — reporting it as
            // a malformed field would name the wrong rule for the oldest attack in the set.
            throw new BundleRejection(BundleRule.HEADER_CHECKSUM_MISMATCH,
                    "the header checksum field is not a number: " + ex.getMessage());
        }
        long unsigned = 0;
        long signed = 0;
        for (int i = 0; i < BLOCK; i++) {
            int b = (i >= CHECKSUM && i < CHECKSUM + 8) ? ' ' : (block[i] & 0xFF);
            unsigned += b;
            signed += (i >= CHECKSUM && i < CHECKSUM + 8) ? ' ' : block[i];
        }
        // Both sums are accepted because both were written by real tars: the standard is the
        // unsigned one, and implementations on platforms with a signed char produced the
        // other. A header whose checksum is simply wrong matches neither.
        if (stored != unsigned && stored != signed) {
            throw new BundleRejection(BundleRule.HEADER_CHECKSUM_MISMATCH,
                    "the header checksum is " + stored + " and its bytes sum to " + unsigned
                            + "; a parser that skipped past this would be reading"
                            + " attacker-chosen bytes as a header");
        }
    }

    private static void verifyMagic(byte[] block) {
        byte[] magic = Arrays.copyOfRange(block, MAGIC, MAGIC + 8);
        boolean posix = magic[0] == 'u' && magic[1] == 's' && magic[2] == 't' && magic[3] == 'a'
                && magic[4] == 'r' && magic[5] == 0;
        boolean gnu = magic[0] == 'u' && magic[1] == 's' && magic[2] == 't' && magic[3] == 'a'
                && magic[4] == 'r' && magic[5] == ' ' && magic[6] == ' ';
        if (!posix && !gnu) {
            throw new BundleRejection(BundleRule.HEADER_NOT_USTAR,
                    "the header magic is '" + BundleRejection.render(magic) + "', which is"
                            + " neither POSIX ustar nor GNU tar");
        }
    }

    private static Kind kindOf(byte typeFlag) {
        switch (typeFlag) {
            case 0:
            case '0':
                return Kind.REGULAR;
            case '5':
                return Kind.DIRECTORY;
            case 'x':
                return Kind.PAX_EXTENDED;
            case 'L':
                return Kind.GNU_LONG_NAME;
            case '1':
                throw notAllowed(typeFlag, "a hard link");
            case '2':
                throw notAllowed(typeFlag, "a symbolic link");
            case '3':
                throw notAllowed(typeFlag, "a character device");
            case '4':
                throw notAllowed(typeFlag, "a block device");
            case '6':
                throw notAllowed(typeFlag, "a FIFO");
            case '7':
                throw notAllowed(typeFlag, "a contiguous file");
            case 'g':
                throw notAllowed(typeFlag, "a global PAX header, which changes the reading of"
                        + " members it does not name");
            case 'K':
                throw notAllowed(typeFlag, "a GNU long link name, and no member here may be"
                        + " a link");
            case 'S':
                throw notAllowed(typeFlag, "a GNU sparse member, whose encoding lets the"
                        + " declared and stored sizes disagree by design");
            case 'D':
            case 'M':
            case 'N':
            case 'V':
                throw notAllowed(typeFlag, "a GNU archive extension this format does not use");
            default:
                throw new BundleRejection(BundleRule.ENTRY_TYPE_UNKNOWN,
                        "typeflag '" + BundleRejection.render(new byte[] {typeFlag})
                                + "' is defined by no standard. A reader that treats anything"
                                + " unrecognised as a regular file materialises"
                                + " attacker-chosen bytes under an attacker-chosen name");
        }
    }

    private static BundleRejection notAllowed(byte typeFlag, String what) {
        return new BundleRejection(BundleRule.ENTRY_TYPE_NOT_ALLOWED,
                "typeflag '" + (char) typeFlag + "' is " + what + "; a bundle carries regular"
                        + " files and directories and nothing else");
    }

    /**
     * One numeric field: ASCII octal, terminated by NUL or space, possibly space-padded.
     *
     * <p>An empty field is zero, which is what a writer leaves in a field that does not
     * apply. Anything else that is not an octal digit — including the leading '-' that
     * writes a negative size — is a rejection rather than a best effort, and the running
     * multiply is checked before it happens rather than after it wraps.
     */
    static long octal(byte[] block, int offset, int length, String field) {
        if ((block[offset] & 0x80) != 0) {
            throw new BundleRejection(BundleRule.HEADER_BASE256_NUMBER,
                    "the " + field + " field uses GNU's base-256 encoding, which this"
                            + " extractor does not accept");
        }
        long value = 0;
        boolean seenDigit = false;
        for (int i = offset; i < offset + length; i++) {
            int c = block[i] & 0xFF;
            if (c == 0 || c == ' ') {
                if (seenDigit) {
                    break;      // terminator after the digits
                }
                continue;       // leading padding
            }
            if (c < '0' || c > '7') {
                throw new BundleRejection(BundleRule.HEADER_MALFORMED_NUMBER,
                        "the " + field + " field is not octal: '"
                                + BundleRejection.render(
                                        Arrays.copyOfRange(block, offset, offset + length))
                                + "'");
            }
            if (value > (Long.MAX_VALUE - (c - '0')) / 8) {
                throw new BundleRejection(BundleRule.HEADER_MALFORMED_NUMBER,
                        "the " + field + " field does not fit in a signed 64-bit integer");
            }
            value = value * 8 + (c - '0');
            seenDigit = true;
        }
        return value;
    }
}
