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

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Exactly one gzip member, decompressed under bounds, with nothing before or after it.
 *
 * <p><b>Why not {@code GZIPInputStream}.</b> It concatenates. Handed two members it reads
 * both and reports one stream, which is the behaviour the extraction contract rules out:
 * "accept a single bounded gzip member and tar end marker; reject concatenated
 * archives/members and non-padding trailing data". A reader that silently joins members and
 * a reader that stops at the first disagree about what the bundle contains, and an uploader
 * gets to choose which one a given consumer is. The corpus has that fixture. So the envelope
 * is parsed here instead — header, one deflate stream, trailer, end of input — and anything
 * after the trailer is a rejection with its own name depending on what it is.
 *
 * <p><b>Both size bounds are enforced while streaming</b>, not afterwards. The compressed
 * bound is checked against bytes actually consumed, so it holds for a stream whose length is
 * not known in advance as well as for a file whose length is; {@link #checkUploadSize} is
 * the cheaper front-door check for when it is known, and the two are deliberately the same
 * rule stated twice rather than one rule trusted twice. The expanded bound is checked
 * against bytes actually produced, which is what makes a small archive claiming to expand
 * into gigabytes die here rather than on the disk.
 *
 * <p><b>The checks do not depend on the caller draining.</b> A consumer that stops early —
 * a tar reader meeting the end-of-archive marker does exactly that — still gets them, because
 * {@link #close()} finishes the member when {@code read} has not. A rule enforced only when
 * the caller cooperates is not a rule, and nothing else in this class trusts the caller.
 *
 * <p>The trailer is verified rather than skipped. A gzip member whose CRC or length does not
 * match what came out of it is corrupt, and a lenient parser that ignores the trailer will
 * happily hand on attacker-chosen bytes — the same class of defect as the corpus's
 * bad-checksum tar header, one layer out.
 */
public final class GzipMember extends InputStream {

    private static final int BUFFER = 64 * 1024;

    private static final int FHCRC = 2;
    private static final int FEXTRA = 4;
    private static final int FNAME = 8;
    private static final int FCOMMENT = 16;
    private static final int RESERVED = 0xE0;

    private final InputStream source;
    private final ExtractionLimits limits;
    private final Inflater inflater = new Inflater(true);
    private final CRC32 crc = new CRC32();
    private final byte[] input = new byte[BUFFER];

    private int inputLength;
    private long compressedRead;
    private long expanded;
    private boolean verified;
    private boolean closed;

    private GzipMember(InputStream source, ExtractionLimits limits) {
        this.source = source;
        this.limits = limits;
    }

    /**
     * The compressed bound against a length already known — the first bound anything hits,
     * before a byte is parsed.
     */
    public static void checkUploadSize(long bytes, ExtractionLimits limits) {
        if (bytes > limits.maxCompressedBytes()) {
            throw new BundleRejection(BundleRule.ARCHIVE_TOO_LARGE_COMPRESSED,
                    "the upload is " + bytes + " bytes, over the configured "
                            + limits.maxCompressedBytes());
        }
    }

    /** Reads and validates the member header; the returned stream yields the member's data. */
    public static GzipMember open(InputStream source, ExtractionLimits limits) {
        GzipMember member = new GzipMember(source, limits);
        member.readHeader();
        return member;
    }

    private void readHeader() {
        int magic1 = required("the gzip magic");
        int magic2 = required("the gzip magic");
        if (magic1 != 0x1F || magic2 != 0x8B) {
            throw new BundleRejection(BundleRule.ARCHIVE_NOT_GZIP,
                    String.format("the upload does not begin with the gzip magic: 0x%02x%02x",
                            magic1, magic2));
        }
        int method = required("the compression method");
        if (method != 8) {
            throw new BundleRejection(BundleRule.ARCHIVE_NOT_GZIP,
                    "compression method " + method + " is not deflate");
        }
        int flags = required("the gzip flags");
        if ((flags & RESERVED) != 0) {
            // Reserved bits have no defined meaning, so a member setting them means something
            // this parser cannot know. Refused rather than ignored.
            throw new BundleRejection(BundleRule.ARCHIVE_NOT_GZIP,
                    String.format("reserved gzip flag bits are set: 0x%02x", flags));
        }
        skip(6, "the gzip header");   // mtime, extra flags, operating system

        if ((flags & FEXTRA) != 0) {
            int low = required("an extra-field length");
            int high = required("an extra-field length");
            skip(low | (high << 8), "a gzip extra field");
        }
        if ((flags & FNAME) != 0) {
            skipZeroTerminated("the stored filename");
        }
        if ((flags & FCOMMENT) != 0) {
            skipZeroTerminated("the stored comment");
        }
        if ((flags & FHCRC) != 0) {
            skip(2, "the header CRC");
        }
        // The remaining defined flag, FTEXT, is advisory and carries no data.
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n < 0 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(byte[] output, int offset, int length) throws IOException {
        if (length == 0) {
            return 0;
        }
        while (true) {
            int produced;
            try {
                produced = inflater.inflate(output, offset, length);
            } catch (DataFormatException ex) {
                throw new BundleRejection(BundleRule.ARCHIVE_GZIP_CORRUPT,
                        "the deflate stream is malformed: " + ex.getMessage());
            }
            if (produced > 0) {
                expanded += produced;
                if (expanded > limits.maxExpandedBytes()) {
                    throw new BundleRejection(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED,
                            "the archive has expanded to " + expanded + " bytes, over the"
                                    + " configured " + limits.maxExpandedBytes());
                }
                crc.update(output, offset, produced);
                return produced;
            }
            if (inflater.finished()) {
                verifyOnce();
                return -1;
            }
            if (inflater.needsDictionary()) {
                throw new BundleRejection(BundleRule.ARCHIVE_GZIP_CORRUPT,
                        "the deflate stream asks for a preset dictionary, which gzip has no"
                                + " way to supply");
            }
            fill();
        }
    }

    private void fill() {
        int read = readSource(input, 0, input.length);
        if (read <= 0) {
            throw new BundleRejection(BundleRule.ARCHIVE_GZIP_TRUNCATED,
                    "the gzip member ends before its deflate stream does, after "
                            + compressedRead + " compressed bytes");
        }
        inputLength = read;
        inflater.setInput(input, 0, read);
    }

    /**
     * Verifies the trailer exactly once, on the first read that reports end of stream.
     *
     * <p>The first version of this class returned -1 from the top of the read loop whenever
     * the inflater was finished, which skipped the verification below entirely whenever the
     * final inflate call produced bytes AND finished in the same breath — the ordinary case.
     * Four tests failed with "nothing was thrown", which is what they are for: the trailer
     * check was written, was correct, and could not run.
     */
    private void verifyOnce() {
        if (verified) {
            return;
        }
        verified = true;
        finish();
    }

    /** Verifies the trailer and that the member is the only thing in the upload. */
    private void finish() {
        // Whatever the inflater did not consume is where the trailer begins.
        int leftover = inflater.getRemaining();
        int leftoverStart = inputLength - leftover;

        byte[] trailer = new byte[8];
        int fromBuffer = Math.min(leftover, trailer.length);
        System.arraycopy(input, leftoverStart, trailer, 0, fromBuffer);
        for (int i = fromBuffer; i < trailer.length; i++) {
            int b = readSource();
            if (b < 0) {
                throw new BundleRejection(BundleRule.ARCHIVE_GZIP_TRUNCATED,
                        "the gzip trailer is " + i + " of 8 bytes");
            }
            trailer[i] = (byte) b;
        }

        long storedCrc = readLittleEndian(trailer, 0);
        long storedSize = readLittleEndian(trailer, 4);
        if (storedCrc != crc.getValue()) {
            throw new BundleRejection(BundleRule.ARCHIVE_GZIP_CORRUPT,
                    String.format("the gzip CRC is 0x%08x and the data checksums to 0x%08x",
                            storedCrc, crc.getValue()));
        }
        if (storedSize != (expanded & 0xFFFFFFFFL)) {
            throw new BundleRejection(BundleRule.ARCHIVE_GZIP_CORRUPT,
                    "the gzip trailer claims " + storedSize + " uncompressed bytes and "
                            + (expanded & 0xFFFFFFFFL) + " arrived");
        }

        // Anything still in the buffer, or still in the source, is after the member.
        int remaining = leftover - fromBuffer;
        if (remaining > 0) {
            reportExtra(input, leftoverStart + fromBuffer, remaining);
        }
        int next = readSource();
        if (next >= 0) {
            int second = readSource();
            byte[] peek = second < 0
                    ? new byte[] {(byte) next}
                    : new byte[] {(byte) next, (byte) second};
            reportExtra(peek, 0, peek.length);
        }
    }

    private void reportExtra(byte[] bytes, int offset, int length) {
        boolean anotherMember = length >= 2
                && (bytes[offset] & 0xFF) == 0x1F && (bytes[offset + 1] & 0xFF) == 0x8B;
        if (anotherMember) {
            throw new BundleRejection(BundleRule.ARCHIVE_MULTIPLE_MEMBERS,
                    "a second gzip member follows the first; readers disagree about whether"
                            + " it exists, so the upload has no single meaning");
        }
        throw new BundleRejection(BundleRule.ARCHIVE_TRAILING_DATA,
                "there are bytes after the gzip member that are not part of it, beginning '"
                        + BundleRejection.render(java.util.Arrays.copyOfRange(
                                bytes, offset, Math.min(bytes.length, offset + 8))) + "'");
    }

    /** Bytes produced so far, which is what the expanded bound is measured against. */
    public long expandedBytes() {
        return expanded;
    }

    /** Bytes consumed from the upload so far. */
    public long compressedBytes() {
        return compressedRead;
    }

    /**
     * Ends the member, and finishes checking it if the caller did not read that far.
     *
     * <p>Finding b50b378-F1: every guarantee this class makes used to be conditional on the
     * consumer reading to end of stream, because the trailer check ran from {@code read()}.
     * A tar reader stops at the end-of-archive marker, which is sixteen bytes into a stream
     * that may have a second gzip member behind it — so the smuggled member was neither
     * joined nor refused, it was never looked at. A reader that stops early is a third
     * reader with a third opinion about what the bundle contains, which is the same defect
     * the class was built to prevent.
     *
     * <p>So closing drains whatever is left and then verifies. The drain is bounded by the
     * expanded limit like any other read, so a bomb behind an early stop is refused rather
     * than decompressed. A rejection raised here during unwinding is suppressed by
     * try-with-resources and the original rejection still propagates, which is the right way
     * round: the first reason a bundle was refused is the one worth reporting.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        try {
            if (!verified) {
                byte[] discard = new byte[BUFFER];
                while (read(discard, 0, discard.length) >= 0) {
                    continue;
                }
            }
        } finally {
            closed = true;
            inflater.end();
        }
    }

    private int required(String what) {
        int b = readSource();
        if (b < 0) {
            throw new BundleRejection(BundleRule.ARCHIVE_GZIP_TRUNCATED,
                    "the upload ends inside " + what);
        }
        return b;
    }

    private void skip(int count, String what) {
        for (int i = 0; i < count; i++) {
            required(what);
        }
    }

    private void skipZeroTerminated(String what) {
        // Bounded by the compressed limit like everything else: readSource counts, so a
        // member whose "filename" never terminates dies on that bound rather than here.
        while (required(what) != 0) {
            continue;
        }
    }

    private int readSource() {
        byte[] one = new byte[1];
        int n = readSource(one, 0, 1);
        return n <= 0 ? -1 : one[0] & 0xFF;
    }

    private int readSource(byte[] buffer, int offset, int length) {
        int read;
        try {
            read = source.read(buffer, offset, length);
        } catch (IOException ex) {
            throw new BundleRejection(BundleRule.ARCHIVE_GZIP_TRUNCATED,
                    "the upload could not be read: " + ex.getMessage());
        }
        if (read > 0) {
            compressedRead += read;
            if (compressedRead > limits.maxCompressedBytes()) {
                throw new BundleRejection(BundleRule.ARCHIVE_TOO_LARGE_COMPRESSED,
                        "the upload has reached " + compressedRead + " bytes, over the"
                                + " configured " + limits.maxCompressedBytes());
            }
        }
        return read;
    }

    private static long readLittleEndian(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL)
                | ((bytes[offset + 1] & 0xFFL) << 8)
                | ((bytes[offset + 2] & 0xFFL) << 16)
                | ((bytes[offset + 3] & 0xFFL) << 24);
    }
}
