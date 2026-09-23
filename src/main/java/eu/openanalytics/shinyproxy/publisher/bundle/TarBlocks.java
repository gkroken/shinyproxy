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
import java.util.function.LongSupplier;

/**
 * The tar stream as blocks: headers out, content bounded, and an end that is proved rather
 * than assumed.
 *
 * <p>This layer knows nothing about what a header means — {@link TarHeader} does that. What
 * it owns is everything that can go wrong between headers: an archive that stops in the
 * middle of a block, a member whose content runs off the end, an end-of-archive marker that
 * is not there, bytes after the marker that are not padding, more headers than the
 * configured bound, and a walk that takes longer than the configured deadline.
 *
 * <p><b>The end is two zero blocks and then nothing but zeros.</b> A tar reader that stops at
 * the first zero block, or that stops at the marker without looking further, cannot tell an
 * archive from an archive with something appended to it — and "reject concatenated
 * archives/members and non-padding trailing data" is the contract. Reaching the end of the
 * stream with no marker at all is {@code bomb-truncated-tar}: half an archive is not a
 * shorter archive.
 *
 * <p><b>Entries are counted, not measured.</b> The bound is on physical headers, so an
 * archive of twenty thousand empty files costs twenty thousand entries and nearly no bytes
 * — {@code bomb-many-empty-entries} exists because a cap counted in bytes never fires on it.
 * Metadata headers count too: a PAX header and a GNU long-name header are headers this
 * parser walked.
 *
 * <p><b>Content is not trusted to the caller.</b> {@link #content} hands out a stream bounded
 * by the declared size, and the next call to {@link #nextHeader} finishes whatever the caller
 * left — the same rule as {@code GzipMember.close}, and for the same reason: a guarantee that
 * holds only when the consumer cooperates is not a guarantee. Bytes are counted as they are
 * produced, so a member that lies about its size is caught by what arrives rather than by
 * what it claims.
 */
public final class TarBlocks {

    private final InputStream source;
    private final ExtractionLimits limits;
    private final LongSupplier nanoTime;
    private final long deadlineNanos;

    private long entries;
    private long contentBytes;
    private BoundedContent open;
    private boolean ended;

    public TarBlocks(InputStream source, ExtractionLimits limits) {
        this(source, limits, System::nanoTime);
    }

    /** The clock is injected so the deadline can be tested without waiting for it. */
    public TarBlocks(InputStream source, ExtractionLimits limits, LongSupplier nanoTime) {
        this.source = source;
        this.limits = limits;
        this.nanoTime = nanoTime;
        this.deadlineNanos = nanoTime.getAsLong()
                + limits.extractionDeadlineSeconds() * 1_000_000_000L;
    }

    /**
     * The next header block, or {@code null} once the archive has properly ended.
     *
     * <p>Returning null is a statement that the end-of-archive marker was found AND that
     * everything after it was padding. There is no way to reach the end of this stream
     * without that having been checked.
     */
    public byte[] nextHeader() {
        if (ended) {
            return null;
        }
        finishOpenContent();
        checkDeadline();

        byte[] block = readBlock("a header");
        if (block == null) {
            throw new BundleRejection(BundleRule.ARCHIVE_NO_END_MARKER,
                    "the archive ends after " + entries + " entr" + (entries == 1 ? "y" : "ies")
                            + " with no end-of-archive marker; half an archive is not a"
                            + " shorter archive");
        }
        if (TarHeader.isAllZero(block)) {
            requireEndOfArchive();
            ended = true;
            return null;
        }

        entries++;
        if (entries > limits.maxEntries()) {
            throw new BundleRejection(BundleRule.ENTRY_COUNT_EXCEEDED,
                    "more than the configured " + limits.maxEntries() + " entries. Headers"
                            + " are counted, not bytes: an archive of empty files costs one"
                            + " entry each and almost no space");
        }
        return block;
    }

    /**
     * A stream over one member's content, bounded by {@code size} and by the expanded limit.
     *
     * <p>The caller may read all of it, some of it or none of it; the padding to the next
     * block boundary, and anything left unread, are dealt with before the next header.
     */
    public InputStream content(long size) {
        if (size < 0) {
            // Not a bundle defect: TarHeader refuses a negative declared size when it parses
            // the octal field, so the walk cannot produce one. It is a caller error, and an
            // unguarded one skews the stream — a size of -1 makes the padding computation
            // consume one byte and every subsequent block starts one byte late
            // (finding e079be4-F2). The class promises alignment; a caller must not be able
            // to break it by passing a value the class accepted without comment.
            throw new IllegalArgumentException("a member's content size cannot be negative: "
                    + size);
        }
        finishOpenContent();
        open = new BoundedContent(size);
        return open;
    }

    /** Physical headers seen so far, which is what the entry bound counts. */
    public long entries() {
        return entries;
    }

    /** Member content bytes produced so far, which is what the expanded bound counts. */
    public long contentBytes() {
        return contentBytes;
    }

    private void requireEndOfArchive() {
        // POSIX ends an archive with two zero blocks. One zero block followed by anything
        // else is not an end and not a header.
        byte[] second = readBlock("the second block of the end-of-archive marker");
        if (second == null) {
            throw new BundleRejection(BundleRule.ARCHIVE_NO_END_MARKER,
                    "the archive ends after one zero block; the marker is two");
        }
        if (!TarHeader.isAllZero(second)) {
            throw new BundleRejection(BundleRule.ARCHIVE_NO_END_MARKER,
                    "a zero block in the middle of the archive, followed by data rather than"
                            + " by the second block of the marker");
        }
        // Everything after the marker must be padding. Anything else is a second archive or
        // an appendix, and either way the bundle has more than one meaning.
        byte[] after;
        long padding = 0;
        while ((after = readBlock("padding after the end-of-archive marker")) != null) {
            if (!TarHeader.isAllZero(after)) {
                throw new BundleRejection(BundleRule.ARCHIVE_TRAILING_DATA,
                        "there is data after the end-of-archive marker, beginning '"
                                + BundleRejection.renderBounded(after, 32, false) + "'");
            }
            // Padding is neither an entry nor member content, so without this it is the one
            // region of an archive that no size bound reaches and only the deadline ends
            // (finding e079be4-F1). GNU tar's default blocking factor is twenty blocks, so a
            // real archive carries about 10 KiB here; the entry bound is reused rather than
            // inventing a number, which leaves three orders of magnitude of headroom at the
            // documented default and moves with an operator who changes it.
            if (++padding > limits.maxEntries()) {
                throw new BundleRejection(BundleRule.ENTRY_COUNT_EXCEEDED,
                        "more than the configured " + limits.maxEntries() + " blocks of"
                                + " padding after the end-of-archive marker. A zero tail is"
                                + " neither an entry nor content, so the entry bound is what"
                                + " counts it");
            }
            checkDeadline();
        }
    }

    private void finishOpenContent() {
        if (open == null) {
            return;
        }
        BoundedContent finishing = open;
        open = null;
        finishing.finish();
    }

    private void checkDeadline() {
        if (nanoTime.getAsLong() - deadlineNanos >= 0) {
            throw new BundleRejection(BundleRule.EXTRACTION_DEADLINE_EXCEEDED,
                    "the extraction passed its configured "
                            + limits.extractionDeadlineSeconds() + "-second deadline after "
                            + entries + " entries and " + contentBytes + " content bytes");
        }
    }

    /** One block, or null at a clean end of stream. A partial block is a truncated archive. */
    private byte[] readBlock(String what) {
        byte[] block = new byte[TarHeader.BLOCK];
        int filled = 0;
        while (filled < block.length) {
            int read;
            try {
                read = source.read(block, filled, block.length - filled);
            } catch (IOException ex) {
                throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                        "the archive could not be read while expecting " + what + ": "
                                + ex.getMessage());
            }
            if (read < 0) {
                if (filled == 0) {
                    return null;
                }
                throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                        "the archive ends " + filled + " bytes into a 512-byte block, while"
                                + " expecting " + what);
            }
            filled += read;
        }
        return block;
    }

    /** A member's content: exactly {@code size} bytes, then the padding to a block boundary. */
    private final class BoundedContent extends InputStream {

        private final long size;
        private long produced;

        private BoundedContent(long size) {
            this.size = size;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (produced >= size) {
                return -1;
            }
            int want = (int) Math.min(length, size - produced);
            int read = source.read(buffer, offset, want);
            if (read < 0) {
                throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                        "a member declares " + size + " bytes and the archive ends after "
                                + produced);
            }
            produced += read;
            contentBytes += read;
            if (contentBytes > limits.maxExpandedBytes()) {
                throw new BundleRejection(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED,
                        "the members extracted so far total " + contentBytes + " bytes, over"
                                + " the configured " + limits.maxExpandedBytes());
            }
            checkDeadline();
            return read;
        }

        /** Consumes whatever the caller did not, then the padding to the block boundary. */
        private void finish() {
            byte[] discard = new byte[8192];
            while (produced < size) {
                int want = (int) Math.min(discard.length, size - produced);
                int read;
                try {
                    read = read(discard, 0, want);
                } catch (IOException ex) {
                    throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                            "a member's content could not be read: " + ex.getMessage());
                }
                if (read < 0) {
                    break;
                }
            }
            long padding = (TarHeader.BLOCK - (size % TarHeader.BLOCK)) % TarHeader.BLOCK;
            for (long left = padding; left > 0; ) {
                int want = (int) Math.min(discard.length, left);
                int read;
                try {
                    read = source.read(discard, 0, want);
                } catch (IOException ex) {
                    throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                            "the padding after a member could not be read: " + ex.getMessage());
                }
                if (read < 0) {
                    throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                            "the archive ends inside the padding after a member");
                }
                left -= read;
            }
        }
    }
}
