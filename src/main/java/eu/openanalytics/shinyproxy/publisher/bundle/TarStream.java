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
import java.util.Arrays;
import java.util.function.LongSupplier;

/**
 * The walk: blocks in, validated members out.
 *
 * <p>Everything this class does is assembly. {@link TarBlocks} owns the stream,
 * {@link TarHeader} owns one header, {@link PaxRecords} owns one extended header,
 * {@link MemberPath} owns one name and {@link MemberIndex} owns the members against each
 * other. What is left, and what lives here, is the part none of them can see: that a name
 * has up to three sources and only one of them may win, and that a metadata header means
 * nothing on its own.
 *
 * <p><b>A member's name comes from exactly one place.</b> The header's own fields, a GNU
 * long-name header before it, or a PAX {@code path} override before it — and never two of
 * them, because a second metadata header is refused where it appears rather than resolved
 * later. POSIX would have an override win over a long name, but an archive that says two
 * different things about one member is an archive two readers describe differently, and
 * choosing for it is the mistake the whole extraction contract is written against.
 * Whichever source supplies the name, it goes through the same {@link MemberPath} rules —
 * there is no blessed path.
 *
 * <p><b>Metadata headers are bounded before they are read.</b> This is the check
 * {@code PaxRecords} records as owed and cannot make itself: the extended header's DECLARED
 * size is compared with {@code max_extended_header_bytes} before a byte of it is read, so
 * {@code bomb-huge-pax-field} — four times the cap — costs one header block rather than a
 * quarter of a megabyte. A GNU long name is bounded the same way, against the longest name
 * that could ever be valid.
 *
 * <p>The corresponding test measures the ORDER rather than the verdict, because both a walk
 * that pre-checks and a walk that reads first end in PAX_HEADER_TOO_LARGE and the verdict
 * cannot tell them apart.
 */
public final class TarStream {

    /**
     * What the walk hands out.
     *
     * <p><b>The content stream is valid only during the call.</b> The walk moves to the next
     * header as soon as this returns, and finishing that move consumes whatever is left of
     * this member. A sink that keeps the stream and reads it afterwards used to get an empty
     * result and no error — which, for an extractor, is an empty file on disk inside a bundle
     * that validated cleanly (finding 1bb68a4-F1). Reading late now throws.
     *
     * <p>Content is empty for a directory. A sink need not read it at all.
     */
    public interface MemberSink {
        void member(MemberPath path, TarHeader header, InputStream content) throws IOException;
    }

    private TarStream() {
    }

    public static void walk(InputStream tar, ExtractionLimits limits, MemberSink sink)
            throws IOException {
        walk(tar, limits, System::nanoTime, sink);
    }

    public static void walk(InputStream tar, ExtractionLimits limits, LongSupplier nanoTime,
                            MemberSink sink) throws IOException {
        TarBlocks blocks = new TarBlocks(tar, limits, nanoTime);
        MemberIndex index = new MemberIndex();

        byte[] pendingLongName = null;
        PaxRecords pendingPax = null;

        byte[] block;
        while ((block = blocks.nextHeader()) != null) {
            TarHeader header = TarHeader.parse(block, limits);

            switch (header.kind()) {
                case GNU_LONG_NAME -> {
                    requireNoPending(pendingLongName, pendingPax, "a GNU long-name header");
                    pendingLongName = readLongName(blocks, header, limits);
                }
                case PAX_EXTENDED -> {
                    requireNoPending(pendingLongName, pendingPax, "a PAX extended header");
                    pendingPax = readPax(blocks, header, limits);
                }
                case REGULAR, DIRECTORY -> {
                    MemberPath path = nameOf(header, pendingLongName, pendingPax, limits);
                    index.add(path);
                    pendingLongName = null;
                    pendingPax = null;
                    sink.member(path, header, blocks.content(header.size()));
                }
            }
        }

        if (pendingLongName != null || pendingPax != null) {
            throw new BundleRejection(BundleRule.METADATA_HEADER_MISPLACED,
                    "the archive ends with a metadata header and no member after it, so it"
                            + " describes something that is not there");
        }
    }

    private static MemberPath nameOf(TarHeader header, byte[] longName, PaxRecords pax,
                                     ExtractionLimits limits) {
        // No both-present case: a second metadata header is refused where it appears, so a
        // member can never reach here carrying two. The first version of this method had a
        // branch for it, and the test written for that branch refused one header earlier and
        // proved it could not fire.
        byte[] override = pax == null ? null : pax.pathOverride().orElse(null);
        byte[] name = override != null ? override : longName != null ? longName : header.name();
        return MemberPath.parse(name, header.kind() == TarHeader.Kind.DIRECTORY, limits);
    }

    private static void requireNoPending(byte[] longName, PaxRecords pax, String what) {
        if (longName != null || pax != null) {
            throw new BundleRejection(BundleRule.METADATA_HEADER_MISPLACED,
                    what + " follows another metadata header. One member takes one name, and"
                            + " a header describing a header describes nothing");
        }
    }

    /**
     * The name in a GNU long-name header, bounded before it is read.
     *
     * <p>The bound is the longest name that could ever produce a valid member: the payload
     * path limit, plus the payload root and its separator, plus the trailing NUL GNU writes.
     * Anything larger cannot become an accepted path however it is parsed, so reading it
     * would be spending memory to reach a conclusion already available.
     */
    private static byte[] readLongName(TarBlocks blocks, TarHeader header,
                                       ExtractionLimits limits) throws IOException {
        long longest = limits.maxPathBytes() + MemberPath.PAYLOAD_ROOT.length() + 2;
        if (header.size() > longest) {
            throw new BundleRejection(BundleRule.PATH_TOO_LONG,
                    "a GNU long-name header declares " + header.size() + " bytes, and no name"
                            + " longer than " + longest + " can be a valid member path");
        }
        byte[] name = readAll(blocks.content(header.size()), (int) header.size());
        // GNU stores the name NUL-terminated; the NUL is the terminator, not the name.
        int end = name.length;
        while (end > 0 && name[end - 1] == 0) {
            end--;
        }
        return Arrays.copyOf(name, end);
    }

    /** The records in a PAX header, bounded before they are read. */
    private static PaxRecords readPax(TarBlocks blocks, TarHeader header,
                                      ExtractionLimits limits) throws IOException {
        if (header.size() > limits.maxExtendedHeaderBytes()) {
            throw new BundleRejection(BundleRule.PAX_HEADER_TOO_LARGE,
                    "an extended header declares " + header.size() + " bytes, over the"
                            + " configured " + limits.maxExtendedHeaderBytes()
                            + ". Refused on the claim, before the bytes are read");
        }
        return PaxRecords.parse(readAll(blocks.content(header.size()), (int) header.size()),
                limits);
    }

    private static byte[] readAll(InputStream content, int size) throws IOException {
        byte[] out = new byte[size];
        int filled = 0;
        while (filled < size) {
            int read = content.read(out, filled, size - filled);
            if (read < 0) {
                throw new BundleRejection(BundleRule.ARCHIVE_TAR_TRUNCATED,
                        "a metadata header declares " + size + " bytes and the archive ends"
                                + " after " + filled);
            }
            filled += read;
        }
        return out;
    }
}
