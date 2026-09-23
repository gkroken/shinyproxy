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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * The records inside one PAX extended header, and the narrow set of them this format honours.
 *
 * <p>A PAX header changes how the member AFTER it is read. That is the whole hazard: a tar
 * library that does not apply the {@code path} override never checks the effective path and
 * accepts {@code trav-pax-override} — a benign ustar name of {@code app/innocent.txt} with an
 * override to {@code app/../../pax-escape.txt}. A reader that applies the override and a
 * reader that ignores it disagree about which file the archive contains, and the uploader
 * picks which one any given consumer is.
 *
 * <p><b>So the keywords are an allowlist, not a denylist.</b> Three groups:
 *
 * <ul>
 *   <li>{@code path} is honoured, and the effective name it produces goes through exactly
 *       the same {@link MemberPath} rules as a name from a header field. It is the only
 *       keyword that changes anything.</li>
 *   <li>A short list of metadata this extractor strips anyway — times, ownership, a comment —
 *       is parsed, bounded and discarded. Parsed rather than skipped, because a header that
 *       does not parse is a header whose remaining records cannot be located either.</li>
 *   <li>Everything else is refused by name, including keywords nobody has invented yet.
 *       {@code linkpath} makes a member a link, {@code size} moves the read head,
 *       {@code GNU.sparse.*} lets the declared and stored sizes disagree by design, and
 *       {@code SCHILY.xattr.*} carries extended attributes the contract says to strip. An
 *       unknown keyword is refused rather than ignored because the ones that matter are
 *       exactly the ones this list has not heard of.</li>
 * </ul>
 *
 * <p><b>The size bound is checked before the bytes are held.</b> {@code bomb-huge-pax-field}
 * is an extended header four times the per-header cap, and the corpus's note says what it is
 * for: "a parser that buffers the whole record reads into memory before deciding anything".
 * The walk checks the DECLARED size before reading; this class checks the content it is
 * given. Two statements of one rule, on purpose, because the declared size is a claim.
 */
public final class PaxRecords {

    /** Parsed, bounded and thrown away: none of it survives extraction. */
    private static final Set<String> IGNORED = Set.of(
            "atime", "ctime", "mtime", "uid", "gid", "uname", "gname", "comment");

    /** Named in the rejection so a publisher is told what their tar writer did. */
    private static final Set<String> KNOWN_AND_REFUSED = Set.of(
            "linkpath", "size", "charset", "hdrcharset", "realtime", "security");

    private final byte[] pathOverride;

    private PaxRecords(byte[] pathOverride) {
        this.pathOverride = pathOverride;
    }

    /** The {@code path} override, if this header carried one. */
    public Optional<byte[]> pathOverride() {
        return Optional.ofNullable(pathOverride).map(bytes -> bytes.clone());
    }

    /**
     * Parses one extended header's content.
     *
     * <p>A record is {@code "<len> <key>=<value>\n"}, where {@code len} is the decimal length
     * of the whole record including the length field and the trailing newline. The value may
     * contain anything, newlines included, which is why the length is what delimits a record
     * and scanning for a newline is not good enough.
     */
    public static PaxRecords parse(byte[] content, ExtractionLimits limits) {
        if (content.length > limits.maxExtendedHeaderBytes()) {
            throw new BundleRejection(BundleRule.PAX_HEADER_TOO_LARGE,
                    "an extended header of " + content.length + " bytes, over the configured "
                            + limits.maxExtendedHeaderBytes());
        }

        byte[] path = null;
        Set<String> seen = new HashSet<>();
        int at = 0;
        while (at < content.length) {
            int space = -1;
            for (int i = at; i < content.length; i++) {
                if (content[i] == ' ') {
                    space = i;
                    break;
                }
                if (content[i] < '0' || content[i] > '9') {
                    throw malformed(at, "expected a decimal length, found '"
                            + BundleRejection.renderBounded(new byte[] {content[i]}, 8, false)
                            + "'");
                }
            }
            if (space < 0 || space == at) {
                throw malformed(at, space == at ? "an empty length field"
                        : "no space after the length field");
            }
            long length = decimal(content, at, space);
            if (length < space - at + 2 || length > content.length - at) {
                // Shorter than its own length field plus a separator and a newline, or
                // longer than what is left: either way the next record cannot be found.
                throw malformed(at, "a record length of " + length + " with "
                        + (content.length - at) + " byte(s) remaining");
            }
            int recordEnd = at + (int) length;
            if (content[recordEnd - 1] != '\n') {
                throw malformed(at, "the record does not end with a newline");
            }
            int equals = -1;
            for (int i = space + 1; i < recordEnd - 1; i++) {
                if (content[i] == '=') {
                    equals = i;
                    break;
                }
            }
            if (equals < 0 || equals == space + 1) {
                throw malformed(at, equals < 0 ? "no '=' in the record" : "an empty keyword");
            }
            String keyword = new String(content, space + 1, equals - space - 1,
                    StandardCharsets.UTF_8);
            byte[] value = Arrays.copyOfRange(content, equals + 1, recordEnd - 1);

            if (!seen.add(keyword)) {
                throw new BundleRejection(BundleRule.PAX_DUPLICATE_KEYWORD,
                        "the keyword '" + keyword + "' appears twice in one extended header;"
                                + " a reader that takes the first and a reader that takes the"
                                + " last are describing different members");
            }
            if ("path".equals(keyword)) {
                path = value;
            } else if (!IGNORED.contains(keyword)) {
                throw new BundleRejection(BundleRule.PAX_KEYWORD_NOT_ALLOWED,
                        "the extended header keyword '" + keyword + "' is "
                                + (KNOWN_AND_REFUSED.contains(keyword) ? "not accepted here"
                                        : "not one this extractor knows")
                                + "; honouring it would change what the member after it is,"
                                + " and ignoring it would mean two readers disagree about"
                                + " the same archive");
            }
            at = recordEnd;
        }
        return new PaxRecords(path);
    }

    private static long decimal(byte[] content, int from, int to) {
        long value = 0;
        for (int i = from; i < to; i++) {
            int digit = content[i] - '0';
            if (value > (Long.MAX_VALUE - digit) / 10) {
                throw malformed(from, "a record length that does not fit in a 64-bit integer");
            }
            value = value * 10 + digit;
        }
        return value;
    }

    private static BundleRejection malformed(int offset, String what) {
        return new BundleRejection(BundleRule.PAX_RECORD_MALFORMED,
                "the extended header record at offset " + offset + " is malformed: " + what);
    }
}
