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

/**
 * Why a bundle was refused, in a form a publisher can act on.
 *
 * <p>The plan's rule for the semantic validator — "a rejection names its rule", because
 * "S5: entrypoint `dashboards` contains neither `app.R` nor both `ui.R` and `server.R`" is
 * actionable and "invalid bundle" sends someone to an administrator — applies just as much
 * to extraction, which is where most refusals will happen. These are the names.
 *
 * <p>They are deliberately identifiers rather than numbers. S1-S11 are numbered because the
 * plan numbers them; nothing numbers these, and an invented numbering would have to be
 * remembered by everyone reading a rejection. {@code PATH_TRAVERSAL} does not.
 *
 * <p>This enum is publisher-visible once T6 puts rejections on the admin transport, so
 * adding to it is ordinary and renaming a member is a breaking change.
 */
public enum BundleRule {

    // ---- member paths, as they stream past ---------------------------------------------
    /** The member has no name at all. */
    PATH_EMPTY,
    /** A NUL byte inside the name field, with the rest of the field still there. */
    PATH_NUL,
    /** A control character, which corrupts any log or terminal that echoes the name. */
    PATH_CONTROL_CHARACTER,
    /** Not valid UTF-8, so the name has no defined normalisation and readers disagree. */
    PATH_NOT_UTF8,
    /** Valid UTF-8 but not in NFC. Rejected rather than normalised: see {@link MemberPath}. */
    PATH_NOT_NFC,
    /** A backslash: a literal character here, a separator to anything that later runs on Windows. */
    PATH_BACKSLASH,
    /** An absolute path. */
    PATH_ABSOLUTE,
    /** A Windows drive designator, which is absolute on the system that understands it. */
    PATH_DRIVE_LETTER,
    /** A {@code ..} segment. */
    PATH_TRAVERSAL,
    /** A {@code .} segment. */
    PATH_DOT_SEGMENT,
    /** An empty segment, from a doubled or trailing separator. */
    PATH_EMPTY_SEGMENT,
    /** A trailing slash on something that is not a directory header. */
    PATH_TRAILING_SLASH,
    /** One segment longer than the configured maximum. */
    PATH_SEGMENT_TOO_LONG,
    /** The whole payload-relative path longer than the configured maximum. */
    PATH_TOO_LONG,
    /** More path segments than the configured maximum. */
    PATH_TOO_DEEP,

    // ---- the gzip envelope -------------------------------------------------------------
    /** Not a gzip member at all: wrong magic, an unknown compression method, or reserved flags. */
    ARCHIVE_NOT_GZIP,
    /** The gzip member ends before its data does. */
    ARCHIVE_GZIP_TRUNCATED,
    /** The gzip member decompresses to something other than what its own trailer claims. */
    ARCHIVE_GZIP_CORRUPT,
    /** A second gzip member after the first. Readers disagree about whether it exists. */
    ARCHIVE_MULTIPLE_MEMBERS,
    /** Bytes after the archive that are not padding. */
    ARCHIVE_TRAILING_DATA,
    /** The upload is larger than the configured compressed bound. */
    ARCHIVE_TOO_LARGE_COMPRESSED,
    /** The archive expands past the configured total bound. */
    ARCHIVE_TOO_LARGE_EXPANDED,

    // ---- the tar stream ------------------------------------------------------------------
    /** The archive ends inside a block, or inside a member's content. */
    ARCHIVE_TAR_TRUNCATED,
    /** No end-of-archive marker, or a zero block where a header should be. */
    ARCHIVE_NO_END_MARKER,
    /** More physical headers than the configured bound, metadata included. */
    ENTRY_COUNT_EXCEEDED,
    /** The extraction ran past its configured wall-clock deadline. */
    EXTRACTION_DEADLINE_EXCEEDED,

    // ---- one tar header ----------------------------------------------------------------
    /** The header's own checksum does not match its bytes. */
    HEADER_CHECKSUM_MISMATCH,
    /** Not a ustar header: the magic says this is some other format, or none. */
    HEADER_NOT_USTAR,
    /** A numeric field that is not octal — which is how a negative size is written. */
    HEADER_MALFORMED_NUMBER,
    /** GNU's base-256 numeric encoding, which this extractor does not accept. */
    HEADER_BASE256_NUMBER,
    /** A member type the bundle format does not carry: link, device, FIFO, socket, sparse. */
    ENTRY_TYPE_NOT_ALLOWED,
    /** A typeflag no standard defines, refused rather than guessed at. */
    ENTRY_TYPE_UNKNOWN,
    /** A setuid, setgid or sticky bit. */
    ENTRY_MODE_PRIVILEGED,
    /** A directory header claiming content, which would move the read head. */
    ENTRY_DIRECTORY_WITH_CONTENT,
    /** A member larger than the configured per-file bound. */
    ENTRY_TOO_LARGE,

    // ---- PAX extended headers ------------------------------------------------------------
    /** An extended header larger than the configured per-header bound. */
    PAX_HEADER_TOO_LARGE,
    /** A record that does not parse: a bad length, a missing '=' or a missing newline. */
    PAX_RECORD_MALFORMED,
    /** A keyword this extractor does not accept, because honouring it changes what a member is. */
    PAX_KEYWORD_NOT_ALLOWED,
    /** The same keyword twice in one header; two readers would disagree about which wins. */
    PAX_DUPLICATE_KEYWORD,

    // ---- members against each other ----------------------------------------------------
    /** The same member path twice. Last-entry-wins means what was validated is not what is on disk. */
    DUPLICATE_MEMBER,
    /** One path used as both a file and a directory, in either order. */
    MEMBER_KIND_CONFLICT,
    /** Two paths differing only by case, which are one file on a case-insensitive filesystem. */
    MEMBER_CASE_COLLISION,

    // ---- archive layout ----------------------------------------------------------------
    /** A member that is neither the manifest nor under the payload root. */
    LAYOUT_UNEXPECTED_MEMBER;

    /** The identifier a publisher sees, which is the enum's own name. */
    public String ruleName() {
        return name();
    }
}
