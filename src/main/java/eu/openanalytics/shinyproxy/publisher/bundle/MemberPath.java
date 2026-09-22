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

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * One member's name, checked against every rule the extraction contract states about paths,
 * and carrying the result rather than a promise that someone checked.
 *
 * <p><b>Bytes first, text second.</b> Every rule that can be decided on the raw bytes is
 * decided there — NUL, control characters, backslashes — because a name that is not valid
 * UTF-8 has no text form to check, and decoding with replacement characters would map two
 * different hostile names onto one harmless-looking string. The decode is strict and its
 * failure is a rejection, not a fallback.
 *
 * <p><b>Rejected, never repaired.</b> Nothing here strips a {@code ..}, collapses a double
 * separator, lower-cases a colliding name or normalises a decomposed one. The plan says why
 * for the semantic validator and it holds identically here: every repair turns a rejection
 * into a silently different bundle, which is how an uploader and a server come to disagree
 * about what was published. A path is in NFC or it is refused.
 *
 * <p><b>No decoder runs over a member name.</b> {@code %2e%2e} is four literal characters
 * in a tar name. A validator that percent-decodes here manufactures the traversal it is
 * looking for, so the corpus carries that exact case; the rules below never decode anything.
 *
 * <p>This is not the only containment rule in the repository, and it is not shared with the
 * other one. {@code ObjectKeys.validatedRenditionPath} guards a rendition output path on its
 * way into an object key: a decoded string, bounded by what a key leaves room for, with no
 * tar conventions and no configured depth. The two agree on the containment core — no
 * {@code ..}, no {@code .}, no empty segment, no absolute path, no backslash, no control
 * character, NFC required — and {@code ContainmentRulesAgreeTest} runs both over the same
 * inputs so that a day when one stops refusing something is a day a test fails.
 *
 * <p>The archive layout is fixed by the manifest contract — {@code manifest.json} at the
 * root, payload under {@code app/} — so classification is part of parsing. The configured
 * depth and total-length bounds are measured on the payload-relative path, which is what
 * the corpus's boundary fixtures straddle; the {@code app/} prefix is the platform's, not
 * the publisher's, and charging it against the publisher's budget would make the accepted
 * half of every boundary pair depend on a prefix nobody chose.
 */
public final class MemberPath {

    /** The manifest's fixed member name, at the archive root. */
    public static final String MANIFEST_MEMBER = "manifest.json";

    /** The single directory every payload member lives under. */
    public static final String PAYLOAD_ROOT = "app";

    /** What a member is, decided by where it sits rather than by what it contains. */
    public enum Role {
        /** The bundle manifest itself. */
        MANIFEST,
        /** Anything under the payload root, including the payload root's own directory header. */
        PAYLOAD
    }

    private final String memberPath;
    private final String payloadPath;
    private final List<String> payloadSegments;
    private final Role role;
    private final boolean directory;

    private MemberPath(String memberPath, String payloadPath, List<String> payloadSegments,
                       Role role, boolean directory) {
        this.memberPath = memberPath;
        this.payloadPath = payloadPath;
        this.payloadSegments = Collections.unmodifiableList(payloadSegments);
        this.role = role;
        this.directory = directory;
    }

    /**
     * Parses a name out of a fixed-width tar header field, which is NUL-padded.
     *
     * <p>The padding is why this is separate from {@link #parse}. Reading "up to the first
     * NUL" is correct for a well-formed header and is also exactly how a hostile one hides:
     * a name, a NUL, and more name after it reads as short and harmless to a C string and
     * carries something else for anything that reads the whole field. Content after the
     * first NUL is a rejection, not padding.
     */
    public static MemberPath parseNameField(byte[] field, boolean directoryHeader,
                                            ExtractionLimits limits) {
        return parse(nameFromField(field), directoryHeader, limits);
    }

    /**
     * The name inside a fixed-width, NUL-padded tar field, with the padding rule enforced.
     *
     * <p>Separate and public because a header has more than one such field: the 100-byte
     * name and, in POSIX ustar, the 155-byte prefix that is joined to it. Both can hide
     * bytes behind a NUL, and one implementation of that rule is better than two that agree
     * today (34182de-F1 was that lesson at a larger scale).
     */
    public static byte[] nameFromField(byte[] field) {
        int end = field.length;
        for (int i = 0; i < field.length; i++) {
            if (field[i] == 0) {
                end = i;
                break;
            }
        }
        for (int i = end; i < field.length; i++) {
            if (field[i] != 0) {
                throw new BundleRejection(BundleRule.PATH_NUL,
                        "a name field carries " + (field.length - i) + " byte(s) after its"
                                + " terminating NUL, which a C string would never see: '"
                                + BundleRejection.render(field) + "'");
            }
        }
        byte[] name = new byte[end];
        System.arraycopy(field, 0, name, 0, end);
        return name;
    }

    /**
     * Parses a name given with an explicit length, which is how a PAX {@code path} override
     * arrives. Such a value is not NUL-padded, so a NUL in it is a NUL in the name.
     */
    public static MemberPath parse(byte[] name, boolean directoryHeader,
                                   ExtractionLimits limits) {
        if (name.length == 0) {
            throw new BundleRejection(BundleRule.PATH_EMPTY, "a member with no name");
        }
        // Checked on the bytes, and before the backslash scan below, because the most
        // useful thing to tell someone who sent 'C:\\escape.txt' is that it names a drive.
        // Reported as a backslash it is still refused, and still baffling.
        if (name.length >= 2 && name[1] == ':' && isAsciiLetter((char) (name[0] & 0xFF))) {
            throw new BundleRejection(BundleRule.PATH_DRIVE_LETTER,
                    "a Windows drive designator, which is absolute on the system that"
                            + " understands it: '" + BundleRejection.render(name) + "'");
        }
        for (byte b : name) {
            int c = b & 0xFF;
            if (c == 0) {
                throw new BundleRejection(BundleRule.PATH_NUL,
                        "a NUL inside the name: '" + BundleRejection.render(name) + "'");
            }
            if (c < 0x20 || c == 0x7F) {
                throw new BundleRejection(BundleRule.PATH_CONTROL_CHARACTER,
                        "a control character (0x" + String.format("%02x", c) + ") in the"
                                + " name: '" + BundleRejection.render(name) + "'");
            }
            if (c == '\\') {
                throw new BundleRejection(BundleRule.PATH_BACKSLASH,
                        "a backslash in the name, which is a literal character here and a"
                                + " separator to anything that later reads it on Windows: '"
                                + BundleRejection.render(name) + "'");
            }
        }

        String text = decodeStrictly(name);

        if (!Normalizer.isNormalized(text, Normalizer.Form.NFC)) {
            throw new BundleRejection(BundleRule.PATH_NOT_NFC,
                    "the name is valid UTF-8 but not in NFC: '" + BundleRejection.render(name)
                            + "'. It is refused rather than normalised, because normalising"
                            + " it would publish a path the uploader did not send");
        }
        if (text.charAt(0) == '/') {
            throw new BundleRejection(BundleRule.PATH_ABSOLUTE,
                    "an absolute path: '" + text + "'");
        }

        String canonical = text;
        if (canonical.endsWith("/")) {
            if (!directoryHeader) {
                throw new BundleRejection(BundleRule.PATH_TRAILING_SLASH,
                        "a trailing slash on a member that is not a directory header: '"
                                + text + "'");
            }
            // A conventional trailing slash on a directory header, and the only one: it is
            // removed here so that "a/" and "a" collide for duplicate detection rather than
            // reading as two different members.
            canonical = canonical.substring(0, canonical.length() - 1);
        }
        if (canonical.isEmpty()) {
            throw new BundleRejection(BundleRule.PATH_EMPTY,
                    "a directory header naming the archive root itself: '" + text + "'");
        }

        List<String> segments = new ArrayList<>();
        for (String segment : canonical.split("/", -1)) {
            if (segment.isEmpty()) {
                throw new BundleRejection(BundleRule.PATH_EMPTY_SEGMENT,
                        "an empty path segment, from a doubled or leading separator: '"
                                + text + "'");
            }
            if (segment.equals(".")) {
                throw new BundleRejection(BundleRule.PATH_DOT_SEGMENT,
                        "a '.' segment: '" + text + "'");
            }
            if (segment.equals("..")) {
                throw new BundleRejection(BundleRule.PATH_TRAVERSAL,
                        "a '..' segment: '" + text + "'");
            }
            int segmentBytes = segment.getBytes(StandardCharsets.UTF_8).length;
            if (segmentBytes > limits.maxSegmentBytes()) {
                throw new BundleRejection(BundleRule.PATH_SEGMENT_TOO_LONG,
                        "a segment of " + segmentBytes + " bytes, over the configured "
                                + limits.maxSegmentBytes() + ": '" + text + "'");
            }
            segments.add(segment);
        }

        Role role;
        List<String> payloadSegments;
        if (segments.size() == 1 && segments.get(0).equals(MANIFEST_MEMBER) && !directoryHeader) {
            role = Role.MANIFEST;
            payloadSegments = List.of();
        } else if (segments.get(0).equals(PAYLOAD_ROOT)) {
            role = Role.PAYLOAD;
            payloadSegments = segments.subList(1, segments.size());
            if (payloadSegments.isEmpty() && !directoryHeader) {
                throw new BundleRejection(BundleRule.LAYOUT_UNEXPECTED_MEMBER,
                        "'" + PAYLOAD_ROOT + "' as a regular member: it is the payload"
                                + " directory, and a file cannot also be it");
            }
        } else {
            throw new BundleRejection(BundleRule.LAYOUT_UNEXPECTED_MEMBER,
                    "'" + text + "' is neither " + MANIFEST_MEMBER + " nor under "
                            + PAYLOAD_ROOT + "/, and the bundle layout has no other place"
                            + " for a member");
        }

        String payloadPath = String.join("/", payloadSegments);
        int payloadBytes = payloadPath.getBytes(StandardCharsets.UTF_8).length;
        if (payloadBytes > limits.maxPathBytes()) {
            throw new BundleRejection(BundleRule.PATH_TOO_LONG,
                    "a payload path of " + payloadBytes + " bytes, over the configured "
                            + limits.maxPathBytes() + ": '" + text + "'");
        }
        if (payloadSegments.size() > limits.maxDepth()) {
            throw new BundleRejection(BundleRule.PATH_TOO_DEEP,
                    "a payload path " + payloadSegments.size() + " segments deep, over the"
                            + " configured " + limits.maxDepth() + ": '" + text + "'");
        }

        return new MemberPath(String.join("/", segments), payloadPath,
                new ArrayList<>(payloadSegments), role, directoryHeader);
    }

    private static String decodeStrictly(byte[] name) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(name)).toString();
        } catch (CharacterCodingException ex) {
            throw new BundleRejection(BundleRule.PATH_NOT_UTF8,
                    "the name is not valid UTF-8, so it has no defined normalisation and two"
                            + " readers would disagree about what it says: '"
                            + BundleRejection.render(name) + "'");
        }
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    /** The member's own path inside the archive, with any conventional trailing slash removed. */
    public String memberPath() {
        return memberPath;
    }

    /** The path relative to the payload root; empty for the manifest and for the root itself. */
    public String payloadPath() {
        return payloadPath;
    }

    public List<String> payloadSegments() {
        return payloadSegments;
    }

    public Role role() {
        return role;
    }

    public boolean isDirectory() {
        return directory;
    }

    @Override
    public String toString() {
        return memberPath + (directory ? "/" : "");
    }
}
