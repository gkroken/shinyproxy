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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The path rules, driven by the shapes T2's corpus actually contains.
 *
 * <p>The hostile names here are the literal member names from
 * {@code dev/fixtures/bundles/generate.py} — {@code app/../../escape.txt},
 * {@code C:\escape.txt}, {@code app/%2e%2e/%2e%2e/escape.txt} and the rest — rather than
 * inventions that happen to exercise the same branches. The corpus was written before any
 * extractor existed and judges the finished one; agreeing with it here is the cheap half of
 * that agreement.
 *
 * <p>Every bound is asserted as a pair, the at-limit name accepted and the one-over name
 * refused, both derived from {@link ExtractionLimits} rather than written out. A suite of
 * refusals alone is satisfied by a parser that refuses everything.
 */
public class MemberPathTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    private static MemberPath parse(String name) {
        return MemberPath.parse(name.getBytes(StandardCharsets.UTF_8), name.endsWith("/"), LIMITS);
    }

    private static BundleRule ruleFor(String name) {
        return assertThrows(BundleRejection.class, () -> parse(name),
                "'" + name + "' was accepted").rule();
    }

    @Test
    public void ordinaryMembersAreAccepted() {
        assertEquals(MemberPath.Role.MANIFEST, parse("manifest.json").role());
        assertEquals("", parse("manifest.json").payloadPath());

        MemberPath app = parse("app/app.R");
        assertEquals(MemberPath.Role.PAYLOAD, app.role());
        assertEquals("app.R", app.payloadPath());
        assertFalse(app.isDirectory());

        assertEquals("www/style.css", parse("app/www/style.css").payloadPath());
        assertEquals("", parse("app/").payloadPath(), "the payload root's own directory header");
        assertTrue(parse("app/www/").isDirectory());
        assertEquals("www", parse("app/www/").payloadPath(),
                "a directory header's conventional trailing slash must not survive into the"
                        + " path, or 'www/' and 'www' would not collide");
    }

    @Test
    public void namesWithSpacesAndUnicodeAreOrdinary() {
        assertEquals("www/a file with spaces.txt",
                parse("app/www/a file with spaces.txt").payloadPath());
        assertEquals("日本語/ページ.html", parse("app/日本語/ページ.html").payloadPath());
        // Precomposed é: already NFC, and not to be confused with the decomposed case below.
        assertEquals("caf\u00e9.txt", parse("app/caf\u00e9.txt").payloadPath());
    }

    @Test
    public void theCorpusTraversalFormsAreEachRefusedForTheirOwnReason() {
        assertEquals(BundleRule.PATH_TRAVERSAL, ruleFor("app/../../escape.txt"));
        assertEquals(BundleRule.PATH_TRAVERSAL, ruleFor("app/a/b/../../../../escape.txt"));
        assertEquals(BundleRule.PATH_ABSOLUTE, ruleFor("/etc/skald-escape.txt"));
        assertEquals(BundleRule.PATH_DRIVE_LETTER, ruleFor("C:\\escape.txt"));
        assertEquals(BundleRule.PATH_BACKSLASH, ruleFor("\\\\server\\share\\escape.txt"));
        assertEquals(BundleRule.PATH_BACKSLASH, ruleFor("app\\escape.txt"));
        assertEquals(BundleRule.PATH_DOT_SEGMENT, ruleFor("app/./escape.txt"));
        assertEquals(BundleRule.PATH_EMPTY_SEGMENT, ruleFor("app//escape.txt"));
    }

    @Test
    public void percentEncodingIsText() {
        // trav-url-encoded. Nothing here decodes: %2e%2e is a five-character directory name,
        // and a validator that decoded it would manufacture the traversal it is looking for.
        // The fixture is still rejected by the bundle as a whole — the manifest does not list
        // this file — but that is the inventory's rule to enforce, not this one's.
        MemberPath path = parse("app/%2e%2e/%2e%2e/escape.txt");
        assertEquals("%2e%2e/%2e%2e/escape.txt", path.payloadPath());
        assertEquals(3, path.payloadSegments().size());
    }

    @Test
    public void bytesThatHaveNoSafeTextFormAreRefusedAsBytes() {
        byte[] invalidUtf8 = new byte[] {'a', 'p', 'p', '/', (byte) 0x80, '.', 't', 'x', 't'};
        BundleRejection notUtf8 = assertThrows(BundleRejection.class,
                () -> MemberPath.parse(invalidUtf8, false, LIMITS));
        assertEquals(BundleRule.PATH_NOT_UTF8, notUtf8.rule());
        assertTrue(notUtf8.getMessage().contains("\\x80"),
                "the raw byte should be escaped into the message: " + notUtf8.getMessage());

        byte[] withTab = "app/we\tird.txt".getBytes(StandardCharsets.UTF_8);
        BundleRejection control = assertThrows(BundleRejection.class,
                () -> MemberPath.parse(withTab, false, LIMITS));
        assertEquals(BundleRule.PATH_CONTROL_CHARACTER, control.rule());
        assertFalse(control.getMessage().contains("\t"),
                "the control character reached the message unescaped, which is the corruption"
                        + " the rule exists to prevent: " + control.getMessage());
        assertTrue(control.getMessage().contains("\\x09"), control.getMessage());
    }

    @Test
    public void aNulEndsTheNameAndAnythingAfterItIsAnAttack() {
        byte[] field = new byte[32];
        byte[] visible = "app/harmless.txt".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(visible, 0, field, 0, visible.length);
        // Padding only: the ordinary case, and the control for the hostile one below.
        assertEquals("harmless.txt",
                MemberPath.parseNameField(field, false, LIMITS).payloadPath());

        byte[] hostile = field.clone();
        byte[] hidden = "../escape".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(hidden, 0, hostile, visible.length + 1, hidden.length);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> MemberPath.parseNameField(hostile, false, LIMITS));
        assertEquals(BundleRule.PATH_NUL, ex.rule());

        // The same bytes with an explicit length are a name containing a NUL, not padding.
        byte[] embedded = "app/a\u0000b.txt".getBytes(StandardCharsets.UTF_8);
        assertEquals(BundleRule.PATH_NUL, assertThrows(BundleRejection.class,
                () -> MemberPath.parse(embedded, false, LIMITS)).rule());
    }

    @Test
    public void aDecomposedNameIsRefusedRatherThanNormalised() {
        // dup-nfc-alias in the corpus: byte-different, identical after normalisation. If this
        // were normalised instead, the extractor would write a path the uploader never sent
        // and the inventory would then disagree with the payload for a reason nobody caused.
        String decomposed = "app/cafe\u0301.txt";
        BundleRejection ex = assertThrows(BundleRejection.class, () -> parse(decomposed));
        assertEquals(BundleRule.PATH_NOT_NFC, ex.rule());
        assertTrue(ex.getMessage().contains("refused rather than normalised"), ex.getMessage());
        // The composed spelling of the same name is ordinary, so the rule is about the
        // encoding and not about the character.
        assertEquals("caf\u00e9.txt", parse("app/caf\u00e9.txt").payloadPath());
    }

    @Test
    public void aTrailingSlashIsOnlyEverADirectoryConvention() {
        assertEquals("www", parse("app/www/").payloadPath());
        assertEquals(BundleRule.PATH_TRAILING_SLASH,
                assertThrows(BundleRejection.class,
                        () -> MemberPath.parse("app/www/".getBytes(StandardCharsets.UTF_8),
                                false, LIMITS)).rule());
        assertEquals(BundleRule.PATH_EMPTY_SEGMENT, ruleFor("app/www//"));
    }

    @Test
    public void theLayoutHasOnlyTwoPlacesForAMember() {
        assertEquals(BundleRule.LAYOUT_UNEXPECTED_MEMBER, ruleFor("README.md"));
        assertEquals(BundleRule.LAYOUT_UNEXPECTED_MEMBER, ruleFor("other/app.R"));
        assertEquals(BundleRule.LAYOUT_UNEXPECTED_MEMBER, ruleFor("app"),
                "'app' as a regular file is the payload directory being claimed by a file");
        assertEquals(BundleRule.LAYOUT_UNEXPECTED_MEMBER, ruleFor("manifest.json/"),
                "a directory header named manifest.json is not the manifest");
        assertEquals(BundleRule.PATH_EMPTY, ruleFor(""));
        assertEquals(BundleRule.PATH_ABSOLUTE, ruleFor("/"));
        // appliance/ starts with the payload root's letters and is not the payload root.
        assertEquals(BundleRule.LAYOUT_UNEXPECTED_MEMBER, ruleFor("appliance/app.R"));
    }

    @Test
    public void everyBoundIsAPairOfNamesStraddlingIt() {
        long segmentMax = LIMITS.maxSegmentBytes();
        String atSegment = "s".repeat((int) segmentMax - ".txt".length()) + ".txt";
        assertEquals(segmentMax, atSegment.getBytes(StandardCharsets.UTF_8).length);
        assertEquals(atSegment, parse("app/" + atSegment).payloadPath());
        assertEquals(BundleRule.PATH_SEGMENT_TOO_LONG, ruleFor("app/" + atSegment + "x"));

        int depthMax = (int) LIMITS.maxDepth();
        String atDepth = deepPath(depthMax);
        assertEquals(depthMax, parse("app/" + atDepth).payloadSegments().size());
        assertEquals(BundleRule.PATH_TOO_DEEP, ruleFor("app/" + deepPath(depthMax + 1)));

        int pathMax = (int) LIMITS.maxPathBytes();
        String atLength = pathOfLength(pathMax);
        assertEquals(pathMax, atLength.getBytes(StandardCharsets.UTF_8).length);
        assertEquals(atLength, parse("app/" + atLength).payloadPath());
        assertEquals(BundleRule.PATH_TOO_LONG, ruleFor("app/" + pathOfLength(pathMax + 1)));
    }

    @Test
    public void theBoundsAreTheConfiguredOnesAndNotTheDefaults() {
        // A parser that read the documented defaults directly would pass everything above and
        // enforce the wrong numbers for an operator who moved them — and would enforce the
        // wrong numbers against the corpus, which runs a reduced profile by default.
        // The three bounds are moved separately, because under one tight profile they mask
        // each other: with an 8-byte segment cap and a depth cap of 2 no path can reach a
        // 24-byte total, so a "total too long" case under that profile is unreachable and
        // would have been asserting the segment rule under another name.
        ExtractionLimits shortSegments = ExtractionLimits.fromOverrides(
                java.util.Map.of("max_segment_bytes", "8"));
        assertEquals(BundleRule.PATH_SEGMENT_TOO_LONG, assertThrows(BundleRejection.class,
                () -> MemberPath.parse("app/123456789".getBytes(StandardCharsets.UTF_8),
                        false, shortSegments)).rule());

        ExtractionLimits shallow = ExtractionLimits.fromOverrides(
                java.util.Map.of("max_depth", "2"));
        assertEquals(BundleRule.PATH_TOO_DEEP, assertThrows(BundleRejection.class,
                () -> MemberPath.parse("app/a/b/c.txt".getBytes(StandardCharsets.UTF_8),
                        false, shallow)).rule());
        assertEquals("a/b", MemberPath.parse("app/a/b".getBytes(StandardCharsets.UTF_8),
                false, shallow).payloadPath(), "the accepted half of the same pair");

        ExtractionLimits shortPaths = ExtractionLimits.fromOverrides(
                java.util.Map.of("max_path_bytes", "10"));
        assertEquals(BundleRule.PATH_TOO_LONG, assertThrows(BundleRejection.class,
                () -> MemberPath.parse("app/aaaaaaaa/bb".getBytes(StandardCharsets.UTF_8),
                        false, shortPaths)).rule());
        assertEquals("aaaaaaaa/b", MemberPath.parse("app/aaaaaaaa/b"
                .getBytes(StandardCharsets.UTF_8), false, shortPaths).payloadPath(),
                "the accepted half: ten bytes exactly");
        // and the same names under the documented defaults are ordinary
        assertEquals("a/b/c.txt", parse("app/a/b/c.txt").payloadPath());
    }

    @Test
    public void theRuleNameIsWhatAPublisherWouldSee() {
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> parse("app/../../escape.txt"));
        assertTrue(ex.getMessage().startsWith("PATH_TRAVERSAL: "), ex.getMessage());
        assertSame(BundleRule.PATH_TRAVERSAL, ex.rule());
        assertEquals("PATH_TRAVERSAL", BundleRule.PATH_TRAVERSAL.ruleName());
    }

    @Test
    public void aHiddenBytesRejectionStaysReadableWhateverTheFieldContains() {
        // 525c504-F1: the bound is a property of the message, so it is driven from the
        // fields that break it rather than from one three-byte name with fifty characters
        // of headroom. Each case below produced an over-long message before this test.
        byte[] longName = hidingField("a".repeat(140).getBytes(StandardCharsets.UTF_8), 141,
                new byte[] {'z'});
        byte[] controlName = hidingField(repeatByte((byte) 0x01, 140), 141, new byte[] {'z'});
        // Short in bytes and long once rendered: thirty control characters are a hundred and
        // twenty characters of escapes. A budget counted in bytes rather than in rendered
        // characters passes every other case here and fails this one, which is why it is a
        // separate shape rather than a smaller version of the one above.
        byte[] shortButEscaped = hidingField(repeatByte((byte) 0x01, 30), 31, new byte[] {'z'});
        byte[] oneLongRun = hidingField("app".getBytes(StandardCharsets.UTF_8), 4,
                repeatByte((byte) 'Z', 50));
        byte[] twoRuns = hidingField("app".getBytes(StandardCharsets.UTF_8), 4,
                "../esc".getBytes(StandardCharsets.UTF_8));
        System.arraycopy("../esc".getBytes(StandardCharsets.UTF_8), 0, twoRuns, 120, 6);
        byte[] ordinary = hidingField("app".getBytes(StandardCharsets.UTF_8), 4,
                "../esc".getBytes(StandardCharsets.UTF_8));

        for (byte[] field : new byte[][] {longName, controlName, shortButEscaped, oneLongRun,
                                          twoRuns, ordinary}) {
            String message = assertThrows(BundleRejection.class,
                    () -> MemberPath.nameFromField(field, "prefix")).getMessage();
            assertTrue(message.length() <= MemberPath.MAX_HIDDEN_BYTES_MESSAGE,
                    "a rejection of " + message.length() + " characters is skimmed past,"
                            + " not read: " + message);
        }

        // 525c504-F2: when the bytes shown are fewer than the bytes counted, say so. A
        // publisher who fixes the run they were shown and is refused again for one they
        // were not has been told half the truth.
        assertTrue(ellipsisIn(oneLongRun), "a run clipped at the window is not marked");
        assertTrue(ellipsisIn(twoRuns), "a second run further along the field is not marked");
        assertTrue(messageFor(twoRuns).contains("12 byte(s)"),
                "the count is of every hidden byte, not of the shown run: "
                        + messageFor(twoRuns));
        assertFalse(ellipsisIn(ordinary),
                "nothing was cut here, so the mark must not appear — otherwise it says"
                        + " nothing when it does");
    }

    private static String messageFor(byte[] field) {
        return assertThrows(BundleRejection.class,
                () -> MemberPath.nameFromField(field, "prefix")).getMessage();
    }

    private static boolean ellipsisIn(byte[] field) {
        return messageFor(field).contains("\u2026");
    }

    /** A 155-byte ustar-prefix-shaped field: a name, its NUL padding, and bytes hidden in it. */
    private static byte[] hidingField(byte[] visible, int hiddenAt, byte[] hidden) {
        byte[] field = new byte[155];
        System.arraycopy(visible, 0, field, 0, visible.length);
        System.arraycopy(hidden, 0, field, hiddenAt, hidden.length);
        return field;
    }

    private static byte[] repeatByte(byte value, int count) {
        byte[] out = new byte[count];
        java.util.Arrays.fill(out, value);
        return out;
    }

    /** {@code d0/d1/.../x.txt} with exactly {@code segments} segments. */
    private static String deepPath(int segments) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < segments - 1; i++) {
            out.append("d").append(i).append("/");
        }
        return out.append("x.txt").toString();
    }

    /**
     * A legal payload path of exactly {@code bytes} UTF-8 bytes.
     *
     * <p>Segment length is 63 so that a path at the default total bound stays well inside
     * the depth and per-segment bounds: the first attempt used twenty-byte segments and
     * produced a path that was over the depth limit before it was over the length limit,
     * so the test failed for a bound it was not testing.
     */
    private static String pathOfLength(int bytes) {
        final int segment = 63;
        java.util.List<String> parts = new java.util.ArrayList<>();
        int remaining = bytes;
        while (remaining > 0) {
            int separator = parts.isEmpty() ? 0 : 1;
            int take = Math.min(remaining - separator, segment);
            if (take <= 0) {
                // The leftover cannot start a segment of its own; it goes on the last one.
                parts.set(parts.size() - 1, parts.get(parts.size() - 1) + "a".repeat(remaining));
                break;
            }
            parts.add("a".repeat(take));
            remaining -= take + separator;
        }
        String path = String.join("/", parts);
        assertEquals(bytes, path.getBytes(StandardCharsets.UTF_8).length,
                "the helper built a path of the wrong length, so the bound is untested");
        return path;
    }
}
