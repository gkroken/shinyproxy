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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * PAX records, with the corpus's two PAX fixtures as the anchors.
 *
 * <p>{@code trav-pax-override} is the reason the {@code path} keyword is honoured at all:
 * its ustar name is the innocent {@code app/innocent.txt} and its override is
 * {@code app/../../pax-escape.txt}, so a reader that ignores the override never sees the
 * traversal. Its record is written here byte for byte as the corpus writes it.
 *
 * <p>{@code bomb-huge-pax-field} is the reason the bound is checked before the bytes are
 * held rather than after they are parsed.
 */
public class PaxRecordsTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    @Test
    public void thePathOverrideIsTheOneKeywordThatChangesAnything() {
        // A correct record: the length field counts itself, so this one says 33 and is 33.
        PaxRecords records = PaxRecords.parse(
                "33 path=app/../../pax-escape.txt\n".getBytes(StandardCharsets.UTF_8), LIMITS);
        assertTrue(records.pathOverride().isPresent());
        assertArrayEquals("app/../../pax-escape.txt".getBytes(StandardCharsets.UTF_8),
                records.pathOverride().get());

        // The override is a NAME, not a blessed one: it goes through the same rules, and
        // this is the escape the fixture exists to catch.
        assertEquals(BundleRule.PATH_TRAVERSAL, assertThrows(BundleRejection.class,
                () -> MemberPath.parse(records.pathOverride().get(), false, LIMITS)).rule());
    }

    @Test
    public void theCorpusTravPaxOverrideRecordIsItselfMalformed() {
        // dev/fixtures/bundles/generate.py writes this record literally:
        //     b"30 path=app/../../pax-escape.txt\n"
        // It is 33 bytes and its length field claims 30, so a parser that trusts the length
        // finds 't' where the record's newline should be. This extractor therefore refuses
        // the fixture as PAX_RECORD_MALFORMED and never reaches the traversal it was built
        // to demonstrate.
        //
        // The DECISION is still reject, which is why the oracle has never noticed: both
        // outcomes look identical from outside. The fixture does not prove what it claims,
        // and a corpus fix is owed — recorded in the commit message rather than made here,
        // because changing a fixture regenerates its hash in expectations.json.
        byte[] asWritten = "30 path=app/../../pax-escape.txt\n".getBytes(StandardCharsets.UTF_8);
        assertEquals(33, asWritten.length, "the record is 33 bytes and claims 30");
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> PaxRecords.parse(asWritten, LIMITS));
        assertEquals(BundleRule.PAX_RECORD_MALFORMED, ex.rule());
        assertTrue(ex.getMessage().contains("newline"), ex.getMessage());
    }

    @Test
    public void aLegitimateLongNameIsWhatThisIsFor() {
        // pos-pax-filename: the accepted half. A format that refused every extended header
        // would pass every rejection below and fail this.
        byte[] name = "app/www/été-rapport.txt".getBytes(StandardCharsets.UTF_8);
        PaxRecords records = PaxRecords.parse(record("path", name), LIMITS);
        assertArrayEquals(name, records.pathOverride().get());
        assertEquals("www/été-rapport.txt",
                MemberPath.parse(records.pathOverride().get(), false, LIMITS).payloadPath());
    }

    @Test
    public void metadataThisExtractorStripsIsParsedAndDiscarded() {
        byte[] header = concat(record("mtime", "1700000000".getBytes(StandardCharsets.UTF_8)),
                concat(record("uid", "1000".getBytes(StandardCharsets.UTF_8)),
                       record("comment", "built by CI".getBytes(StandardCharsets.UTF_8))));
        PaxRecords records = PaxRecords.parse(header, LIMITS);
        assertFalse(records.pathOverride().isPresent(),
                "none of those keywords may produce a name");
    }

    @Test
    public void everyOtherKeywordIsRefusedByName() {
        for (String keyword : new String[] {"linkpath", "size", "charset", "hdrcharset",
                                            "GNU.sparse.size", "GNU.sparse.name",
                                            "SCHILY.xattr.user.demo", "SCHILY.acl.access",
                                            "RHT.security.selinux", "invented.tomorrow"}) {
            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> PaxRecords.parse(record(keyword, "x".getBytes(StandardCharsets.UTF_8)),
                            LIMITS),
                    "'" + keyword + "' was accepted");
            assertEquals(BundleRule.PAX_KEYWORD_NOT_ALLOWED, ex.rule(), keyword);
            assertTrue(ex.getMessage().contains(keyword),
                    "the rejection must name the keyword the publisher's tar writer emitted: "
                            + ex.getMessage());
        }
    }

    @Test
    public void theSameKeywordTwiceHasNoSingleMeaning() {
        byte[] header = concat(record("path", "app/a.txt".getBytes(StandardCharsets.UTF_8)),
                               record("path", "app/b.txt".getBytes(StandardCharsets.UTF_8)));
        assertEquals(BundleRule.PAX_DUPLICATE_KEYWORD, assertThrows(BundleRejection.class,
                () -> PaxRecords.parse(header, LIMITS)).rule());
    }

    @Test
    public void theHeaderBoundIsAPair() {
        // bomb-huge-pax-field is four times the cap; the pair here straddles it exactly.
        int max = (int) LIMITS.maxExtendedHeaderBytes();
        assertEquals(max, recordOfLength("comment", max).length);
        PaxRecords.parse(recordOfLength("comment", max), LIMITS);

        byte[] over = recordOfLength("comment", max + 1);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> PaxRecords.parse(over, LIMITS));
        assertEquals(BundleRule.PAX_HEADER_TOO_LARGE, ex.rule());

        // And it is the CONFIGURED bound, not the documented default.
        ExtractionLimits tight = ExtractionLimits.fromOverrides(
                Map.of("max_extended_header_bytes", "64"));
        assertEquals(BundleRule.PAX_HEADER_TOO_LARGE, assertThrows(BundleRejection.class,
                () -> PaxRecords.parse(recordOfLength("comment", 65), tight)).rule());
        PaxRecords.parse(recordOfLength("comment", 64), tight);
    }

    @Test
    public void aRecordThatCannotBeLocatedIsRefusedRatherThanGuessedAt() {
        // One case per branch, each asserting the branch by its message. Several of these
        // reached the same rule through a different check on the first attempt, which is
        // the defect this project keeps producing: a case passing for a reason it was not
        // written to test.
        assertMalformed("path=app/a.txt\n", "expected a decimal length");
        // All digits and no separator at all. "16path=..." looks like this case and is not:
        // 'p' is not a digit, so it is refused by the branch above and would have been that
        // case passing twice under two names.
        assertMalformed("1234", "no space after the length field");
        assertMalformed(" 16 path=a.txt\n", "an empty length field");
        // Shorter than its own length field plus a separator and a newline. "3 x=y\n" is
        // not this case — three is large enough to clear the guard, so it is refused for its
        // newline instead, which is the same case passing under another name.
        assertMalformed("1 x=y\n", "a record length of 1");
        assertMalformed("99 path=a.txt\n", "a record length of 99 with 14 byte(s) remaining");
        assertMalformed("18 path=app/a.txt.", "does not end with a newline");
        assertMalformed("17 pathapp/a.txt\n", "no '=' in the record");
        assertMalformed("9 =value\n", "an empty keyword");
        assertMalformed("99999999999999999999999 path=a\n", "does not fit in a 64-bit integer");

        // The control: the same shape, correct, is accepted. Fourteen is the true length of
        // "14 path=a.txt\n" — two digits, a space, the keyword, '=', the value, a newline.
        assertArrayEquals("a.txt".getBytes(StandardCharsets.UTF_8),
                PaxRecords.parse("14 path=a.txt\n".getBytes(StandardCharsets.UTF_8), LIMITS)
                        .pathOverride().get());
    }

    private static void assertMalformed(String header, String expectedReason) {
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> PaxRecords.parse(header.getBytes(StandardCharsets.UTF_8), LIMITS),
                "accepted: " + header);
        assertEquals(BundleRule.PAX_RECORD_MALFORMED, ex.rule(), header);
        assertTrue(ex.getMessage().contains(expectedReason),
                "refused by a different branch than the one under test: " + ex.getMessage());
    }

    @Test
    public void aValueMayContainNewlines() {
        // Which is exactly why the length delimits a record and scanning for '\n' does not.
        byte[] value = "line one\nline two".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(value, PaxRecords.parse(record("path", value), LIMITS)
                .pathOverride().get());
    }

    @Test
    public void anEmptyHeaderCarriesNoOverride() {
        assertFalse(PaxRecords.parse(new byte[0], LIMITS).pathOverride().isPresent());
    }

    // ------------------------------------------------------------------ helpers

    /** A record whose length field counts itself, as _pax_record does in the generator. */
    private static byte[] record(String keyword, byte[] value) {
        byte[] body = (" " + keyword + "=").getBytes(StandardCharsets.UTF_8);
        int n = body.length + value.length + 1;
        while (Integer.toString(n + Integer.toString(n).length()).length()
                != Integer.toString(n).length()) {
            n++;
        }
        int total = n + Integer.toString(n).length();
        byte[] prefix = Integer.toString(total).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length + value.length + 1];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        System.arraycopy(value, 0, out, prefix.length + body.length, value.length);
        out[out.length - 1] = '\n';
        return out;
    }

    /** A record whose complete encoded length is exactly {@code total} bytes. */
    private static byte[] recordOfLength(String keyword, int total) {
        int overhead = Integer.toString(total).length() + 1 + keyword.length() + 1 + 1;
        byte[] value = new byte[total - overhead];
        java.util.Arrays.fill(value, (byte) 'x');
        byte[] prefix = Integer.toString(total).getBytes(StandardCharsets.UTF_8);
        byte[] body = (" " + keyword + "=").getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[total];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        System.arraycopy(value, 0, out, prefix.length + body.length, value.length);
        out[total - 1] = '\n';
        return out;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] out = java.util.Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }
}
