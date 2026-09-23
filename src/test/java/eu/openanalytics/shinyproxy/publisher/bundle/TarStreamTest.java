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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The walk, end to end over real tar bytes.
 *
 * <p>The cases that matter here are the ones no lower layer can see: a name with three
 * possible sources, a metadata header that describes nothing, and the bound that has to be
 * applied to a DECLARED size rather than to bytes in hand.
 *
 * <p>That last one is measured by ORDER rather than by verdict. Both a walk that pre-checks
 * and a walk that reads first end in PAX_HEADER_TOO_LARGE, so the rejection cannot
 * distinguish them (finding 3b37820-F2); the source stream counts what it was asked for
 * instead.
 */
public class TarStreamTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    @Test
    public void anOrdinaryArchiveArrivesAsItsMembers() throws Exception {
        byte[] archive = TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .directory("app")
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .file("app/renv.lock", "{}".getBytes(StandardCharsets.UTF_8))
                .end();

        Map<String, String> seen = walk(archive);
        assertEquals(List.of("manifest.json", "app", "app/app.R", "app/renv.lock"),
                new ArrayList<>(seen.keySet()));
        assertEquals("library(shiny)\n", seen.get("app/app.R"));
        assertEquals("", seen.get("app"), "a directory has no content");
    }

    @Test
    public void aGnuLongNameNamesTheMemberAfterIt() throws Exception {
        String name = "app/www/" + "d".repeat(150) + ".txt";
        byte[] archive = TarArchives.archive()
                .longName(name)
                .file("app/www/placeholder", "content".getBytes(StandardCharsets.UTF_8))
                .end();

        Map<String, String> seen = walk(archive);
        assertEquals(List.of(name), new ArrayList<>(seen.keySet()),
                "the long name replaces the header's own, which is truncated to 100 bytes");
        assertEquals("content", seen.get(name));
    }

    @Test
    public void aPaxPathOverrideNamesTheMemberAfterIt() throws Exception {
        byte[] archive = TarArchives.archive()
                .pax("path", "app/www/été-rapport.txt")
                .file("app/www/short.txt", "x".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(List.of("app/www/été-rapport.txt"), new ArrayList<>(walk(archive).keySet()));
    }

    @Test
    public void theOverrideIsANameAndNotABlessedOne() throws Exception {
        // trav-pax-override, end to end: a benign ustar name with an override to a traversal.
        // A reader that ignores the override never sees it; a reader that trusts it writes
        // outside the root. This one applies it and then refuses it.
        byte[] archive = TarArchives.archive()
                .pax("path", "app/../../pax-escape.txt")
                .file("app/innocent.txt", "owned\n".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(BundleRule.PATH_TRAVERSAL, ruleFor(archive));
    }

    @Test
    public void aMemberMayNotCarryTwoNames() throws Exception {
        // Refused at the second metadata header rather than at the member, in either order.
        // The first version of the walk also had a both-present branch at the member; this
        // test never reached it, which is how it was found to be unreachable.
        byte[] gnuThenPax = TarArchives.archive()
                .longName("app/from-gnu.txt")
                .pax("path", "app/from-pax.txt")
                .file("app/from-header.txt", "x".getBytes(StandardCharsets.UTF_8))
                .end();
        BundleRejection ex = assertThrows(BundleRejection.class, () -> walk(gnuThenPax));
        assertEquals(BundleRule.METADATA_HEADER_MISPLACED, ex.rule());
        assertTrue(ex.getMessage().contains("follows another metadata header"), ex.getMessage());

        byte[] paxThenGnu = TarArchives.archive()
                .pax("path", "app/from-pax.txt")
                .longName("app/from-gnu.txt")
                .file("app/from-header.txt", "x".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(BundleRule.METADATA_HEADER_MISPLACED, ruleFor(paxThenGnu));
    }

    @Test
    public void aMetadataHeaderThatDescribesNothingIsRefused() throws Exception {
        byte[] trailing = TarArchives.archive()
                .file("app/app.R", "x".getBytes(StandardCharsets.UTF_8))
                .pax("path", "app/never-arrives.txt")
                .end();
        BundleRejection ex = assertThrows(BundleRejection.class, () -> walk(trailing));
        assertEquals(BundleRule.METADATA_HEADER_MISPLACED, ex.rule());
        assertTrue(ex.getMessage().contains("not there"), ex.getMessage());

        byte[] doubled = TarArchives.archive()
                .pax("path", "app/one.txt")
                .pax("path", "app/two.txt")
                .file("app/x.txt", "x".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(BundleRule.METADATA_HEADER_MISPLACED, ruleFor(doubled));
    }

    @Test
    public void anExtendedHeaderIsRefusedOnItsClaimBeforeItsBytes() throws Exception {
        // 3b37820-F2, discharged. bomb-huge-pax-field is four times the cap; the archive
        // here carries only the header block, so a walk that read first would demand bytes
        // that are not there and report truncation instead.
        long declared = 4 * LIMITS.maxExtendedHeaderBytes();
        byte[] archive = TarArchives.archive()
                .headerOnly("PaxHeader", declared, 'x')
                .end();

        CountingStream source = new CountingStream(archive);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> TarStream.walk(source, LIMITS, (path, header, content) -> { }));

        assertEquals(BundleRule.PAX_HEADER_TOO_LARGE, ex.rule());
        assertTrue(ex.getMessage().contains("before the bytes are read"), ex.getMessage());
        assertEquals(TarHeader.BLOCK, source.read,
                "the walk read " + source.read + " bytes to refuse a header it could refuse"
                        + " from its declared size alone — which is what the fixture is"
                        + " about, and what a verdict cannot show");
    }

    @Test
    public void aLongNameHeaderIsBoundedTheSameWay() throws Exception {
        long declared = 64L * 1024 * 1024;
        byte[] archive = TarArchives.archive()
                .headerOnly("././@LongLink", declared, 'L')
                .end();

        CountingStream source = new CountingStream(archive);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> TarStream.walk(source, LIMITS, (path, header, content) -> { }));

        assertEquals(BundleRule.PATH_TOO_LONG, ex.rule());
        assertEquals(TarHeader.BLOCK, source.read,
                "a name that cannot be valid at any length was read before being refused");
    }

    @Test
    public void aLongNameWithinTheBoundIsStillJudgedAsAPath() throws Exception {
        // The accepted half of the bound, and the proof that passing it is not the same as
        // being allowed: this name is short enough to read and still too deep to accept.
        String deep = "app/" + "d/".repeat((int) LIMITS.maxDepth() + 1) + "x.txt";
        byte[] archive = TarArchives.archive()
                .longName(deep)
                .file("app/placeholder", "x".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(BundleRule.PATH_TOO_DEEP, ruleFor(archive));
    }

    @Test
    public void membersAreCheckedAgainstEachOther() throws Exception {
        byte[] duplicate = TarArchives.archive()
                .file("app/app.R", "one".getBytes(StandardCharsets.UTF_8))
                .file("app/app.R", "two".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(BundleRule.DUPLICATE_MEMBER, ruleFor(duplicate));

        byte[] collision = TarArchives.archive()
                .file("app/app.R", "one".getBytes(StandardCharsets.UTF_8))
                .file("app/App.R", "two".getBytes(StandardCharsets.UTF_8))
                .end();
        assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor(collision));
    }

    @Test
    public void aSinkThatIgnoresContentDoesNotLoseTheArchive() throws Exception {
        // The walk hands out a stream; a sink is free not to read it. The members after it
        // must still arrive.
        byte[] archive = TarArchives.archive()
                .file("app/big.bin", new byte[3000])
                .file("app/after.txt", "here".getBytes(StandardCharsets.UTF_8))
                .end();

        List<String> names = new ArrayList<>();
        TarStream.walk(new ByteArrayInputStream(archive), LIMITS,
                (path, header, content) -> names.add(path.memberPath()));
        assertEquals(List.of("app/big.bin", "app/after.txt"), names);
    }

    @Test
    public void theLowerLayersStillApply() throws Exception {
        // Not re-testing them; asserting the walk does not somehow route around them.
        byte[] symlink = TarArchives.archive()
                .raw(TarArchives.header("app/link", 0, '2', "0000777"), new byte[0])
                .end();
        assertEquals(BundleRule.ENTRY_TYPE_NOT_ALLOWED, ruleFor(symlink));

        byte[] setuid = TarArchives.archive()
                .raw(TarArchives.header("app/run", 0, '0', "0004755"), new byte[0])
                .end();
        assertEquals(BundleRule.ENTRY_MODE_PRIVILEGED, ruleFor(setuid));

        byte[] unterminated = TarArchives.archive()
                .file("app/app.R", "x".getBytes(StandardCharsets.UTF_8))
                .unterminated();
        assertEquals(BundleRule.ARCHIVE_NO_END_MARKER, ruleFor(unterminated));
    }

    // ------------------------------------------------------------------ helpers

    private static Map<String, String> walk(byte[] archive) throws IOException {
        Map<String, String> seen = new LinkedHashMap<>();
        TarStream.walk(new ByteArrayInputStream(archive), LIMITS, (path, header, content) ->
                seen.put(path.memberPath(),
                        new String(content.readAllBytes(), StandardCharsets.UTF_8)));
        return seen;
    }

    private static BundleRule ruleFor(byte[] archive) {
        return assertThrows(BundleRejection.class, () -> walk(archive)).rule();
    }

    /** Counts what the walk actually asked the source for. */
    private static final class CountingStream extends InputStream {
        private final ByteArrayInputStream delegate;
        private int read;

        private CountingStream(byte[] bytes) {
            this.delegate = new ByteArrayInputStream(bytes);
        }

        @Override
        public int read() {
            int b = delegate.read();
            if (b >= 0) {
                read++;
            }
            return b;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            int n = delegate.read(buffer, offset, length);
            if (n > 0) {
                read += n;
            }
            return n;
        }
    }
}
