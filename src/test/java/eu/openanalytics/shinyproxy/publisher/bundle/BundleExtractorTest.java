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
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The pipeline, from an upload to files on a disk.
 *
 * <p>The property every case here shares is the one no earlier layer had to have: after a
 * refusal there is nothing left. Each rejection asserts the workspace is empty afterwards,
 * because a partial extraction left on disk is a directory some later step may mistake for
 * a validated one — and because the corpus's oracle checks exactly that ("a rejected bundle
 * left an empty root: no residue to clean up later").
 */
public class BundleExtractorTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    @Test
    public void anOrdinaryBundleBecomesFiles(@TempDir Path workspace) throws Exception {
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", "{\"schema_version\":1}".getBytes(StandardCharsets.UTF_8))
                .directory("app")
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .directory("app/www")
                .file("app/www/style.css", "body {}".getBytes(StandardCharsets.UTF_8))
                .end());

        BundleExtractor.Extracted extracted =
                BundleExtractor.extract(new ByteArrayInputStream(upload), upload.length,
                        workspace, LIMITS);
        try (ExtractionRoot root = extracted.root()) {
            assertEquals("{\"schema_version\":1}",
                    new String(extracted.manifest(), StandardCharsets.UTF_8));
            assertEquals(2, extracted.files());
            assertEquals("library(shiny)\n".length() + "body {}".length(), extracted.bytes());

            assertEquals("library(shiny)\n", Files.readString(root.path().resolve("app.R")));
            assertEquals("body {}", Files.readString(root.path().resolve("www/style.css")));
            assertFalse(Files.exists(root.path().resolve("manifest.json")),
                    "the manifest is read, not written: this directory is the payload root"
                            + " and a bundle may carry its own app/manifest.json");
        }
    }

    @Test
    public void aRefusalLeavesNothingBehind(@TempDir Path workspace) throws Exception {
        // Each of these fails at a different layer, and after each one the workspace must be
        // as empty as it was. The traversal is the one that matters most: it is refused
        // AFTER two members have already been written.
        byte[] traversal = gzip(TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .file("app/one.txt", "one".getBytes(StandardCharsets.UTF_8))
                .file("app/two.txt", "two".getBytes(StandardCharsets.UTF_8))
                .file("app/../../escape.txt", "owned".getBytes(StandardCharsets.UTF_8))
                .end());
        assertEquals(BundleRule.PATH_TRAVERSAL, refusalFor(traversal, workspace));
        assertEmpty(workspace);

        byte[] noMarker = gzip(TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .unterminated());
        assertEquals(BundleRule.ARCHIVE_NO_END_MARKER, refusalFor(noMarker, workspace));
        assertEmpty(workspace);

        byte[] notGzip = "PK\u0003\u0004 not a gzip".getBytes(StandardCharsets.UTF_8);
        assertEquals(BundleRule.ARCHIVE_NOT_GZIP, refusalFor(notGzip, workspace));
        assertEmpty(workspace);

        byte[] duplicate = gzip(TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .file("app/app.R", "one".getBytes(StandardCharsets.UTF_8))
                .file("app/app.R", "two".getBytes(StandardCharsets.UTF_8))
                .end());
        assertEquals(BundleRule.DUPLICATE_MEMBER, refusalFor(duplicate, workspace));
        assertEmpty(workspace);
    }

    @Test
    public void aFailureThatIsNotARejectionAlsoLeavesNothing(@TempDir Path workspace)
            throws Exception {
        // "Delete it on all failure/cancellation paths" includes the paths that are not
        // rejections, and this is the test that says so — so it has to fail in a way that is
        // genuinely not one. The first version used a truncated upload, which every layer
        // below turns into ARCHIVE_TAR_TRUNCATED: a BundleRejection, and the assertion said
        // only RuntimeException, so it passed against a cleanup that ran for rejections
        // alone. Narrowing the cleanup to `catch (BundleRejection)` survived as a mutation,
        // which is how that was found.
        //
        // A source that throws something else partway is the real case: an I/O layer failing,
        // a bug in any layer below, a cancellation.
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .file("app/one.txt", "one".getBytes(StandardCharsets.UTF_8))
                .file("app/two.txt", "two".getBytes(StandardCharsets.UTF_8))
                .end());

        InputStream hostile = new InputStream() {
            private final ByteArrayInputStream delegate = new ByteArrayInputStream(upload);
            private int served;

            @Override
            public int read() {
                throw new IllegalStateException("the storage layer gave up");
            }

            @Override
            public int read(byte[] buffer, int offset, int length) {
                if (served >= upload.length / 2) {
                    throw new IllegalStateException("the storage layer gave up");
                }
                int n = delegate.read(buffer, offset, Math.min(length, 64));
                served += Math.max(n, 0);
                return n;
            }
        };

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> BundleExtractor.extract(hostile, upload.length, workspace, LIMITS));
        assertEquals("the storage layer gave up", ex.getMessage(),
                "the failure was turned into something else on its way out");
        assertEmpty(workspace);
    }

    @Test
    public void theManifestComesFirst(@TempDir Path workspace) throws Exception {
        byte[] late = gzip(TarArchives.archive()
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .end());
        assertEquals(BundleRule.MANIFEST_NOT_FIRST, refusalFor(late, workspace));
        assertEmpty(workspace);

        // But a DIRECTORY header before the manifest is permitted: the contract's ordering
        // clause is about the first regular FILE, and its next sentence permits optional
        // directory headers. Refusing both made one archive accepted or refused depending
        // only on where its 'app/' header sat (e670073-F1). The pair is what distinguishes
        // "first regular file" from "first member", so both halves are here.
        byte[] leadingDirectory = gzip(TarArchives.archive()
                .directory("app")
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .end());
        try (ExtractionRoot root = BundleExtractor.extract(
                new ByteArrayInputStream(leadingDirectory), leadingDirectory.length,
                workspace, LIMITS).root()) {
            assertEquals("library(shiny)\n", Files.readString(root.path().resolve("app.R")));
            root.deleteTree();
        }

        byte[] missing = gzip(TarArchives.archive()
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .end());
        // Refused for arriving before a manifest that never comes, which is the earlier and
        // more specific answer; MANIFEST_MISSING is what an archive with no members at all
        // gets.
        assertEquals(BundleRule.MANIFEST_NOT_FIRST, refusalFor(missing, workspace));

        byte[] empty = gzip(TarArchives.archive().end());
        assertEquals(BundleRule.MANIFEST_MISSING, refusalFor(empty, workspace));
        assertEmpty(workspace);
    }

    @Test
    public void theManifestIsBoundedOnItsClaim(@TempDir Path workspace) throws Exception {
        ExtractionLimits small = ExtractionLimits.fromOverrides(
                Map.of("max_manifest_bytes", "16"));

        byte[] declared = gzip(TarArchives.archive()
                .headerOnly("manifest.json", 1024, '0')
                .end());
        CountingStream source = new CountingStream(declared);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> BundleExtractor.extract(source, declared.length, workspace, small));
        assertEquals(BundleRule.MANIFEST_TOO_LARGE, ex.rule());
        assertTrue(ex.getMessage().contains("before the bytes are read"), ex.getMessage());
        assertEmpty(workspace);

        // The accepted half, at exactly the bound.
        byte[] atLimit = gzip(TarArchives.archive()
                .file("manifest.json", "0123456789abcdef".getBytes(StandardCharsets.UTF_8))
                .end());
        try (ExtractionRoot root = BundleExtractor.extract(new ByteArrayInputStream(atLimit),
                atLimit.length, workspace, small).root()) {
            assertEquals(0, Files.list(root.path()).count());
        }
    }

    @Test
    public void anUploadWhoseLengthIsKnownIsRefusedBeforeItIsParsed(@TempDir Path workspace)
            throws Exception {
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .end());
        ExtractionLimits tiny = ExtractionLimits.fromOverrides(
                Map.of("max_compressed_bytes", Long.toString(upload.length - 1)));

        CountingStream source = new CountingStream(upload);
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_COMPRESSED, assertThrows(BundleRejection.class,
                () -> BundleExtractor.extract(source, upload.length, workspace, tiny)).rule());
        assertEquals(0, source.read, "the upload was read before its declared length was checked");
        assertEmpty(workspace);
    }

    @Test
    public void aCleanupThatFailsDoesNotReplaceTheFailureItWasCleaningUpAfter(
            @TempDir Path workspace) throws Exception {
        // e670073-F2. An exception thrown from a finally block discards the one in flight,
        // so a delete that failed would replace the rejection naming the rule with an
        // IOException about the filesystem — losing the rule AND leaving the tree.
        //
        // The review could not arrange for deleteTree to fail from outside, and neither
        // could I from the workspace alone: the root is ours and writable. But the hostile
        // source can do it. On its way out it moves the root aside and puts an occupied
        // directory under its name. The descriptor-relative walk empties the real root
        // wherever it now is; the last step removes the root by path, finds the occupant,
        // and fails. The original failure has to survive that.
        //
        // An earlier version made the workspace read-only instead. Root ignores that, so
        // under --user 0:0 the delete succeeded and the case failed pointing at
        // BundleExtractor rather than at the uid (c97863d-F2). A rename does not depend on
        // who is running, so this case runs, and means the same thing, everywhere.
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", "{}".getBytes(StandardCharsets.UTF_8))
                .file("app/one.txt", "one".getBytes(StandardCharsets.UTF_8))
                // Incompressible, so the halfway point falls well inside it and app/one.txt
                // is already on disk when the sabotage runs. Without it nothing had been
                // written yet, and the walk's assertion below passed with the walk deleted.
                .file("app/tail.bin", incompressible(32 * 1024))
                .end());
        java.util.List<Path> heldAtSabotage = new java.util.ArrayList<>();

        InputStream sabotage = new InputStream() {
            private final ByteArrayInputStream delegate = new ByteArrayInputStream(upload);
            private int served;
            private boolean sabotaged;

            @Override
            public int read() {
                throw new IllegalStateException("unused");
            }

            @Override
            public int read(byte[] buffer, int offset, int length) throws IOException {
                if (sabotaged) {
                    // Closing the gzip member reads again. Once is the whole sabotage.
                    throw new IllegalStateException("the storage layer gave up");
                }
                if (served >= upload.length / 2) {
                    sabotaged = true;
                    Path root;
                    try (var entries = Files.list(workspace)) {
                        root = entries.collect(java.util.stream.Collectors.toList()).get(0);
                    }
                    try (var held = Files.walk(root)) {
                        held.filter(Files::isRegularFile).forEach(heldAtSabotage::add);
                    }
                    Files.move(root, workspace.resolve("moved-aside"));
                    Files.createDirectory(root);
                    Files.writeString(root.resolve("occupant"), "not the extractor's");
                    throw new IllegalStateException("the storage layer gave up");
                }
                int n = delegate.read(buffer, offset, Math.min(length, 64));
                served += Math.max(n, 0);
                return n;
            }
        };

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> BundleExtractor.extract(sabotage, upload.length, workspace, LIMITS));
        assertEquals("the storage layer gave up", ex.getMessage(),
                "the cleanup's own failure replaced the failure it was cleaning up after");
        // Two, not one: closing the gzip member fails on the same hostile source, and that
        // failure is attached as well. So the assertion names the cleanup's own exception
        // rather than any IOException, which the close could one day satisfy on its own.
        assertTrue(java.util.Arrays.stream(ex.getSuppressed())
                        .anyMatch(java.nio.file.DirectoryNotEmptyException.class::isInstance),
                "the cleanup failed and said nothing about it; suppressed: "
                        + java.util.Arrays.toString(ex.getSuppressed()));
        // And the walk did its part: the real root, moved or not, was emptied through its
        // descriptor. Only the final by-path step met the occupant. The first line is the
        // premise — a root that held nothing when it moved would pass the second vacuously.
        assertFalse(heldAtSabotage.isEmpty(), "nothing had been written when the root moved");
        try (var left = Files.list(workspace.resolve("moved-aside"))) {
            assertEquals(java.util.List.of(), left.toList(),
                    "the descriptor-relative walk did not empty the root it had open");
        }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] incompressible(int length) {
        byte[] bytes = new byte[length];
        new java.util.Random(0).nextBytes(bytes);
        return bytes;
    }

    private static BundleRule refusalFor(byte[] upload, Path workspace) {
        return assertThrows(BundleRejection.class,
                () -> BundleExtractor.extract(new ByteArrayInputStream(upload), upload.length,
                        workspace, LIMITS)).rule();
    }

    private static void assertEmpty(Path workspace) throws IOException {
        try (var entries = Files.list(workspace)) {
            assertEquals(java.util.List.of(), entries.toList(),
                    "a refusal left something behind; a later step may mistake a partial"
                            + " extraction for a validated one");
        }
    }

    private static byte[] gzip(byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(body);
        }
        return out.toByteArray();
    }

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
