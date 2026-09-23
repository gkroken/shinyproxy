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
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put("www/style.css", "body {}".getBytes(StandardCharsets.UTF_8));
        byte[] manifest = TarArchives.manifestFor(payload);
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", manifest)
                .directory("app")
                .file("app/app.R", payload.get("app.R"))
                .file("app/renv.lock", payload.get("renv.lock"))
                .directory("app/www")
                .file("app/www/style.css", payload.get("www/style.css"))
                .end());

        BundleExtractor.Extracted extracted =
                BundleExtractor.extract(new ByteArrayInputStream(upload), upload.length,
                        workspace, LIMITS);
        try (ExtractionRoot root = extracted.root()) {
            assertArrayEquals(manifest, extracted.manifest());
            assertEquals(payload.keySet(), extracted.validated().files().keySet());
            assertEquals(3, extracted.files());
            assertEquals(payload.values().stream().mapToLong(b -> b.length).sum(),
                    extracted.bytes());

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
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put("one.txt", "one".getBytes(StandardCharsets.UTF_8));
        payload.put("two.txt", "two".getBytes(StandardCharsets.UTF_8));
        byte[] traversal = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(payload))
                .file("app/one.txt", payload.get("one.txt"))
                .file("app/two.txt", payload.get("two.txt"))
                .file("app/../../escape.txt", "owned".getBytes(StandardCharsets.UTF_8))
                .end());
        assertEquals(BundleRule.PATH_TRAVERSAL, refusalFor(traversal, workspace));
        assertEmpty(workspace);

        byte[] noMarker = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(TarArchives.shinyPayload()))
                .unterminated());
        assertEquals(BundleRule.ARCHIVE_NO_END_MARKER, refusalFor(noMarker, workspace));
        assertEmpty(workspace);

        byte[] notGzip = "PK\u0003\u0004 not a gzip".getBytes(StandardCharsets.UTF_8);
        assertEquals(BundleRule.ARCHIVE_NOT_GZIP, refusalFor(notGzip, workspace));
        assertEmpty(workspace);

        Map<String, byte[]> once = TarArchives.shinyPayload();
        byte[] duplicate = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(once))
                .file("app/app.R", once.get("app.R"))
                .file("app/app.R", once.get("app.R"))
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
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put("one.txt", "one".getBytes(StandardCharsets.UTF_8));
        payload.put("two.txt", "two".getBytes(StandardCharsets.UTF_8));
        byte[] upload = gzip(TarArchives.bundle(payload).end());

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
        byte[] valid = TarArchives.manifestFor(TarArchives.shinyPayload());
        byte[] late = gzip(TarArchives.archive()
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .file("manifest.json", valid)
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
                .file("manifest.json", valid)
                .file("app/app.R", "library(shiny)\n".getBytes(StandardCharsets.UTF_8))
                .file("app/renv.lock", TarArchives.shinyPayload().get("renv.lock"))
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
        byte[] manifest = TarArchives.manifestFor(TarArchives.shinyPayload());
        ExtractionLimits small = ExtractionLimits.fromOverrides(
                Map.of("max_manifest_bytes", Long.toString(manifest.length)));

        byte[] declared = gzip(TarArchives.archive()
                .headerOnly("manifest.json", manifest.length + 1, '0')
                .end());
        CountingStream source = new CountingStream(declared);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> BundleExtractor.extract(source, declared.length, workspace, small));
        assertEquals(BundleRule.MANIFEST_TOO_LARGE, ex.rule());
        assertTrue(ex.getMessage().contains("before the bytes are read"), ex.getMessage());
        assertEmpty(workspace);

        // The accepted half, at exactly the bound.
        byte[] atLimit = gzip(TarArchives.bundle(TarArchives.shinyPayload()).end());
        try (ExtractionRoot root = BundleExtractor.extract(new ByteArrayInputStream(atLimit),
                atLimit.length, workspace, small).root()) {
            assertEquals(2, Files.list(root.path()).count());
        }
    }

    @Test
    public void anUploadWhoseLengthIsKnownIsRefusedBeforeItIsParsed(@TempDir Path workspace)
            throws Exception {
        byte[] upload = gzip(TarArchives.bundle(TarArchives.shinyPayload()).end());
        ExtractionLimits tiny = ExtractionLimits.fromOverrides(
                Map.of("max_compressed_bytes", Long.toString(upload.length - 1)));

        CountingStream source = new CountingStream(upload);
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_COMPRESSED, assertThrows(BundleRejection.class,
                () -> BundleExtractor.extract(source, upload.length, workspace, tiny)).rule());
        assertEquals(0, source.read, "the upload was read before its declared length was checked");
        assertEmpty(workspace);
    }

    @Test
    public void contentExactlyAtTheExpandedCapIsAcceptedAndOneByteMoreIsNot(
            @TempDir Path workspace) throws Exception {
        // bomb-expanded-at-limit, which the corpus found in af58f2e: max_expanded_bytes is
        // "total bytes written across all members", and GzipMember held the WHOLE tar
        // stream -- headers, padding, end marker -- to it, so content exactly at the cap
        // was refused. The manifest is member content too, and counts.
        long cap = 8192;
        ExtractionLimits limits = ExtractionLimits.fromOverrides(
                Map.of("max_expanded_bytes", Long.toString(cap)));
        // The manifest's length depends on fill.bin's declared size, which has four digits
        // anywhere near this cap, so sizing it against a four-digit placeholder settles it
        // in one pass. The assertion below is what says it did.
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        long others = payload.values().stream().mapToLong(b -> b.length).sum();
        payload.put("fill.bin", new byte[1000]);
        int fill = (int) (cap - TarArchives.manifestFor(payload).length - others);
        payload.put("fill.bin", new byte[fill]);
        assertEquals(cap, TarArchives.manifestFor(payload).length + others + fill,
                "the bundle is not at the cap, so it proves nothing about the cap");

        byte[] atCap = gzip(TarArchives.bundle(payload).end());
        try (ExtractionRoot root = BundleExtractor.extract(new ByteArrayInputStream(atCap),
                atCap.length, workspace, limits).root()) {
            assertEquals(fill, Files.size(root.path().resolve("fill.bin")));
        }

        payload.put("fill.bin", new byte[fill + 1]);
        byte[] overCap = gzip(TarArchives.bundle(payload).end());
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> BundleExtractor.extract(new ByteArrayInputStream(overCap),
                        overCap.length, workspace, limits));
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED, ex.rule());
        // Which layer refused it matters: the content bound is TarBlocks', and a stream
        // ceiling that fired first would mean it was still counting framing as content.
        assertTrue(ex.getMessage().contains("members extracted so far"),
                "refused by the wrong bound: " + ex.getMessage());
    }

    @Test
    public void anArchiveAtEveryTarBoundAtOnceFitsTheGzipCeilingExactly(@TempDir Path workspace)
            throws Exception {
        // The gzip layer's ceiling is DERIVED (ExtractionLimits.maxTarStreamBytes), and a
        // derivation that forgot one kind of framing would refuse a valid archive only when
        // that framing is at its maximum. So this one is at every maximum at once: content
        // exactly at the cap, the full entry count, every member's content one byte past a
        // block so each carries the most padding (511), and the longest zero tail the tar
        // layer accepts after the marker. It decompresses to exactly the ceiling.
        // Every member's content is one byte past a block. For the manifest that means JSON
        // padded with trailing whitespace, which JSON permits, to a length of 1 mod 512.
        Map<String, byte[]> payload = new java.util.LinkedHashMap<>();
        payload.put("app.R", new byte[] {'x'});                                     // 1
        payload.put("renv.lock", new byte[] {'{'});                                 // 1
        payload.put("rest.bin", new byte[10 * 512 + 1]);                            // 5121
        byte[] bare = TarArchives.manifestFor(payload);
        byte[] manifest = java.util.Arrays.copyOf(bare, bare.length
                + Math.floorMod(1 - bare.length, 512));
        java.util.Arrays.fill(manifest, bare.length, manifest.length, (byte) ' ');
        long entries = 1 + payload.size();
        long cap = manifest.length + payload.values().stream().mapToLong(b -> b.length).sum();
        ExtractionLimits limits = ExtractionLimits.fromOverrides(Map.of(
                "max_expanded_bytes", Long.toString(cap),
                "max_entries", Long.toString(entries)));

        TarArchives archive = TarArchives.archive().file("manifest.json", manifest);
        payload.forEach((path, bytes) -> archive.file("app/" + path, bytes));
        byte[] marked = archive.end();
        byte[] tar = java.util.Arrays.copyOf(marked, marked.length + (int) entries * 512);
        assertEquals(limits.maxTarStreamBytes(), tar.length,
                "the fixture is not at every bound, so it proves nothing about the ceiling");

        byte[] upload = gzip(tar);
        try (ExtractionRoot root = BundleExtractor.extract(new ByteArrayInputStream(upload),
                upload.length, workspace, limits).root()) {
            assertEquals(payload.get("rest.bin").length,
                    Files.size(root.path().resolve("rest.bin")));
        }
    }

    @Test
    public void aFileTheManifestDoesNotListIsRefusedBeforeItIsWritten(@TempDir Path workspace)
            throws Exception {
        // S11. The undeclared member's header claims 256 MiB, under the per-file limit, with
        // nothing behind it. If the extractor began writing, the walk would end as a
        // truncation; refused on the header, it ends as the inventory rule.
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        byte[] upload = gzip(TarArchives.bundle(payload)
                .headerOnly("app/extra.bin", 1L << 28, '0')
                .end());
        BundleRejection ex = assertThrows(BundleRejection.class, () -> extractQuietly(upload,
                workspace));
        assertEquals(BundleRule.INVENTORY_UNDECLARED_FILE, ex.rule(), ex.getMessage());
        assertTrue(ex.getMessage().contains("S11: 'extra.bin'"), ex.getMessage());
        assertEmpty(workspace);
    }

    @Test
    public void aSizeTheManifestDidNotDeclareIsRefusedBeforeItIsWritten(@TempDir Path workspace)
            throws Exception {
        // S10's size half, the same way: the header's claim is the member's size, and it
        // disagrees with the declaration before any content is read.
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(payload))
                .file("app/app.R", payload.get("app.R"))
                .headerOnly("app/renv.lock", 1L << 28, '0')
                .end());
        BundleRejection ex = assertThrows(BundleRejection.class, () -> extractQuietly(upload,
                workspace));
        assertEquals(BundleRule.INVENTORY_SIZE_MISMATCH, ex.rule(), ex.getMessage());
        assertEmpty(workspace);
    }

    @Test
    public void bytesThatAreNotTheDeclaredBytesAreRefused(@TempDir Path workspace)
            throws Exception {
        // S10's digest half: the same length, different content.
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        byte[] manifest = TarArchives.manifestFor(payload);
        byte[] swapped = payload.get("app.R").clone();
        swapped[0] ^= 0x20;
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", manifest)
                .file("app/app.R", swapped)
                .file("app/renv.lock", payload.get("renv.lock"))
                .end());
        BundleRejection ex = assertThrows(BundleRejection.class, () -> extractQuietly(upload,
                workspace));
        assertEquals(BundleRule.INVENTORY_HASH_MISMATCH, ex.rule(), ex.getMessage());
        assertTrue(ex.getMessage().contains(TarArchives.sha256(swapped)), ex.getMessage());
        assertEmpty(workspace);
    }

    @Test
    public void aDeclaredFileTheArchiveNeverDeliversIsRefused(@TempDir Path workspace)
            throws Exception {
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put("www/gone.txt", "promised".getBytes(StandardCharsets.UTF_8));
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(payload))
                .file("app/app.R", payload.get("app.R"))
                .file("app/renv.lock", payload.get("renv.lock"))
                .end());
        BundleRejection ex = assertThrows(BundleRejection.class, () -> extractQuietly(upload,
                workspace));
        assertEquals(BundleRule.INVENTORY_MISSING_FILE, ex.rule(), ex.getMessage());
        assertTrue(ex.getMessage().contains("www/gone.txt"), ex.getMessage());
        assertEmpty(workspace);
    }

    @Test
    public void executabilityComesFromTheManifestAndNeverFromTheHeader(@TempDir Path workspace)
            throws Exception {
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put("run.sh", "#!/bin/sh\n".getBytes(StandardCharsets.UTF_8));
        payload.put("data.csv", "a,b\n".getBytes(StandardCharsets.UTF_8));
        // The archive's own headers say the opposite of the manifest for both files: 0644 on
        // the one the manifest marks executable, and 0755 on the one it does not.
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(payload, "run.sh"))
                .file("app/app.R", payload.get("app.R"))
                .file("app/renv.lock", payload.get("renv.lock"))
                .file("app/run.sh", payload.get("run.sh"))
                .raw(TarArchives.header("app/data.csv", payload.get("data.csv").length, '0',
                        "0000755"), payload.get("data.csv"))
                .end());
        try (ExtractionRoot root = BundleExtractor.extract(new ByteArrayInputStream(upload),
                upload.length, workspace, LIMITS).root()) {
            assertEquals("rwx------", mode(root.path().resolve("run.sh")));
            assertEquals("rw-------", mode(root.path().resolve("data.csv")));
            assertEquals("rw-------", mode(root.path().resolve("app.R")));
        }
    }

    @Test
    public void aManifestThatCannotBeTrueIsRefusedBeforeAnyPayloadIsWritten(
            @TempDir Path workspace) throws Exception {
        // S5, through the extractor: the entrypoint names a directory with no app. The
        // payload after the manifest is a header claiming 256 MiB, so a refusal that came
        // after writing began would be a truncation instead.
        Map<String, byte[]> payload = new java.util.LinkedHashMap<>();
        payload.put("readme.md", "no app here".getBytes(StandardCharsets.UTF_8));
        payload.put("renv.lock", "{}".getBytes(StandardCharsets.UTF_8));
        byte[] upload = gzip(TarArchives.archive()
                .file("manifest.json", TarArchives.manifestFor(payload))
                .headerOnly("app/readme.md", 1L << 28, '0')
                .end());
        BundleRejection ex = assertThrows(BundleRejection.class, () -> extractQuietly(upload,
                workspace));
        assertEquals(BundleRule.MANIFEST_ENTRYPOINT_UNRESOLVED, ex.rule(), ex.getMessage());
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
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put("one.txt", "one".getBytes(StandardCharsets.UTF_8));
        // Incompressible, so the halfway point falls well inside it and app/one.txt is
        // already on disk when the sabotage runs. Without it nothing had been written yet,
        // and the walk's assertion below passed with the walk deleted.
        payload.put("tail.bin", incompressible(32 * 1024));
        byte[] upload = gzip(TarArchives.bundle(payload).end());
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

    private static BundleExtractor.Extracted extractQuietly(byte[] upload, Path workspace)
            throws IOException {
        return BundleExtractor.extract(new ByteArrayInputStream(upload), upload.length,
                workspace, LIMITS);
    }

    private static String mode(Path file) throws IOException {
        return java.nio.file.attribute.PosixFilePermissions.toString(
                Files.getPosixFilePermissions(file, java.nio.file.LinkOption.NOFOLLOW_LINKS));
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
