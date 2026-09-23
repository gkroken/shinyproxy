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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The write path, against a real filesystem and real symlinks.
 *
 * <p>Everything here is about the gap between a name and an inode. The corpus's link group
 * describes it from the archive's side — symlink file, symlink directory followed by a
 * child, chained links, a pre-existing symlinked parent, a rename race — and this is the
 * other side: what happens when the thing at a path is not what the extractor last saw.
 *
 * <p>Each case that must be refused has a sentinel OUTSIDE the root, asserted unchanged
 * afterwards. A rejection with the sentinel modified would mean the write happened and the
 * refusal came too late, which is the distinction a decision alone cannot make.
 */
public class ExtractionRootTest {

    private static MemberPath member(String name) {
        return MemberPath.parse(name.getBytes(StandardCharsets.UTF_8), name.endsWith("/"),
                ExtractionLimits.defaults());
    }

    @Test
    public void thePlatformProvidesWhatThisDesignNeeds(@TempDir Path tmp) throws Exception {
        // Not a test of the code: a test of the assumption under it. If this fails, nothing
        // else in this file means anything, and the extractor refuses to run at all.
        Path dir = Files.createDirectory(tmp.resolve("probe"));
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            assertTrue(stream instanceof SecureDirectoryStream,
                    "descriptor-relative directory operations are unavailable here ("
                            + stream.getClass().getName() + "), so the extractor would refuse"
                            + " to run rather than fall back to resolving names twice");
        }
    }

    @Test
    public void theRootIsFreshAndPrivate(@TempDir Path tmp) throws Exception {
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            assertEquals("rwx------",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(root.path())));
            assertEquals(0, Files.list(root.path()).count());
        }
        // Creating it twice is refused: this extractor is the only writer, so a root that is
        // already there is not one it made.
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "twice")) {
            assertThrows(java.nio.file.FileAlreadyExistsException.class,
                    () -> ExtractionRoot.createUnder(tmp, "twice"));
        }
    }

    @Test
    public void anOrdinaryMemberLandsWhereItShould(@TempDir Path tmp) throws Exception {
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            long written = root.writeFile(member("app/www/style.css"),
                    new ByteArrayInputStream("body {}".getBytes(StandardCharsets.UTF_8)));

            Path file = root.path().resolve("www/style.css");
            assertEquals(7, written);
            assertEquals("body {}", Files.readString(file));
            assertEquals("rw-------",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(file)),
                    "modes are set here, never carried from the archive");
            assertEquals("rwx------", PosixFilePermissions.toString(
                    Files.getPosixFilePermissions(root.path().resolve("www"))));
        }
    }

    @Test
    public void aSymlinkedParentIsRefusedAndTheTargetIsUntouched(@TempDir Path tmp)
            throws Exception {
        Path outside = Files.createDirectory(tmp.resolve("outside"));
        Path sentinel = Files.writeString(outside.resolve("sentinel.txt"), "untouched");

        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            // The pre-existing symlinked parent from the corpus's link group, arriving here
            // as a component that is a link rather than the directory it is named as.
            Files.createSymbolicLink(root.path().resolve("www"), outside);

            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> root.writeFile(member("app/www/planted.txt"),
                            new ByteArrayInputStream("owned".getBytes(StandardCharsets.UTF_8))));
            assertEquals(BundleRule.WRITE_PATH_NOT_AS_EXPECTED, ex.rule());
        }

        assertEquals("untouched", Files.readString(sentinel));
        assertFalse(Files.exists(outside.resolve("planted.txt")),
                "the write went through the link; a refusal after the fact is not a refusal");
        assertEquals(1, Files.list(outside).count());
    }

    @Test
    public void aSymlinkAtTheFinalNameIsRefusedAndTheTargetIsUntouched(@TempDir Path tmp)
            throws Exception {
        Path outside = Files.createDirectory(tmp.resolve("outside"));
        Path sentinel = Files.writeString(outside.resolve("target.txt"), "untouched");

        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            Files.createSymbolicLink(root.path().resolve("app.R"), sentinel);

            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> root.writeFile(member("app/app.R"),
                            new ByteArrayInputStream("owned".getBytes(StandardCharsets.UTF_8))));
            assertEquals(BundleRule.WRITE_PATH_NOT_AS_EXPECTED, ex.rule());
        }

        assertEquals("untouched", Files.readString(sentinel));
    }

    @Test
    public void aComponentThatIsAFileIsNotADirectoryToDescendInto(@TempDir Path tmp)
            throws Exception {
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            root.writeFile(member("app/www"),
                    new ByteArrayInputStream("a file".getBytes(StandardCharsets.UTF_8)));

            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> root.writeFile(member("app/www/inside.txt"),
                            new ByteArrayInputStream("x".getBytes(StandardCharsets.UTF_8))));
            assertEquals(BundleRule.WRITE_PATH_NOT_AS_EXPECTED, ex.rule());
            assertEquals("a file", Files.readString(root.path().resolve("www")),
                    "the file that was in the way was overwritten");
        }
    }

    @Test
    public void writingTheSamePathTwiceIsRefused(@TempDir Path tmp) throws Exception {
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            root.writeFile(member("app/app.R"),
                    new ByteArrayInputStream("first".getBytes(StandardCharsets.UTF_8)));

            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> root.writeFile(member("app/app.R"),
                            new ByteArrayInputStream("second".getBytes(StandardCharsets.UTF_8))));
            assertEquals(BundleRule.WRITE_PATH_NOT_AS_EXPECTED, ex.rule());
            assertEquals("first", Files.readString(root.path().resolve("app.R")),
                    "last-entry-wins reached the disk");
        }
    }

    @Test
    public void directoriesDeclaredByTheArchiveAreCreatedPrivate(@TempDir Path tmp)
            throws Exception {
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            root.createDirectory(member("app/R/helpers/"));
            Path made = root.path().resolve("R/helpers");
            assertTrue(Files.isDirectory(made, LinkOption.NOFOLLOW_LINKS));
            assertEquals("rwx------",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(made)));

            // The payload root's own header names this directory, and is not an error.
            root.createDirectory(member("app/"));
        }
    }

    @Test
    public void deletingTheTreeDoesNotFollowAnythingOutOfIt(@TempDir Path tmp) throws Exception {
        Path outside = Files.createDirectory(tmp.resolve("outside"));
        Path sentinel = Files.writeString(outside.resolve("keep.txt"), "untouched");

        ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work");
        root.writeFile(member("app/www/style.css"),
                new ByteArrayInputStream("body {}".getBytes(StandardCharsets.UTF_8)));
        Files.createSymbolicLink(root.path().resolve("escape"), outside);

        root.deleteTree();

        assertFalse(Files.exists(root.path(), LinkOption.NOFOLLOW_LINKS),
                "the extraction root survived a delete that is called on every failure path");
        assertTrue(Files.exists(sentinel), "the delete followed a link and removed"
                + " someone else's files");
        assertEquals("untouched", Files.readString(sentinel));
        assertTrue(Files.isDirectory(outside));
    }

    @Test
    public void theManifestIsNotAPayloadFileAndIsRefusedHere(@TempDir Path tmp) throws Exception {
        // d13212e-F1. manifest.json is a MANIFEST-role member with no payload segments, and
        // writeFile reached subList(0, -1) on it: an untyped IllegalArgumentException out of
        // the only class that writes to a disk, on the first member of every bundle.
        try (ExtractionRoot root = ExtractionRoot.createUnder(tmp, "work")) {
            MemberPath manifest = member("manifest.json");
            assertEquals(MemberPath.Role.MANIFEST, manifest.role());
            assertTrue(manifest.payloadSegments().isEmpty());

            BundleRejection ex = assertThrows(BundleRejection.class,
                    () -> root.writeFile(manifest,
                            new ByteArrayInputStream("{}".getBytes(StandardCharsets.UTF_8))));
            assertEquals(BundleRule.WRITE_PATH_NOT_AS_EXPECTED, ex.rule());

            // And the sibling method agrees. It used to return in silence, which is the same
            // asymmetry with the sign reversed: "this is the payload root" and "this member
            // is not mine" were one return (191db7f-F2).
            assertEquals(BundleRule.WRITE_PATH_NOT_AS_EXPECTED, assertThrows(
                    BundleRejection.class, () -> root.createDirectory(manifest)).rule());
            // The payload root's own header is still a legitimate no-op.
            root.createDirectory(member("app/"));

            // The reason it is refused rather than written at the root: a bundle may carry
            // its own app/manifest.json, which lands exactly there.
            root.writeFile(member("app/manifest.json"),
                    new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8)));
            assertEquals("payload", Files.readString(root.path().resolve("manifest.json")));
        }
    }

    @Test
    public void theRootsNameIsNotTheCallersToChoose(@TempDir Path tmp) throws Exception {
        // The residual window between the create and the identity read is closed in practice
        // by the parent being private and the name being unpredictable (191db7f-F1). The
        // second is no longer an obligation a caller can fail: the public entry point
        // generates the name.
        try (ExtractionRoot first = ExtractionRoot.createUnder(tmp);
             ExtractionRoot second = ExtractionRoot.createUnder(tmp)) {
            assertNotEquals(first.path().getFileName(), second.path().getFileName(),
                    "two roots under one parent took the same name, so it is predictable");
            assertTrue(first.path().getFileName().toString().length() > 16,
                    "the generated name is short enough to guess: "
                            + first.path().getFileName());
            assertEquals(tmp, first.path().getParent());
        }
    }

    @Test
    public void adoptingARootChecksWhatTheDescriptorPointsAt(@TempDir Path tmp) throws Exception {
        // d13212e-F2. From outside, each of these needs a swap between the create and the
        // open, which no deterministic test can arrange; adopt() takes its expectations as
        // arguments so they are three ordinary cases.
        Path real = Files.createDirectory(tmp.resolve("real"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path other = Files.createDirectory(tmp.resolve("other"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path loose = Files.createDirectory(tmp.resolve("loose"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
        Files.createSymbolicLink(tmp.resolve("link"), real);
        Object realKey = Files.readAttributes(real, java.nio.file.attribute.BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).fileKey();
        Object looseKey = Files.readAttributes(loose, java.nio.file.attribute.BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).fileKey();

        // A symbolic link where the root should be: refused at the open, not by a later
        // check of the same name.
        assertEquals(BundleRule.EXTRACTION_ROOT_UNSAFE,
                assertThrows(BundleRejection.class,
                        () -> ExtractionRoot.adopt(parentOf(tmp), real, "link", realKey)).rule());

        // A different directory in its place: the open succeeds and the identity does not.
        BundleRejection swapped = assertThrows(BundleRejection.class,
                () -> ExtractionRoot.adopt(parentOf(tmp), other, "other", realKey));
        assertEquals(BundleRule.EXTRACTION_ROOT_UNSAFE, swapped.rule());
        assertTrue(swapped.getMessage().contains("not the one it created"), swapped.getMessage());

        // The right directory, not private: this extractor is not its only writer.
        BundleRejection open = assertThrows(BundleRejection.class,
                () -> ExtractionRoot.adopt(parentOf(tmp), loose, "loose", looseKey));
        assertEquals(BundleRule.EXTRACTION_ROOT_UNSAFE, open.rule());
        assertTrue(open.getMessage().contains("rather than private"), open.getMessage());

        // The control: the directory that was created, private, opens and is adopted.
        try (ExtractionRoot adopted = ExtractionRoot.adopt(parentOf(tmp), real, "real", realKey)) {
            assertEquals(real, adopted.path());
        }
    }

    private static SecureDirectoryStream<Path> parentOf(Path directory) throws IOException {
        return (SecureDirectoryStream<Path>) Files.newDirectoryStream(directory);
    }

    @Test
    public void aPlatformWithoutDescriptorRelativeStreamsIsRefused(@TempDir Path tmp)
            throws Exception {
        // The guard that cannot fire here. Removing it altogether survived as a mutation,
        // because this platform always supplies a SecureDirectoryStream — so the check was
        // correct, load-bearing on some other platform, and proven by nothing. Handed a
        // stream that is not one, it can be.
        DirectoryStream<Path> plain = new DirectoryStream<>() {
            @Override
            public java.util.Iterator<Path> iterator() {
                return java.util.Collections.emptyIterator();
            }

            @Override
            public void close() {
            }
        };
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> ExtractionRoot.requireDescriptorRelative(plain));
        assertEquals(BundleRule.PLATFORM_UNSAFE_FILESYSTEM, ex.rule());
        assertTrue(ex.getMessage().contains("refused here rather than done unsafely"),
                ex.getMessage());

        // And the control: a real one passes, so the rule is about the capability rather
        // than about refusing whatever it is handed.
        Path dir = Files.createDirectory(tmp.resolve("real"));
        try (DirectoryStream<Path> secure = Files.newDirectoryStream(dir)) {
            ExtractionRoot.requireDescriptorRelative(secure);
        }
    }

    @Test
    public void aRootThatIsNotADirectoryIsRefused(@TempDir Path tmp) throws Exception {
        Files.writeString(tmp.resolve("occupied"), "in the way");
        assertThrows(java.nio.file.FileAlreadyExistsException.class,
                () -> ExtractionRoot.createUnder(tmp, "occupied"));
    }
}
