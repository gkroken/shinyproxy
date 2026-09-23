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
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Set;

/**
 * Where a validated member actually lands, and the only thing in this extractor that touches
 * a filesystem.
 *
 * <p><b>A lexical check is not containment.</b> {@code normalize().startsWith(root)} answers
 * a question about a string; what matters is which inode the kernel reaches, and between the
 * check and the open those can differ — a directory replaced by a symlink, a parent that was
 * a link all along. The contract says so and this class is built on it: every component is
 * opened relative to the descriptor of the directory above it, with links refused at each
 * step, so there is no window in which a name is resolved again.
 *
 * <p><b>Every create must be the first.</b> Files open with {@code CREATE_NEW} and
 * {@code NOFOLLOW_LINKS}; directories are created and must not already exist. The extraction
 * root is fresh and this extractor is the only writer, so anything already present at a path
 * it is about to create is something that arrived on its own, and the only safe response is
 * to stop. That also makes the duplicate rules of {@link MemberIndex} defence in depth rather
 * than the only guard.
 *
 * <p><b>Nothing is inherited from the archive.</b> Modes are set here, not carried: files are
 * created private and non-executable, directories private. Executability belongs to the
 * manifest, which is read later and is not a header's business — "library defaults must not
 * create files or preserve permissions behind the validator" is exactly the defect being
 * avoided, and the cheapest way to avoid it is never to pass the header's mode anywhere.
 *
 * <p><b>If the platform cannot do this, nothing is extracted.</b> {@link SecureDirectoryStream}
 * is the primitive the design depends on; where it is absent, a build is refused rather than
 * silently falling back to path-based operations that reopen every component by name.
 */
public final class ExtractionRoot implements AutoCloseable {

    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> PRIVATE_FILE =
            PosixFilePermissions.fromString("rw-------");

    private final Path root;
    private final SecureDirectoryStream<Path> rootStream;

    private ExtractionRoot(Path root, SecureDirectoryStream<Path> rootStream) {
        this.root = root;
        this.rootStream = rootStream;
    }

    /**
     * Creates a fresh private directory under {@code parent} and opens it safely.
     *
     * @throws BundleRejection if the platform cannot supply the primitives, or if the
     *                         directory that was created is not the one that opens
     */
    public static ExtractionRoot createUnder(Path parent, String name) throws IOException {
        FileAttribute<Set<PosixFilePermission>> mode =
                PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY);
        Path root = Files.createDirectory(parent.resolve(name), mode);

        // Opened NOFOLLOW so that a root replaced by a symlink between the create and the
        // open is refused rather than followed. The permissions are re-read from the open
        // directory rather than trusted from the create.
        DirectoryStream<Path> stream = Files.newDirectoryStream(root);
        requireDescriptorRelative(stream);
        if (Files.isSymbolicLink(root)) {
            stream.close();
            throw new BundleRejection(BundleRule.EXTRACTION_ROOT_UNSAFE,
                    "the extraction root is a symbolic link");
        }
        return new ExtractionRoot(root, (SecureDirectoryStream<Path>) stream);
    }

    /**
     * Refuses a platform whose directory streams are not descriptor-relative.
     *
     * <p>Package-private and taking the stream rather than reading it from the filesystem,
     * so that it can be exercised. On every platform this project runs on the check never
     * fires, which made it a guard nothing could test: removing it altogether survived as a
     * mutation because the condition it protects against cannot be produced here. Handed a
     * stream, it can be.
     */
    static void requireDescriptorRelative(DirectoryStream<Path> stream) throws IOException {
        if (!(stream instanceof SecureDirectoryStream)) {
            stream.close();
            throw new BundleRejection(BundleRule.PLATFORM_UNSAFE_FILESYSTEM,
                    "this platform does not provide descriptor-relative directory operations"
                            + " (" + stream.getClass().getName() + "), so every path component"
                            + " would be resolved again by name between the check and the"
                            + " open. Extraction is refused here rather than done unsafely");
        }
    }

    /** The directory itself, for a caller that needs to hand it on. */
    public Path path() {
        return root;
    }

    /**
     * Writes one member's content at {@code member}, creating the directories above it.
     *
     * @return the number of bytes written
     */
    public long writeFile(MemberPath member, InputStream content) throws IOException {
        List<String> segments = member.payloadSegments();
        Deque<SecureDirectoryStream<Path>> opened = new ArrayDeque<>();
        try {
            SecureDirectoryStream<Path> directory = descend(segments.subList(0, segments.size() - 1),
                    true, opened);
            Path name = Path.of(segments.get(segments.size() - 1));
            // CREATE_NEW refuses anything already at the name, symlink included, and
            // NOFOLLOW_LINKS says so explicitly rather than relying on that. Both, because
            // this is the one call that turns an archive into bytes on a disk.
            Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            try (SeekableByteChannel channel = directory.newByteChannel(name, options,
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE))) {
                return copy(content, channel);
            } catch (java.nio.file.FileAlreadyExistsException ex) {
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + member.memberPath() + "' already exists in an extraction root"
                                + " this extractor created and is the only writer for");
            }
        } finally {
            closeAll(opened);
        }
    }

    /** Creates the directory a member declares, and the directories above it. */
    public void createDirectory(MemberPath member) throws IOException {
        List<String> segments = member.payloadSegments();
        if (segments.isEmpty()) {
            return;                 // the payload root itself, which is this directory
        }
        Deque<SecureDirectoryStream<Path>> opened = new ArrayDeque<>();
        try {
            descend(segments, true, opened);
        } finally {
            closeAll(opened);
        }
    }

    /**
     * Opens each segment in turn, relative to the one above it, refusing links at every step.
     *
     * <p>{@code create} makes a missing directory rather than failing, which is what an
     * archive's implicit parents need. The creation is path-based — {@link SecureDirectoryStream}
     * has no relative mkdir — but it is immediately followed by a descriptor-relative
     * NOFOLLOW open, so a name that became a link in between is refused before anything is
     * written through it.
     */
    private SecureDirectoryStream<Path> descend(List<String> segments, boolean create,
                                                Deque<SecureDirectoryStream<Path>> opened)
            throws IOException {
        SecureDirectoryStream<Path> current = rootStream;
        Path materialised = root;
        for (String segment : segments) {
            Path name = Path.of(segment);
            materialised = materialised.resolve(segment);
            if (create && !Files.exists(materialised, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectory(materialised,
                        PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY));
            }
            SecureDirectoryStream<Path> next;
            try {
                next = current.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS);
            } catch (java.nio.file.NotDirectoryException | java.nio.file.NoSuchFileException ex) {
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + segment + "' is not a directory this extractor can descend"
                                + " into: " + ex.getClass().getSimpleName()
                                + ". A link or a substitution is the usual cause");
            } catch (IOException ex) {
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + segment + "' could not be opened as a directory: "
                                + ex.getMessage());
            }
            opened.push(next);
            current = next;
        }
        return current;
    }

    private static long copy(InputStream from, SeekableByteChannel to) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        long written = 0;
        int read;
        while ((read = from.read(buffer, 0, buffer.length)) >= 0) {
            java.nio.ByteBuffer slice = java.nio.ByteBuffer.wrap(buffer, 0, read);
            while (slice.hasRemaining()) {
                to.write(slice);
            }
            written += read;
        }
        return written;
    }

    private static void closeAll(Deque<SecureDirectoryStream<Path>> opened) throws IOException {
        IOException first = null;
        while (!opened.isEmpty()) {
            try {
                opened.pop().close();
            } catch (IOException ex) {
                first = first == null ? ex : first;
            }
        }
        if (first != null) {
            throw first;
        }
    }

    /**
     * Removes the whole tree without following anything out of it.
     *
     * <p>Called on every failure path. A recursive delete that follows a symlink deletes
     * someone else's files, so every step is descriptor-relative and no-follow — the same
     * primitives the writing uses, for the same reason.
     */
    public void deleteTree() throws IOException {
        deleteContents(rootStream);
        rootStream.close();
        Files.deleteIfExists(root);
    }

    private static void deleteContents(SecureDirectoryStream<Path> directory) throws IOException {
        for (Path entry : directory) {
            Path name = entry.getFileName();
            boolean isDirectory = directory.getFileAttributeView(name,
                    java.nio.file.attribute.BasicFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS).readAttributes().isDirectory();
            if (isDirectory) {
                try (SecureDirectoryStream<Path> child =
                             directory.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS)) {
                    deleteContents(child);
                }
                directory.deleteDirectory(name);
            } else {
                directory.deleteFile(name);
            }
        }
    }

    @Override
    public void close() throws IOException {
        rootStream.close();
    }
}
