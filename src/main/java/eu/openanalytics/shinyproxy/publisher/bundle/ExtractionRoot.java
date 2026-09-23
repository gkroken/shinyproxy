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
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
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
    private final DirectoryStream<Path> parentStream;

    private ExtractionRoot(Path root, SecureDirectoryStream<Path> rootStream,
                           DirectoryStream<Path> parentStream) {
        this.root = root;
        this.rootStream = rootStream;
        // Held open for the object's lifetime rather than closed after the adoption: the
        // documented relationship between a SecureDirectoryStream and one opened through it
        // does not promise the child survives the parent, and assuming it does would be an
        // assumption in the one place this class exists to remove them from.
        this.parentStream = parentStream;
    }

    /**
     * Creates a fresh private directory under {@code parent} and adopts it safely.
     *
     * <p>The sequence used to be create by name, open by name following links, then check by
     * name — three resolutions of one name, in the single call that establishes what "inside
     * the root" means, using the pattern this class's own javadoc calls insufficient. An
     * actor able to write in {@code parent} could replace the new directory with a symlink
     * between the create and the open and restore a real directory before the check, leaving
     * this object holding a descriptor on a directory of their choosing — after which every
     * descriptor-relative operation below is faithfully relative to the wrong root
     * (finding d13212e-F2).
     *
     * <p>Now the directory is created, its identity recorded, and then opened THROUGH the
     * parent's descriptor with links refused — and the open directory is required to be the
     * same inode that was created, with the permissions it was created with, read from that
     * descriptor. A swap AFTER the identity is recorded is refused whether or not it is
     * restored, because the question asked is what the descriptor points at.
     *
     * <p><b>The residual, stated rather than implied</b> (finding 191db7f-F1). The identity
     * itself is captured by resolving the name a second time, in the two calls between the
     * create and the {@code readAttributes}. An actor who can write in {@code parent} and who
     * replaces the new directory within that window has their inode recorded as the expected
     * one, and the adoption then succeeds on it. Java offers no atomic create-and-open for a
     * directory — {@link SecureDirectoryStream} has no relative mkdir, which {@code descend}
     * notes for the same reason — so this is narrowed rather than closed.
     *
     * <p>What closes it in practice is that {@code parent} is a private directory and the
     * name is unpredictable. The second is no longer the caller's to get right: the name is
     * generated here. The first is the caller's, and is the one obligation this class states
     * and cannot check.
     */
    public static ExtractionRoot createUnder(Path parent) throws IOException {
        return createUnder(parent, "extract-" + java.util.UUID.randomUUID());
    }

    /**
     * The same, with the name supplied.
     *
     * <p>Package-private: a caller that chooses the name owns the unpredictability the
     * paragraph above rests on, and there is no reason for anything outside this package to
     * take that on. Tests use it to get a name they can assert against.
     */
    static ExtractionRoot createUnder(Path parent, String name) throws IOException {
        FileAttribute<Set<PosixFilePermission>> mode =
                PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY);
        Path created = Files.createDirectory(parent.resolve(name), mode);
        Object createdKey = Files.readAttributes(created, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).fileKey();

        DirectoryStream<Path> parentStream = Files.newDirectoryStream(parent);
        boolean adopted = false;
        try {
            requireDescriptorRelative(parentStream);
            ExtractionRoot root = adopt((SecureDirectoryStream<Path>) parentStream, created,
                    name, createdKey);
            adopted = true;
            return root;
        } finally {
            if (!adopted) {
                parentStream.close();
            }
        }
    }

    /**
     * Opens {@code name} under an already-open parent and checks it is the directory that was
     * created.
     *
     * <p>Package-private and taking its expectations as arguments so the three refusals can
     * be exercised. From outside, each of them needs a swap between the create and the open,
     * which no deterministic test can arrange; from here they are three ordinary cases.
     */
    static ExtractionRoot adopt(SecureDirectoryStream<Path> parentStream, Path root,
                                String name, Object expectedKey) throws IOException {
        SecureDirectoryStream<Path> rootStream;
        try {
            rootStream = parentStream.newDirectoryStream(Path.of(name),
                    LinkOption.NOFOLLOW_LINKS);
        } catch (IOException ex) {
            parentStream.close();
            throw new BundleRejection(BundleRule.EXTRACTION_ROOT_UNSAFE,
                    "the extraction root could not be opened as a directory through its"
                            + " parent's descriptor (" + ex.getClass().getSimpleName()
                            + "); a symbolic link in its place is the usual cause");
        }
        try {
            PosixFileAttributes attributes = rootStream.getFileAttributeView(
                    PosixFileAttributeView.class).readAttributes();
            if (!attributes.fileKey().equals(expectedKey)) {
                throw new BundleRejection(BundleRule.EXTRACTION_ROOT_UNSAFE,
                        "the directory this extractor opened is not the one it created;"
                                + " something replaced it between the two");
            }
            if (!attributes.permissions().equals(PRIVATE_DIRECTORY)) {
                throw new BundleRejection(BundleRule.EXTRACTION_ROOT_UNSAFE,
                        "the extraction root is " + PosixFilePermissions.toString(
                                attributes.permissions()) + " rather than private, so this"
                                + " extractor is not its only writer");
            }
        } catch (RuntimeException | IOException ex) {
            rootStream.close();
            parentStream.close();
            throw ex;
        }
        return new ExtractionRoot(root, rootStream, parentStream);
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
        List<String> segments = requirePayload(member);
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

    /**
     * The members this directory holds, which is the payload and nothing else.
     *
     * <p>This directory IS the payload root: {@code app/www/x} lands at {@code <root>/www/x},
     * because the {@code app/} prefix is the platform's rather than the publisher's. The
     * manifest is not part of that namespace and must not be written into it — a bundle may
     * legitimately contain {@code app/manifest.json}, which lands at {@code <root>/manifest.json}
     * and would collide with the archive-root manifest put in the same place. MemberIndex
     * does not catch that pair, because {@code manifest.json} and {@code app/manifest.json}
     * are two different members; only keeping the manifest out of this directory does.
     *
     * <p>So a non-payload member is refused here and the caller routes it elsewhere. Before
     * this, {@code writeFile} reached {@code subList(0, -1)} on the manifest and threw an
     * untyped IllegalArgumentException out of the middle of the only class that writes to a
     * disk — on the first member of every well-formed bundle (finding d13212e-F1).
     */
    private static List<String> requirePayload(MemberPath member) {
        if (member.role() != MemberPath.Role.PAYLOAD || member.payloadSegments().isEmpty()) {
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + member.memberPath() + "' is not a payload file. This directory is"
                            + " the payload root, and a bundle may carry its own"
                            + " 'app/manifest.json'; putting the archive's manifest here too"
                            + " would put two different members at one path");
        }
        return member.payloadSegments();
    }

    /** Creates the directory a member declares, and the directories above it. */
    public void createDirectory(MemberPath member) throws IOException {
        if (member.role() != MemberPath.Role.PAYLOAD) {
            // Refused before the empty check, so that "this is the payload root" and "this
            // member is not mine" stop being the same silent return. writeFile refuses the
            // manifest and this used to accept it, which is the asymmetry that produced
            // d13212e-F1 with the sign reversed (finding 191db7f-F2).
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + member.memberPath() + "' is not a payload member, so this"
                            + " directory has no place to make for it");
        }
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
        close();
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
        try {
            rootStream.close();
        } finally {
            parentStream.close();
        }
    }
}
