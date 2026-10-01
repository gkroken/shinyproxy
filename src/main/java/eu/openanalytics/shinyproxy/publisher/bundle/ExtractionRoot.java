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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    private static final Set<PosixFilePermission> PRIVATE_EXECUTABLE =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FROZEN_DIRECTORY =
            PosixFilePermissions.fromString("r-x------");
    private static final Set<PosixFilePermission> FROZEN_FILE =
            PosixFilePermissions.fromString("r--------");
    private static final Set<PosixFilePermission> FROZEN_EXECUTABLE =
            PosixFilePermissions.fromString("r-x------");

    private final Path root;
    private final SecureDirectoryStream<Path> rootStream;
    private final DirectoryStream<Path> parentStream;
    private boolean frozen;
    /**
     * Every file and directory this root created, relative to it ({@code www},
     * {@code www/style.css}), with what it was when created. freeze() refuses any entry not
     * here (t5-e5e3071-F5) and any entry that is no longer what is recorded (c76cd70-F1).
     */
    private final Map<String, Created> created = new HashMap<>();

    /**
     * What an entry was when this root made it: its file key (device and inode), and for
     * a file the size and SHA-256 of the bytes written. A directory has no size or digest;
     * what is in it is checked entry by entry.
     */
    record Created(Object fileKey, long size, byte[] sha256) {
        static Created directory(Object fileKey) {
            return new Created(fileKey, -1, null);
        }
    }

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
     * directory — {@link SecureDirectoryStream} has no relative mkdir. Directories INSIDE the
     * root avoid that by being staged in the root and renamed into place through descriptors
     * ({@code createThrough}); the root itself has nothing above it to stage in but
     * {@code parent}, so this is narrowed rather than closed.
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
                String mode = PosixFilePermissions.toString(attributes.permissions());
                boolean othersHaveAccess = attributes.permissions().stream()
                        .anyMatch(bit -> !PRIVATE_DIRECTORY.contains(bit));
                // Two different problems, and they used to share one message that was false
                // for the second: a mode STRICTER than rwx------ does not let anyone else
                // write. It does stop the extractor itself, and the usual cause is a process
                // umask that clears an owner bit (noted in 191db7f's review).
                throw new BundleRejection(BundleRule.EXTRACTION_ROOT_UNSAFE, othersHaveAccess
                        ? "the extraction root is " + mode + " rather than private, so this"
                                + " extractor is not its only writer"
                        : "the extraction root is " + mode + ", lacking owner permissions this"
                                + " extractor needs; the process umask is the usual cause, and"
                                + " one that keeps the owner's rwx (077, for example) fixes it");
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
        return writeFile(member, content, false);
    }

    /**
     * The same, created executable by its owner when {@code executable}.
     *
     * <p>The flag is the manifest's, never the archive header's: "executability from the
     * manifest". It is applied at creation, so there is no moment at which the file exists
     * with a mode it should not have, and no second, path-resolving chmod.
     */
    public long writeFile(MemberPath member, InputStream content, boolean executable)
            throws IOException {
        requireNotFrozen();
        List<String> segments = requirePayload(member);
        Deque<SecureDirectoryStream<Path>> opened = new ArrayDeque<>();
        try {
            SecureDirectoryStream<Path> directory = descend(segments.subList(0, segments.size() - 1),
                    true, opened);
            return writeInto(directory, segments.get(segments.size() - 1),
                    String.join("/", segments), member.memberPath(), content, executable);
        } finally {
            closeAll(opened);
        }
    }

    /**
     * Creates file {@code fileName} in {@code directory}, writes {@code content} into it and
     * records what was written, for freeze() to compare.
     *
     * <p>Every call here is relative to the parent's descriptor, so something else changing
     * the tree surfaces as a NoSuchFileException or NotDirectoryException rather than as a
     * write somewhere else. Those are refusals, typed like {@link #descend}'s and freeze's:
     * reaching a caller as a raw IOException, they read as an infrastructure failure to
     * retry rather than as a tree this extractor no longer owns (gate finding
     * t5-f4f5f32-F3). Package-private so a test can hand it a parent that is already gone.
     */
    long writeInto(SecureDirectoryStream<Path> directory, String fileName, String relative,
                   String memberPath, InputStream content, boolean executable)
            throws IOException {
        Path name = Path.of(fileName);
        // CREATE_NEW refuses anything already at the name, symlink included, and
        // NOFOLLOW_LINKS says so explicitly rather than relying on that. Both, because
        // this is the one call that turns an archive into bytes on a disk.
        Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        MessageDigest digest = sha256();
        long written;
        try (SeekableByteChannel channel = directory.newByteChannel(name, options,
                PosixFilePermissions.asFileAttribute(
                        executable ? PRIVATE_EXECUTABLE : PRIVATE_FILE))) {
            written = copy(content, channel, digest);
        } catch (java.nio.file.FileAlreadyExistsException ex) {
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + BundleRejection.quote(memberPath) + "' already exists"
                            + " in an extraction root this extractor created and is the"
                            + " only writer for");
        } catch (java.nio.file.NoSuchFileException | java.nio.file.NotDirectoryException ex) {
            throw changedWhileWriting(relative, ex);
        }
        // The key is read after the write, by name through the parent's descriptor, so
        // a swap in between would record the swapped file's key. The digest is what
        // this object wrote, whatever is there now, and freeze() compares both.
        created.put(relative, new Created(keyOf(directory, name, relative), written,
                digest.digest()));
        return written;
    }

    /**
     * The file key of {@code name} in {@code directory}, read without following a link. An
     * entry that is gone or no longer under a directory is a tree changed under this
     * extractor, refused like the rest (t5-f4f5f32-F3); the post-write read here was one of
     * the two places the gate's race ended in a raw exception.
     */
    static Object keyOf(SecureDirectoryStream<Path> directory, Path name, String relative)
            throws IOException {
        try {
            return directory.getFileAttributeView(name, PosixFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS).readAttributes().fileKey();
        } catch (java.nio.file.NoSuchFileException | java.nio.file.NotDirectoryException ex) {
            throw changedWhileWriting(relative, ex);
        }
    }

    private static BundleRejection changedWhileWriting(String relative, Throwable cause) {
        return new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                "the extraction root changed while '" + BundleRejection.quote(relative)
                        + "' was being written (" + cause.getClass().getSimpleName()
                        + "); something other than this extractor is writing to it");
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
                    "'" + BundleRejection.quote(member.memberPath()) + "' is not a payload file. This directory is"
                            + " the payload root, and a bundle may carry its own"
                            + " 'app/manifest.json'; putting the archive's manifest here too"
                            + " would put two different members at one path");
        }
        return member.payloadSegments();
    }

    /** Creates the directory a member declares, and the directories above it. */
    public void createDirectory(MemberPath member) throws IOException {
        requireNotFrozen();
        if (member.role() != MemberPath.Role.PAYLOAD) {
            // Refused before the empty check, so that "this is the payload root" and "this
            // member is not mine" stop being the same silent return. writeFile refuses the
            // manifest and this used to accept it, which is the asymmetry that produced
            // d13212e-F1 with the sign reversed (finding 191db7f-F2).
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + BundleRejection.quote(member.memberPath()) + "' is not a payload member, so this"
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
     * archive's implicit parents need. {@link SecureDirectoryStream} has no relative mkdir, and
     * this used to create by path — {@code <root>/www/dN} — which resolves every component
     * again by name. A {@code www} swapped for a link after it was opened and before the create
     * took the create through the link: an empty directory outside the root, and the NOFOLLOW
     * open that followed refused only afterwards. The javadoc claimed nothing was written
     * through such a link; the mkdir itself was. See {@link #createThrough}.
     */
    private SecureDirectoryStream<Path> descend(List<String> segments, boolean create,
                                                Deque<SecureDirectoryStream<Path>> opened)
            throws IOException {
        SecureDirectoryStream<Path> current = rootStream;
        StringBuilder relative = new StringBuilder();
        for (String segment : segments) {
            Path name = Path.of(segment);
            relative.append(relative.length() == 0 ? "" : "/").append(segment);
            if (create && !presentIn(current, name, segment)) {
                createThrough(current, name, segment);
                created.put(relative.toString(), Created.directory(
                        keyOf(current, name, relative.toString())));
            }
            SecureDirectoryStream<Path> next;
            try {
                next = current.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS);
            } catch (java.nio.file.NotDirectoryException | java.nio.file.NoSuchFileException ex) {
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + BundleRejection.quote(segment) + "' is not a directory this extractor can descend"
                                + " into: " + ex.getClass().getSimpleName()
                                + ". A link or a substitution is the usual cause");
            } catch (IOException ex) {
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + BundleRejection.quote(segment) + "' could not be opened as a directory: "
                                + ex.getMessage());
            }
            opened.push(next);
            current = next;
        }
        return current;
    }

    private static boolean presentIn(SecureDirectoryStream<Path> directory, Path name,
                                     String segment) {
        try {
            directory.getFileAttributeView(name,
                    java.nio.file.attribute.BasicFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS).readAttributes();
            return true;
        } catch (java.nio.file.NoSuchFileException absent) {
            return false;
        } catch (IOException ex) {
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + BundleRejection.quote(segment) + "' could not be examined through its parent's descriptor: "
                            + ex.getClass().getSimpleName());
        }
    }

    /**
     * Makes directory {@code name} inside {@code parent} without resolving any name the
     * archive chose.
     *
     * <p>Staged, then renamed. The new directory is created by path directly in the root,
     * under a random name — a path made only of the workspace, which the platform owns, and
     * the root's own name, which {@link #createUnder} generated. That is the same trust
     * {@link #createUnder} already rests on, and no more. It is then moved into place with
     * {@link SecureDirectoryStream#move}, which is {@code renameat} between two directory
     * descriptors. Neither side is resolved by path, and a rename never follows a link at its
     * target. If {@code name} turned into something else in the meantime, the rename fails —
     * a directory cannot replace a link or a file — or replaces an empty directory inside
     * this root, and either way nothing leaves it.
     *
     * <p>Package-private so the window can be set up exactly — open a parent, swap it, then
     * create — rather than only raced; a race test catches a regression on some runs, this
     * on every one.
     */
    void createThrough(SecureDirectoryStream<Path> parent, Path name, String segment)
            throws IOException {
        Path staging = Path.of(".skald-mkdir-" + java.util.UUID.randomUUID());
        try {
            Files.createDirectory(root.resolve(staging),
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY));
        } catch (IOException ex) {
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "a directory for '" + BundleRejection.quote(segment) + "' could not be staged in the extraction"
                            + " root: " + ex.getClass().getSimpleName());
        }
        try {
            rootStream.move(staging, parent, name);
        } catch (IOException ex) {
            BundleRejection refused = new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + BundleRejection.quote(segment) + "' could not be put in place (" + ex.getClass()
                            .getSimpleName() + "); something other than this extractor is"
                            + " changing the tree");
            try {
                rootStream.deleteDirectory(staging);
            } catch (IOException cleanup) {
                refused.addSuppressed(cleanup);
            }
            throw refused;
        }
    }

    private static long copy(InputStream from, SeekableByteChannel to, MessageDigest digest)
            throws IOException {
        byte[] buffer = new byte[64 * 1024];
        long written = 0;
        int read;
        while ((read = from.read(buffer, 0, buffer.length)) >= 0) {
            digest.update(buffer, 0, read);
            java.nio.ByteBuffer slice = java.nio.ByteBuffer.wrap(buffer, 0, read);
            while (slice.hasRemaining()) {
                to.write(slice);
            }
            written += read;
        }
        return written;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is required of every JDK", ex);
        }
    }

    /**
     * The SHA-256 of a file as it is now, read through its parent's descriptor with links
     * refused: the bytes freeze() is about to call validated.
     */
    private static byte[] digestOf(SecureDirectoryStream<Path> directory, Path name)
            throws IOException {
        MessageDigest digest = sha256();
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(64 * 1024);
        try (SeekableByteChannel channel = directory.newByteChannel(name,
                Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            while (channel.read(buffer) >= 0) {
                buffer.flip();
                digest.update(buffer);
                buffer.clear();
            }
        }
        return digest.digest();
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
        // A frozen tree's directories are read-only, and removing an entry needs write on
        // its directory; so each directory is made writable again, through its descriptor,
        // just before its contents go. Harmless for a tree that was never frozen.
        rootStream.getFileAttributeView(PosixFileAttributeView.class)
                .setPermissions(PRIVATE_DIRECTORY);
        try (SecureDirectoryStream<Path> top = reopenRoot()) {
            deleteContents(top);
        }
        close();
        Files.deleteIfExists(root);
    }

    /**
     * Makes the validated tree read-only: files r-------- (r-x------ where the manifest made
     * them executable), directories r-x------, the root included. After this, writeFile and
     * createDirectory refuse.
     *
     * <p>"Freeze the validated tree before handing it to a worker" is the extraction
     * contract's wording. What this buys, stated rather than implied: nothing in the platform
     * can change validated content by accident, a bug included, and anything that tries
     * fails loudly instead. What it does not buy: a process running as the platform's own
     * user can change the modes back, because ownership is not a boundary against the owner.
     * The boundary between this tree and untrusted build code is elsewhere: the worker is
     * sent the context as a stream and never sees this directory (the launcher contract,
     * T3).
     *
     * <p><b>It freezes only what this root wrote, as it wrote it.</b> Every entry the walk
     * meets must be one this object created, and still the same entry: the same file key
     * (a file renamed over it has another), and for a file the same size and the same
     * SHA-256 as the bytes written, re-read through the descriptor after the file is made
     * read-only (an in-place write whose mtime was put back still changes the digest).
     * Anything else is refused, and the extractor then deletes the tree like any refused
     * one. It used to freeze whatever it found: the gate's same-uid "foreign writer" put 752
     * files into a root during extraction, and the bundle was accepted with 734 of them
     * frozen beside the payload as if validated (t5-e5e3071-F5); a check by name alone still
     * accepted a validated file replaced or appended to (c76cd70-F1). A second writer breaks
     * the contract's precondition, so this is defence in depth. The cost is one more read of
     * the tree, measured in the commit that added it.
     *
     * <p><b>What it does not cover once it returns.</b> The checks describe the tree at the
     * moment of the freeze. A same-uid process that made a hard link to a validated file
     * from outside the root, or held a writable descriptor opened before the chmod, can
     * still change the frozen bytes afterwards: the same inode, so nothing here differs, and
     * a mode never stopped its owner. A link count of 1 would flag the first, but the
     * descriptor-relative view this class uses does not expose it, and a path-based lookup
     * is what this class exists to avoid. Both are covered by the contract's "no other
     * writer" precondition, not by freeze() (e425718 review N1).
     *
     * <p>Every change goes through a descriptor, with links refused, like every other
     * operation in this class. The walk opens a fresh listing of the root rather than
     * iterating {@code rootStream}, because a directory stream can be iterated once and
     * deleteTree needs it afterwards.
     */
    public void freeze() throws IOException {
        if (frozen) {
            return;
        }
        frozen = true;     // first: no write may begin while the walk runs
        Set<String> visited = new java.util.HashSet<>();
        try (SecureDirectoryStream<Path> top = reopenRoot()) {
            freezeContents(top, "", created, visited);
        }
        // And nothing it wrote may be gone: a validated file deleted or moved out is a tree
        // that is not the one validated either.
        List<String> missing = created.keySet().stream()
                .filter(entry -> !visited.contains(entry)).sorted().toList();
        if (!missing.isEmpty()) {
            requireSame(missing.get(0), false, "removed");
        }
        rootStream.getFileAttributeView(PosixFileAttributeView.class)
                .setPermissions(FROZEN_DIRECTORY);
    }

    /** Whether {@link #freeze} has run. */
    public boolean isFrozen() {
        return frozen;
    }

    private static void freezeContents(SecureDirectoryStream<Path> directory, String prefix,
                                       Map<String, Created> created, Set<String> visited)
            throws IOException {
        try {
            for (Path entry : directory) {
                Path name = entry.getFileName();
                freezeEntry(directory, name,
                        prefix.isEmpty() ? name.toString() : prefix + "/" + name, created,
                        visited);
            }
        } catch (java.nio.file.DirectoryIteratorException ex) {
            throw changedUnderUs("(listing)", ex.getCause());
        }
    }

    /**
     * One entry, with any filesystem error typed.
     *
     * <p>The walk refuses links and reads through descriptors, so a tree changed underneath
     * it cannot take anything outside the root. But the change surfaced as a raw IOException:
     * a symlink swapped in gives ELOOP (the no-follow open refusing it), an entry renamed away
     * between the listing and the access gives NoSuchFile. The corpus's rename race found 7
     * such crashes in 273 runs on this commit's first version, where every run had been clean
     * before freezing existed. Under tampering, refusing is correct and crashing is not; the
     * refusal then deletes the tree like any other.
     *
     * <p>Package-private so the conversion can be tested exactly (an entry that is gone by the
     * time it is read), where from outside it can only be raced.
     */
    static void freezeEntry(SecureDirectoryStream<Path> directory, Path name, String relative,
                            Map<String, Created> created, Set<String> visited) {
        try {
            PosixFileAttributeView view = directory.getFileAttributeView(name,
                    PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            PosixFileAttributes attributes = view.readAttributes();
            // The type first, so a link or a device keeps its own, more specific refusal
            // below; then whether this root made it and whether it still is what was made,
            // before anything about it changes.
            Created made = created.get(relative);
            if ((attributes.isDirectory() || attributes.isRegularFile()) && made == null) {
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + BundleRejection.quote(relative) + "' is in the extraction root,"
                                + " and this extractor did not write it; something else is"
                                + " writing to the root, so the tree is not the one that was"
                                + " validated");
            }
            if (made != null) {
                visited.add(relative);
            }
            if (attributes.isDirectory()) {
                requireSame(relative, made.fileKey().equals(attributes.fileKey())
                        && made.sha256() == null, "replaced");
                try (SecureDirectoryStream<Path> child =
                             directory.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS)) {
                    freezeContents(child, relative, created, visited);
                }
                view.setPermissions(FROZEN_DIRECTORY);
            } else if (attributes.isRegularFile()) {
                requireSame(relative, made.sha256() != null, "replaced");
                requireSame(relative, attributes.size() == made.size(), "resized");
                view.setPermissions(attributes.permissions()
                        .contains(PosixFilePermission.OWNER_EXECUTE)
                        ? FROZEN_EXECUTABLE : FROZEN_FILE);
                // Read-only first, then the digest, then the key: read last, so a file
                // swapped in before the walk reached it and one swapped in during the read
                // are both seen, by the one comparison.
                requireSame(relative, MessageDigest.isEqual(made.sha256(),
                        digestOf(directory, name)), "rewritten");
                requireSame(relative, made.fileKey().equals(view.readAttributes().fileKey()),
                        "replaced");
            } else {
                // This class creates nothing else, so something else put it there. Refused
                // rather than frozen around: the tree is not the one that was validated.
                throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                        "'" + BundleRejection.quote(name.toString()) + "' in the extraction root is neither a file nor a"
                                + " directory; something other than this extractor wrote it");
            }
        } catch (IOException ex) {
            throw changedUnderUs(name.toString(), ex);
        }
    }

    private static void requireSame(String relative, boolean same, String how) {
        if (!same) {
            throw new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                    "'" + BundleRejection.quote(relative) + "' was " + how + " after this"
                            + " extractor wrote it; something else is writing to the root, so"
                            + " the tree is not the one that was validated");
        }
    }

    private static BundleRejection changedUnderUs(String name, Throwable cause) {
        return new BundleRejection(BundleRule.WRITE_PATH_NOT_AS_EXPECTED,
                "the extraction root changed while it was being frozen, at '" + BundleRejection.quote(name.toString()) + "' ("
                        + (cause == null ? "unknown" : cause.getClass().getSimpleName())
                        + "); something other than this extractor is writing to it");
    }

    private void requireNotFrozen() {
        if (frozen) {
            throw new IllegalStateException("the extraction root is frozen: it was validated"
                    + " as it stands, and nothing may be written to it any more");
        }
    }

    /** A fresh, descriptor-relative listing of the root, which can be iterated again. */
    private SecureDirectoryStream<Path> reopenRoot() throws IOException {
        return rootStream.newDirectoryStream(Path.of("."), LinkOption.NOFOLLOW_LINKS);
    }

    private static void deleteContents(SecureDirectoryStream<Path> directory) throws IOException {
        for (Path entry : directory) {
            Path name = entry.getFileName();
            boolean isDirectory = directory.getFileAttributeView(name,
                    java.nio.file.attribute.BasicFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS).readAttributes().isDirectory();
            if (isDirectory) {
                directory.getFileAttributeView(name, PosixFileAttributeView.class,
                        LinkOption.NOFOLLOW_LINKS).setPermissions(PRIVATE_DIRECTORY);
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
