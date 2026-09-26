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

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

/**
 * Coverage-guided fuzzing of the bundle parser, which Skald writes by hand and so owns.
 *
 * <p>The corpus and the unit tests hold the cases someone thought of; this is for the rest.
 * Every target states one invariant, and the one they share is the extraction contract's
 * strongest: <b>a hostile input is refused, never mishandled</b>. The only thing allowed out
 * of any layer is a {@link BundleRejection}; anything else — an IllegalArgumentException from
 * an unguarded branch, an ArithmeticException, an OutOfMemoryError from a bound that did not
 * hold, a hang past the per-input timeout — is a finding.
 *
 * <p><b>Two modes.</b> Plain {@code make test} runs each target once per checked-in seed, and
 * per any crash reproducer Jazzer has saved, as ordinary regression tests: seconds, no
 * instrumentation. {@code make fuzz} runs each target under libFuzzer with coverage
 * guidance; Jazzer allows one target per JVM, so it goes through them one at a time.
 *
 * <p>The limits are small on purpose: the boundaries are the same code at any size, and a
 * fuzzer that spends its budget writing megabytes explores less.
 */
public class BundleFuzzTest {

    static final ExtractionLimits LIMITS = ExtractionLimits.fromOverrides(Map.of(
            "max_compressed_bytes", "262144",
            "max_expanded_bytes", "1048576",
            "max_file_bytes", "262144",
            "max_entries", "64",
            "max_manifest_bytes", "65536",
            "max_extended_header_bytes", "4096",
            "max_path_bytes", "256",
            "max_segment_bytes", "64",
            "max_depth", "8",
            "extraction_deadline_seconds", "5"));

    @FuzzTest
    void gzipMember(byte[] data) throws IOException {
        try (GzipMember member = GzipMember.open(new ByteArrayInputStream(data), LIMITS)) {
            member.transferTo(OutputStreamSink.INSTANCE);
        } catch (BundleRejection refused) {
            // the only acceptable failure
        }
    }

    @FuzzTest
    void tarHeader(byte[] data) {
        try {
            TarHeader header = TarHeader.parse(java.util.Arrays.copyOf(data, TarHeader.BLOCK),
                    LIMITS);
            if (header.size() < 0) {
                throw new AssertionError("a parsed header has a negative size: " + header.size());
            }
        } catch (BundleRejection refused) {
            // the only acceptable failure
        }
    }

    @FuzzTest
    void paxRecords(byte[] data) {
        try {
            PaxRecords.parse(data, LIMITS);
        } catch (BundleRejection refused) {
            // the only acceptable failure
        }
    }

    /**
     * The memberPath input layout: byte 0's low bit is the directory flag, the rest is the
     * name. Defined here, and dev/fuzz/seeds.py writes it, rather than leaving it to a
     * FuzzedDataProvider. Jazzer's provider takes consumeBoolean from the END of the input,
     * and the seeds put the flag FIRST, so until this changed every seed's name began with
     * a NUL byte and all 275 were refused as PATH_NUL before any other rule ran.
     */
    static MemberPath parseMemberPathInput(byte[] data) {
        boolean directory = data.length > 0 && (data[0] & 1) == 1;
        byte[] name = Arrays.copyOfRange(data, Math.min(1, data.length), data.length);
        return MemberPath.parse(name, directory, LIMITS);
    }

    @FuzzTest
    void memberPath(byte[] data) {
        MemberPath path;
        try {
            path = parseMemberPathInput(data);
        } catch (BundleRejection refused) {
            return;
        }
        // An accepted name must be one the extraction contract permits, whatever it took to
        // get here: the checks below restate the contract, not MemberPath's code.
        String text = path.memberPath();
        if (!Normalizer.isNormalized(text, Normalizer.Form.NFC)) {
            throw new AssertionError("accepted a name not in NFC: " + text);
        }
        // Every Cc code point. This said `c < 0x20`, the same range short as the rule it
        // checks, so the fuzzer could never have reported t5-e5e3071-F1.
        if (text.startsWith("/") || text.contains("\\")
                || text.chars().anyMatch(Character::isISOControl)) {
            throw new AssertionError("accepted an absolute, backslashed or control name: " + text);
        }
        for (String segment : path.payloadSegments()) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")
                    || segment.contains("/")) {
                throw new AssertionError("accepted a segment that is not a name: '" + segment
                        + "' in " + text);
            }
        }
        if (path.payloadSegments().size() > LIMITS.maxDepth()) {
            throw new AssertionError("accepted a path deeper than the limit: " + text);
        }
    }

    /**
     * The memberPath seeds must reach MemberPath's rules, not stop at its first byte.
     *
     * <p>A seed corpus that every input leaves at the same early branch still makes
     * {@code make test} green and still gives the fuzzer somewhere to start, so nothing
     * noticed that this one did (see {@link #parseMemberPathInput}). Replayed through the
     * target's own layout, some seeds must be accepted and some must be refused by rules
     * that run only after the byte loop and the decode.
     */
    @Test
    void theMemberPathSeedsReachPastTheFirstByte() throws IOException {
        Path seeds = Path.of("src/test/resources/eu/openanalytics/shinyproxy/publisher/bundle/"
                + "BundleFuzzTestInputs/memberPath");
        int accepted = 0;
        Set<BundleRule> deep = EnumSet.noneOf(BundleRule.class);
        Set<BundleRule> late = EnumSet.of(BundleRule.PATH_TRAVERSAL, BundleRule.PATH_DOT_SEGMENT,
                BundleRule.PATH_EMPTY_SEGMENT, BundleRule.PATH_NOT_NFC,
                BundleRule.LAYOUT_UNEXPECTED_MEMBER);
        try (Stream<Path> files = Files.list(seeds)) {
            for (Path seed : (Iterable<Path>) files::iterator) {
                try {
                    parseMemberPathInput(Files.readAllBytes(seed));
                    accepted++;
                } catch (BundleRejection refused) {
                    if (late.contains(refused.rule())) {
                        deep.add(refused.rule());
                    }
                }
            }
        }
        if (accepted == 0 || deep.isEmpty()) {
            throw new AssertionError("the memberPath seeds do not reach MemberPath's rules: "
                    + accepted + " accepted, late rules reached " + deep);
        }
    }

    @FuzzTest
    void tarStream(byte[] tar) throws IOException {
        try {
            TarStream.walk(new ByteArrayInputStream(tar), LIMITS, (path, header, content) ->
                    content.transferTo(OutputStreamSink.INSTANCE));
        } catch (BundleRejection refused) {
            // the only acceptable failure
        }
    }

    @FuzzTest
    void manifest(byte[] document) {
        try {
            ManifestValidator.validate(document, LIMITS);
        } catch (BundleRejection refused) {
            // the only acceptable failure
        }
    }

    /**
     * The whole pipeline, with the filesystem checked afterwards.
     *
     * <p>The input is the tar; it is gzipped here, so the fuzzer spends its effort on the
     * structure that matters and the gzip layer has its own target. Beside the workspace sits
     * a sentinel directory that must be byte-for-byte untouched afterwards, and the workspace
     * itself must be empty after a refusal and hold only private regular files and directories
     * after an acceptance.
     */
    @FuzzTest
    void extractor(byte[] tar) throws IOException {
        Path world = Files.createTempDirectory("skald-fuzz-");
        try {
            Path workspace = Files.createDirectory(world.resolve("workspace"),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            Path sentinel = Files.createDirectory(world.resolve("sentinel"));
            Files.writeString(sentinel.resolve("keep.txt"), "untouched");

            byte[] upload = gzip(tar);
            BundleExtractor.Extracted extracted = null;
            try {
                extracted = BundleExtractor.extract(new ByteArrayInputStream(upload),
                        upload.length, workspace, LIMITS);
            } catch (BundleRejection refused) {
                try (Stream<Path> left = Files.list(workspace)) {
                    List<Path> residue = left.toList();
                    if (!residue.isEmpty()) {
                        throw new AssertionError("a refusal (" + refused.rule() + ") left "
                                + residue);
                    }
                }
            }
            if (extracted != null) {
                ExtractionRoot root = extracted.root();
                requireOnlyPrivateFilesAndDirectories(root.path());
                // Deleted by the product's own deleteTree, so every accepted input also
                // proves a frozen tree can still be removed.
                root.deleteTree();
                try (Stream<Path> left = Files.list(workspace)) {
                    if (left.findAny().isPresent()) {
                        throw new AssertionError("deleteTree left a frozen tree behind");
                    }
                }
            }
            try (Stream<Path> entries = Files.list(sentinel)) {
                List<Path> seen = entries.toList();
                if (seen.size() != 1 || !Files.readString(sentinel.resolve("keep.txt"))
                        .equals("untouched")) {
                    throw new AssertionError("something outside the workspace changed: " + seen);
                }
            }
            try (Stream<Path> top = Files.list(world)) {
                Set<String> names = new java.util.TreeSet<>();
                top.forEach(p -> names.add(p.getFileName().toString()));
                if (!names.equals(Set.of("sentinel", "workspace"))) {
                    throw new AssertionError("something was created beside the workspace: "
                            + names);
                }
            }
        } finally {
            deleteTree(world);
        }
    }

    private static void requireOnlyPrivateFilesAndDirectories(Path root) throws IOException {
        try (Stream<Path> tree = Files.walk(root)) {
            for (Path p : tree.toList()) {
                if (Files.isSymbolicLink(p)) {
                    throw new AssertionError("a symbolic link was extracted: " + p);
                }
                String mode = PosixFilePermissions.toString(
                        Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS));
                // Frozen: an accepted tree is read-only, executable only where declared.
                boolean ok = Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)
                        ? mode.equals("r-x------")
                        : Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)
                                && (mode.equals("r--------") || mode.equals("r-x------"));
                if (!ok) {
                    throw new AssertionError("extracted " + p + " with mode " + mode);
                }
            }
        }
    }

    private static byte[] gzip(byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(body);
        }
        return out.toByteArray();
    }

    /** The test's own cleanup, for whatever a failed case left: directories made writable
     *  first (a frozen tree's are not), then everything removed deepest first. */
    private static void deleteTree(Path top) throws IOException {
        List<Path> all;
        try (Stream<Path> tree = Files.walk(top)) {
            all = tree.toList();
        }
        for (Path p : all) {
            if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------"));
            }
        }
        for (Path p : all.stream().sorted(java.util.Comparator.reverseOrder()).toList()) {
            Files.deleteIfExists(p);
        }
    }

    /** Discards what it is given; content has to be read for the layers under it to run. */
    private static final class OutputStreamSink extends java.io.OutputStream {
        static final OutputStreamSink INSTANCE = new OutputStreamSink();

        @Override
        public void write(int b) {
        }

        @Override
        public void write(byte[] b, int off, int len) {
        }
    }

}
