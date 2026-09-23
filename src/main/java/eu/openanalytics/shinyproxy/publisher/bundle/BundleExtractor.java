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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.function.LongSupplier;

/**
 * An upload in, a private directory of validated files out — or nothing at all.
 *
 * <p>This is the first class in the track that produces a side effect, and the only one that
 * has to undo one. Every other layer refuses and returns; this one may have written files
 * before the refusal arrives, so its contract is that a bundle is either extracted in full
 * or leaves nothing behind. "Delete it on all failure/cancellation paths" is the contract's
 * wording, and "all" includes the paths that are not rejections: an I/O error, an
 * interruption, a bug in any layer below.
 *
 * <p><b>The manifest is read, not written.</b> It is held in memory under
 * {@code max_manifest_bytes} and handed back; it never lands in the extraction directory,
 * which is the payload root and may legitimately contain the publisher's own
 * {@code app/manifest.json}. {@link ExtractionRoot} refuses to write it for that reason and
 * this is the other half of the arrangement.
 *
 * <p><b>The manifest comes first, and that is structural.</b> The contract says "root
 * manifest.json is the first logical regular file". A payload member arriving before it is
 * refused rather than buffered, because the alternative is holding an unbounded amount of
 * unvalidated content while waiting for the document that says what it should be — which is
 * the shape of every bomb in the corpus. What the manifest SAYS is judged later, by the
 * validator that reads it; that it is there and that it is first is decided here.
 */
public final class BundleExtractor {

    /** What a successful extraction produced. */
    public record Extracted(ExtractionRoot root, byte[] manifest, long files, long bytes) { }

    private BundleExtractor() {
    }

    public static Extracted extract(InputStream upload, long uploadSize, Path workspace,
                                    ExtractionLimits limits) throws IOException {
        return extract(upload, uploadSize, workspace, limits, System::nanoTime);
    }

    /**
     * Extracts one upload into a fresh private directory under {@code workspace}.
     *
     * @param uploadSize the upload's length if it is known, or a negative number if it is
     *                   not. When it is known it is checked before anything is parsed, which
     *                   is the cheapest refusal available; when it is not, the streaming
     *                   count in {@link GzipMember} is the only one and still holds.
     * @throws BundleRejection with the rule that refused it, having left nothing behind
     */
    public static Extracted extract(InputStream upload, long uploadSize, Path workspace,
                                    ExtractionLimits limits, LongSupplier nanoTime)
            throws IOException {
        if (uploadSize >= 0) {
            GzipMember.checkUploadSize(uploadSize, limits);
        }

        return extractInto(ExtractionRoot.createUnder(workspace), upload, limits, nanoTime);
    }

    /**
     * The same, into a root that has already been adopted.
     *
     * <p>Package-private, and split out only so the independent corpus oracle can judge this
     * code rather than a reference extractor: the oracle hands its subject an existing
     * directory, which a test-tree adapter adopts through
     * {@link ExtractionRoot#adopt} — the same identity, no-follow and permission checks
     * {@link ExtractionRoot#createUnder} ends in. Production never takes this path; it
     * always creates the root itself.
     */
    static Extracted extractInto(ExtractionRoot root, InputStream upload,
                                 ExtractionLimits limits, LongSupplier nanoTime)
            throws IOException {
        Collector collector = new Collector(root, limits);
        try (GzipMember member = GzipMember.open(upload, limits)) {
            TarStream.walk(member, limits, nanoTime, collector);
            if (collector.manifest == null) {
                throw new BundleRejection(BundleRule.MANIFEST_MISSING,
                        "the archive carries no manifest.json, so nothing says what these "
                                + collector.files + " file(s) are");
            }
            return new Extracted(root, collector.manifest, collector.files, collector.bytes);
        } catch (Throwable failure) {
            // Every failure path, including the ones that are not rejections, and including
            // the envelope check that GzipMember runs when it closes. A partial extraction
            // left on disk is a directory some later step may mistake for a validated one.
            //
            // Not a finally block: an exception thrown from one discards the exception in
            // flight, so a delete that failed would replace the BundleRejection naming the
            // rule with an IOException about the filesystem — losing the rule AND leaving
            // the tree, which is both halves of what this method promises (e670073-F2). The
            // cleanup's own failure is attached to the original instead.
            try {
                root.deleteTree();
            } catch (Throwable cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
    }

    /** Routes each member to the one place it belongs. */
    private static final class Collector implements TarStream.MemberSink {

        private final ExtractionRoot root;
        private final ExtractionLimits limits;

        private byte[] manifest;
        private long files;
        private long bytes;

        private Collector(ExtractionRoot root, ExtractionLimits limits) {
            this.root = root;
            this.limits = limits;
        }

        @Override
        public void member(MemberPath path, TarHeader header, InputStream content)
                throws IOException {
            if (path.role() == MemberPath.Role.MANIFEST) {
                manifest = readManifest(header, content);
                return;
            }
            if (header.kind() == TarHeader.Kind.DIRECTORY) {
                // Directory headers are permitted before the manifest. The contract's two
                // clauses are separate — "root manifest.json is the first logical regular
                // FILE" and "optional directory headers are permitted" — and refusing on
                // both made the same archive accepted or refused depending only on whether
                // its 'app/' header came before or after the manifest (finding e670073-F1).
                // A directory header carries no content, so the reason the rule exists does
                // not reach it either.
                root.createDirectory(path);
                return;
            }
            if (manifest == null) {
                throw new BundleRejection(BundleRule.MANIFEST_NOT_FIRST,
                        "'" + path.memberPath() + "' arrives before manifest.json. The"
                                + " manifest is the first logical regular file, so that"
                                + " nothing is written before the document describing it has"
                                + " been read");
            }
            files++;
            bytes += root.writeFile(path, content);
        }

        /**
         * Reads the manifest into memory under its own bound, checked on the DECLARED size
         * first — the same rule PAX headers get, and for the same reason: a bound applied to
         * bytes already in hand has been paid for by the time it fires.
         */
        private byte[] readManifest(TarHeader header, InputStream content) throws IOException {
            if (header.size() > limits.maxManifestBytes()) {
                throw new BundleRejection(BundleRule.MANIFEST_TOO_LARGE,
                        "the manifest declares " + header.size() + " bytes, over the"
                                + " configured " + limits.maxManifestBytes()
                                + ". Refused on the claim, before the bytes are read");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) header.size());
            byte[] buffer = new byte[8192];
            int read;
            while ((read = content.read(buffer, 0, buffer.length)) >= 0) {
                out.write(buffer, 0, read);
                if (out.size() > limits.maxManifestBytes()) {
                    throw new BundleRejection(BundleRule.MANIFEST_TOO_LARGE,
                            "the manifest is over the configured "
                                    + limits.maxManifestBytes() + " bytes");
                }
            }
            return out.toByteArray();
        }
    }
}
