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
package eu.openanalytics.shinyproxy.publisher.storage;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Locale;
import java.util.UUID;

/**
 * Every object key Skald writes, built in one place.
 *
 * <p>The layout is fixed by the storage table in {@code WORKPLAN-BUNDLES.md} and
 * {@code ObjectKeysTest} parses that table rather than restating it, so the code and the
 * plan cannot drift. Keys live in object storage for as long as the content does: a
 * mistake here is not a bug to fix but a migration to run, which is why this is a separate,
 * dependency-free class rather than string concatenation at each call site.
 *
 * <p><b>Nothing here is user-supplied except one thing.</b> Every component is a
 * server-generated UUID or a fixed literal — except the relative path inside a rendition,
 * which comes from what a render produced. That one is validated by
 * {@link #renditionFile}, and it is validated <em>here</em> because the output-descriptor
 * schema deliberately does not. Its {@code renditionPath} says, in full:
 *
 * <blockquote>"Containment, '.' and '..' segments, empty segments, NFC normalisation and
 * case collisions are the writer's to enforce, exactly as on the input side."</blockquote>
 *
 * This class is the writer, and it enforces four of those five. <b>Case collisions it
 * cannot</b>: two paths collide only relative to each other, so the obligation belongs to
 * whatever assembles a rendition's complete file list, exactly as the input side assigns it
 * to the semantic validator's rule S3. It is named here rather than omitted, because an
 * earlier revision of this javadoc quoted the sentence above with "NFC normalisation and
 * case collisions" trimmed out — which removed from the record precisely the two
 * obligations the class did not meet (finding {@code 2b483fb-F2}).
 *
 * <p><b>No encoding happens here.</b> An S3 key is a byte string and the literal path is
 * what belongs in it; percent-encoding is the HTTP client's job at its own boundary. T1(b)
 * fixed the same rule for the descriptor — names requiring URL encoding are carried
 * literally "so that whatever encodes them for an S3 key or a URL does it at one boundary
 * rather than inheriting something already mangled".
 */
public final class ObjectKeys {

    /**
     * The layout generation. Present in every key so that a future layout can coexist with
     * this one instead of requiring every object to move on the same day.
     */
    public static final String LAYOUT = "v1";

    /** Objects that make up an uploaded bundle. {@code receipt.json} is written last. */
    public static final String BUNDLE_ARCHIVE = "bundle.tar.gz";
    public static final String BUNDLE_MANIFEST = "manifest.json";
    public static final String BUNDLE_INVENTORY = "inventory.json";
    public static final String BUNDLE_RECEIPT = "receipt.json";

    /** Log objects. {@code index.json} is the one mutable artifact in the whole layout. */
    public static final String LOG_INDEX = "index.json";
    public static final String LOG_FINAL = "final.json";

    public static final String RENDITION_DESCRIPTOR = "descriptor.json";

    /**
     * Width of the zero-padded chunk sequence.
     *
     * <p>Twelve, because the table says {@code chunks/000000000001.jsonl} and the width is
     * not cosmetic: chunk keys are listed and replayed in lexicographic order, so a
     * sequence that outgrows its padding sorts before its predecessors and a reader
     * following the index replays the log scrambled. Twelve digits is also why
     * {@link #MAX_SEQUENCE} exists rather than being left implicit at {@code Long.MAX_VALUE}.
     */
    public static final int SEQUENCE_DIGITS = 12;

    /** The largest sequence that still fits {@link #SEQUENCE_DIGITS} without widening. */
    public static final long MAX_SEQUENCE = 999_999_999_999L;

    /**
     * Matches {@code renditionPath}/{@code payloadPath} in the released schemas, which
     * dev/validate-manifests.sh already asserts have not drifted from each other.
     *
     * <p>This is the <em>weaker</em> of the two limits and it is not the one that protects
     * storage: it counts Java chars and spends the whole budget on the path, ignoring the
     * prefix every key carries. See {@link #MAX_RENDITION_PATH_BYTES}.
     */
    public static final int MAX_RENDITION_PATH_LENGTH = 1024;

    /** The key-length limit S3-compatible object stores impose, counted in UTF-8 bytes. */
    public static final int MAX_KEY_BYTES = 1024;

    /**
     * Width of {@code v1/content/C/versions/V/renditions/R/files/}.
     *
     * <p>Computed, not written down, so it cannot drift from the builder above. It is a
     * constant because every component is fixed-width: three canonical UUIDs at 36 ASCII
     * characters each plus fixed literals.
     */
    public static final int RENDITION_PREFIX_BYTES =
            (renditionPrefix(new UUID(0L, 0L), new UUID(0L, 0L), new UUID(0L, 0L))
                    + "/files/").getBytes(StandardCharsets.UTF_8).length;

    /**
     * What is actually left for a rendition path: {@value #MAX_KEY_BYTES} minus the prefix.
     *
     * <p>The schema's 1024 is a limit on the path; this is the limit on the <em>key</em>,
     * which is the one the object store enforces and the only one that knows the prefix
     * exists. Checking only the schema's limit accepted a 1024-character ASCII path as a
     * 1172-byte key, and 400 Japanese characters — comfortably inside 1024 chars — as a
     * 1348-byte key (finding {@code 2b483fb-F1}). The store would then refuse the PUT, and
     * because a rendition writes its files before its descriptor, it would refuse it after
     * earlier files of the same rendition were already written.
     */
    public static final int MAX_RENDITION_PATH_BYTES = MAX_KEY_BYTES - RENDITION_PREFIX_BYTES;

    private ObjectKeys() {
    }

    /** {@code v1/content/C/bundles/U/<name>} — the bundle's bytes and its metadata. */
    public static String bundleObject(UUID content, UUID bundle, String name) {
        requireKnownBundleObject(name);
        return String.join("/", LAYOUT, "content", id(content), "bundles", id(bundle), name);
    }

    /** {@code v1/content/C/builds/B/chunks/NNNNNNNNNNNN.jsonl} — one completed log chunk. */
    public static String logChunk(UUID content, UUID build, long sequence) {
        if (sequence < 1 || sequence > MAX_SEQUENCE) {
            throw new IllegalArgumentException(
                    "log chunk sequence must be between 1 and " + MAX_SEQUENCE
                            + ", but was " + sequence
                            + "; a sequence outside the padded width would sort out of order"
                            + " and replay the log scrambled");
        }
        String padded = String.format(Locale.ROOT, "%0" + SEQUENCE_DIGITS + "d", sequence);
        return String.join("/", LAYOUT, "content", id(content), "builds", id(build),
                "chunks", padded + ".jsonl");
    }

    /** {@code v1/content/C/builds/B/<name>} — the progress index or the final record. */
    public static String logObject(UUID content, UUID build, String name) {
        if (!LOG_INDEX.equals(name) && !LOG_FINAL.equals(name)) {
            throw new IllegalArgumentException(
                    "unknown log object '" + name + "'; the layout has only "
                            + LOG_INDEX + " and " + LOG_FINAL);
        }
        return String.join("/", LAYOUT, "content", id(content), "builds", id(build), name);
    }

    /**
     * {@code v1/content/C/versions/V/renditions/R/files/<path>} — one produced file.
     *
     * <p>The only key with a component this platform did not generate. The schema that
     * validates a descriptor leaves containment to the writer, so the rules are applied
     * here: the path must be relative, free of {@code .} and {@code ..} segments, free of
     * empty segments, and free of backslashes and control characters. A path failing any of
     * those could otherwise address an object outside its own rendition prefix.
     *
     * @throws IllegalArgumentException with a message naming the rule that rejected it
     */
    public static String renditionFile(UUID content, UUID version, UUID rendition,
                                       String relativePath) {
        return String.join("/", renditionPrefix(content, version, rendition), "files",
                validatedRenditionPath(relativePath));
    }

    /** {@code v1/content/C/versions/V/renditions/R/descriptor.json} — written last. */
    public static String renditionDescriptor(UUID content, UUID version, UUID rendition) {
        return renditionPrefix(content, version, rendition) + "/" + RENDITION_DESCRIPTOR;
    }

    /** The prefix every object of one rendition shares. Useful for listing and deletion. */
    public static String renditionPrefix(UUID content, UUID version, UUID rendition) {
        return String.join("/", LAYOUT, "content", id(content), "versions", id(version),
                "renditions", id(rendition));
    }

    /**
     * Applies the rules the descriptor schema leaves to the writer.
     *
     * <p>Public because the extractor and the descriptor writer need the same answer as the
     * key builder, and a second implementation of a containment rule is how two of them come
     * to disagree.
     */
    public static String validatedRenditionPath(String relativePath) {
        if (relativePath == null || relativePath.isEmpty()) {
            throw new IllegalArgumentException("rendition path must not be empty");
        }
        if (relativePath.length() > MAX_RENDITION_PATH_LENGTH) {
            throw new IllegalArgumentException(
                    "rendition path is " + relativePath.length() + " characters, over the "
                            + "schema limit of " + MAX_RENDITION_PATH_LENGTH);
        }
        // The limit that actually protects the PUT. Both are named in the message because
        // they fail at very different lengths and a publisher needs to know which one.
        int bytes = relativePath.getBytes(StandardCharsets.UTF_8).length;
        if (bytes > MAX_RENDITION_PATH_BYTES) {
            throw new IllegalArgumentException(
                    "rendition path is " + bytes + " UTF-8 bytes, over the "
                            + MAX_RENDITION_PATH_BYTES + " a key leaves for it ("
                            + MAX_KEY_BYTES + "-byte key limit minus a "
                            + RENDITION_PREFIX_BYTES + "-byte prefix); the schema's "
                            + MAX_RENDITION_PATH_LENGTH + "-character limit is weaker and "
                            + "counts characters, not bytes");
        }
        // Reject, never normalise. WORKPLAN-BUNDLES.md: "Paths must be relative
        // slash-separated UTF-8 in NFC. Reject, rather than normalize away, ..." --
        // normalising would silently rewrite a publisher's filename, and the descriptor
        // that names the original would then not describe the object that exists.
        if (!Normalizer.isNormalized(relativePath, Normalizer.Form.NFC)) {
            throw new IllegalArgumentException(
                    "rendition path is not in Unicode NFC: " + quoted(relativePath)
                            + "; the same name in two normalisations is two objects, so it "
                            + "is refused rather than rewritten");
        }
        if (relativePath.charAt(0) == '/') {
            throw new IllegalArgumentException(
                    "rendition path must be relative, but starts with '/': " + quoted(relativePath));
        }
        for (int i = 0; i < relativePath.length(); i++) {
            char c = relativePath.charAt(i);
            if (c == '\\') {
                throw new IllegalArgumentException(
                        "rendition path must not contain a backslash: " + quoted(relativePath));
            }
            // Includes NUL, newline and carriage return. A key carrying one of these is a
            // key that reads differently in a log line than it does in the bucket.
            if (c <= 0x1f || c == 0x7f) {
                throw new IllegalArgumentException(
                        "rendition path must not contain control characters: "
                                + quoted(relativePath));
            }
        }
        // -1 keeps trailing empty segments, so "a/" is rejected rather than silently trimmed.
        String[] segments = relativePath.split("/", -1);
        for (String segment : segments) {
            if (segment.isEmpty()) {
                throw new IllegalArgumentException(
                        "rendition path must not contain an empty segment: "
                                + quoted(relativePath));
            }
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException(
                        "rendition path must not contain a '" + segment + "' segment: "
                                + quoted(relativePath));
            }
        }
        return relativePath;
    }

    private static void requireKnownBundleObject(String name) {
        if (!BUNDLE_ARCHIVE.equals(name) && !BUNDLE_MANIFEST.equals(name)
                && !BUNDLE_INVENTORY.equals(name) && !BUNDLE_RECEIPT.equals(name)) {
            throw new IllegalArgumentException(
                    "unknown bundle object '" + name + "'; the layout has only "
                            + BUNDLE_ARCHIVE + ", " + BUNDLE_MANIFEST + ", "
                            + BUNDLE_INVENTORY + " and " + BUNDLE_RECEIPT);
        }
    }

    /**
     * A UUID as it appears in a key.
     *
     * <p>Explicitly lower-cased with {@link Locale#ROOT} rather than trusting
     * {@link UUID#toString()}: object keys are case-sensitive, so two spellings of one UUID
     * are two objects, and a default-locale lowercase is the same trap
     * {@code ContentPath} avoids for content paths.
     */
    private static String id(UUID id) {
        if (id == null) {
            throw new IllegalArgumentException("identifier must not be null");
        }
        return id.toString().toLowerCase(Locale.ROOT);
    }

    private static String quoted(String value) {
        return "'" + value + "'";
    }
}
