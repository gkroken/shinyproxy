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

import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * What the manifest claims, checked against itself: the plan's semantic rules S1-S9.
 *
 * <p>{@link ManifestSchema} decides the document's shape; this decides whether what it says
 * can be true. Paths stay inside the payload (S1) in the one canonical form an archive member
 * could carry (S2), once each (S3); the entrypoint resolves through the inventory the way its
 * language needs (S4, S5); the lockfile is in the inventory (S6) in the format the language
 * uses (S7); the type is one a reviewed recipe builds (S8) and, when the target is known, the
 * target's type (S9). S10 and S11 need the payload's bytes and are the extractor's.
 *
 * <p><b>A path is valid here exactly when a member carrying it would be valid there.</b> Every
 * path is put through {@link MemberPath} as {@code app/<path>}, the same parser and the same
 * configured bounds the archive's names meet. Two definitions would let the inventory declare
 * something no archive can deliver, or deliver something the inventory cannot name, and S11's
 * exact comparison depends on there being one. Its refusals are relabelled as the manifest's
 * rules, because what a publisher must fix is the manifest, not the archive.
 *
 * <p><b>Nothing is repaired.</b> No {@code ..} is stripped, no colliding path lower-cased, no
 * entrypoint inferred. Each rejection names its rule, starting with the plan's S-number,
 * and stops.
 */
public final class ManifestValidator {

    /** One inventory entry, as declared. */
    public record Declared(String path, long size, String sha256, boolean executable) { }

    /** A manifest that passed the schema and S1-S9 (and S9 only when a target was given). */
    public record Manifest(String type, String language, String runtimeVersion,
                           String entrypoint, String dependencyFormat, String dependencyPath,
                           Map<String, Declared> files) { }

    /**
     * The recipe matrix: the types a reviewed recipe builds, with the dependency format each
     * language uses. A type the schema registers but this does not list is S8. Grows with T7's
     * recipes, one reviewed branch at a time; a registered enum value is not a promise.
     */
    private static final Set<String> ENABLED_TYPES = Set.of("shiny");
    private static final Map<String, String> FORMAT_OF_LANGUAGE =
            Map.of("r", "renv", "python", "pip-hashed");

    private ManifestValidator() {
    }

    /** The schema and S1-S8. S9 needs a target and is skipped. */
    public static Manifest validate(byte[] manifest, ExtractionLimits limits) {
        return validate(manifest, limits, Optional.empty());
    }

    /**
     * The schema, S1-S8, and S9 against {@code targetType} when one is given.
     *
     * @throws BundleRejection naming the first rule the manifest breaks
     */
    public static Manifest validate(byte[] manifest, ExtractionLimits limits,
                                    Optional<String> targetType) {
        JsonNode document = ManifestSchema.validate(manifest);

        String type = document.path("type").textValue();
        String language = document.path("runtime").path("language").textValue();
        String format = document.path("dependencies").path("format").textValue();
        if (!ENABLED_TYPES.contains(type)) {
            throw new BundleRejection(BundleRule.MANIFEST_TYPE_UNSUPPORTED,
                    "S8: type '" + type + "' is registered but no reviewed recipe builds it"
                            + " yet; this platform builds " + ENABLED_TYPES);
        }
        if (targetType.isPresent() && !targetType.get().equals(type)) {
            throw new BundleRejection(BundleRule.MANIFEST_TYPE_MISMATCH,
                    "S9: the bundle is type '" + type + "' and the content it was uploaded to"
                            + " is '" + targetType.get() + "'");
        }
        if (!FORMAT_OF_LANGUAGE.get(language).equals(format)) {
            throw new BundleRejection(BundleRule.MANIFEST_FORMAT_LANGUAGE_MISMATCH,
                    "S7: dependencies.format is '" + format + "', and runtime.language '"
                            + language + "' uses '" + FORMAT_OF_LANGUAGE.get(language) + "'");
        }

        Map<String, Declared> files = inventory(document.path("files"), limits);

        String lockfile = document.path("dependencies").path("path").textValue();
        requirePayloadPath(lockfile, false, "dependencies.path", limits);
        if (!files.containsKey(lockfile)) {
            throw new BundleRejection(BundleRule.MANIFEST_LOCKFILE_NOT_IN_INVENTORY,
                    "S6: dependencies.path '" + lockfile + "' is not in files, so the"
                            + " dependencies it pins would never be delivered");
        }

        String entrypoint = document.path("entrypoint").textValue();
        if (language.equals("python")) {
            requireFileEntrypoint(entrypoint, files, limits);
        } else {
            requireDirectoryEntrypoint(entrypoint, files, limits);
        }

        return new Manifest(type, language, document.path("runtime").path("version").textValue(),
                entrypoint, format, lockfile, files);
    }

    private static Map<String, Declared> inventory(JsonNode entries, ExtractionLimits limits) {
        if (entries.size() > limits.maxEntries()) {
            throw new BundleRejection(BundleRule.ENTRY_COUNT_EXCEEDED,
                    "files declares " + entries.size() + " entries, more than the configured "
                            + limits.maxEntries() + "; refused before any of them is read");
        }
        Map<String, Declared> files = new LinkedHashMap<>();
        Map<String, String> byFolded = new HashMap<>();
        long total = 0;
        for (int i = 0; i < entries.size(); i++) {
            JsonNode entry = entries.get(i);
            String where = "files[" + i + "]";
            String path = entry.path("path").textValue();
            requirePayloadPath(path, false, where + ".path", limits);

            String earlier = byFolded.putIfAbsent(MemberIndex.fold(path), path);
            if (earlier != null) {
                throw new BundleRejection(BundleRule.MANIFEST_PATH_DUPLICATE,
                        "S3: " + where + ".path '" + path + "' is the same path as '" + earlier
                                + "'" + (earlier.equals(path) ? "" : " under case folding,"
                                + " and they would be one file on a case-insensitive system"));
            }

            long size = exactSize(entry.path("size"), where);
            if (size > limits.maxFileBytes()) {
                throw new BundleRejection(BundleRule.ENTRY_TOO_LARGE,
                        where + " declares " + size + " bytes, over the configured"
                                + " max_file_bytes " + limits.maxFileBytes()
                                + "; refused on the claim, before the bytes are read");
            }
            // Checked against the cap at every step, so the running total never exceeds
            // max_expanded_bytes + max_file_bytes, both validated limits: no overflow.
            total += size;
            if (total > limits.maxExpandedBytes()) {
                throw new BundleRejection(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED,
                        "files declares more than the configured max_expanded_bytes "
                                + limits.maxExpandedBytes() + " in total; refused on the claim");
            }
            files.put(path, new Declared(path, size, entry.path("sha256").textValue(),
                    entry.path("executable").asBoolean(false)));
        }
        return Collections.unmodifiableMap(files);
    }

    /**
     * The size as an exact long. The schema's "integer" admits 64.0 (2020-12 counts it), 1e20
     * and a 23-digit literal; {@code asLong()} would silently wrap the last. Only a value that
     * is a whole number AND fits is a size (recorded in 04e3d93's review).
     */
    private static long exactSize(JsonNode size, String where) {
        try {
            return size.decimalValue().longValueExact();
        } catch (ArithmeticException ex) {
            throw new BundleRejection(BundleRule.MANIFEST_SIZE_INVALID,
                    where + ".size " + size.asText() + " is not a whole number of bytes that"
                            + " fits in 64 bits");
        }
    }

    /** S4: a file, present in the inventory, ending in .py, and not a directory. */
    private static void requireFileEntrypoint(String entrypoint, Map<String, Declared> files,
                                              ExtractionLimits limits) {
        requirePayloadPath(entrypoint, false, "entrypoint", limits);
        if (hasFileBeneath(entrypoint + "/", files)) {
            throw new BundleRejection(BundleRule.MANIFEST_ENTRYPOINT_UNRESOLVED,
                    "S4: entrypoint '" + entrypoint + "' is a directory; a Python Shiny"
                            + " entrypoint names a .py file");
        }
        if (!entrypoint.endsWith(".py")) {
            throw new BundleRejection(BundleRule.MANIFEST_ENTRYPOINT_UNRESOLVED,
                    "S4: entrypoint '" + entrypoint + "' does not end in .py");
        }
        if (!files.containsKey(entrypoint)) {
            throw new BundleRejection(BundleRule.MANIFEST_ENTRYPOINT_UNRESOLVED,
                    "S4: entrypoint '" + entrypoint + "' is not in files");
        }
    }

    /**
     * S5: '.' or a contained directory, evidenced by the inventory alone, holding app.R or
     * both ui.R and server.R. A directory header does not count and is not required.
     */
    private static void requireDirectoryEntrypoint(String entrypoint,
                                                   Map<String, Declared> files,
                                                   ExtractionLimits limits) {
        String prefix;
        if (entrypoint.equals(".")) {
            prefix = "";
        } else {
            requirePayloadPath(entrypoint, true, "entrypoint", limits);
            if (files.containsKey(entrypoint)) {
                throw new BundleRejection(BundleRule.MANIFEST_ENTRYPOINT_UNRESOLVED,
                        "S5: entrypoint '" + entrypoint + "' is a file; an R Shiny"
                                + " entrypoint names a directory ('.' for the payload root)");
            }
            prefix = entrypoint + "/";
        }
        boolean single = files.containsKey(prefix + "app.R");
        boolean pair = files.containsKey(prefix + "ui.R") && files.containsKey(prefix + "server.R");
        if (!single && !pair) {
            throw new BundleRejection(BundleRule.MANIFEST_ENTRYPOINT_UNRESOLVED,
                    "S5: entrypoint '" + entrypoint + "' contains neither app.R nor both ui.R"
                            + " and server.R");
        }
    }

    private static boolean hasFileBeneath(String prefix, Map<String, Declared> files) {
        return files.keySet().stream().anyMatch(path -> path.startsWith(prefix));
    }

    /**
     * S1/S2 through {@link MemberPath}: valid here exactly when an archive member carrying the
     * path would be. Refusals that leave the root are S1, every other refusal S2.
     */
    private static void requirePayloadPath(String path, boolean directory, String where,
                                           ExtractionLimits limits) {
        byte[] member = (MemberPath.PAYLOAD_ROOT + "/" + path).getBytes(StandardCharsets.UTF_8);
        try {
            MemberPath parsed = MemberPath.parse(member, directory, limits);
            if (parsed.role() != MemberPath.Role.PAYLOAD || parsed.payloadSegments().isEmpty()) {
                throw new BundleRejection(BundleRule.PATH_EMPTY, "names the payload root");
            }
        } catch (BundleRejection ex) {
            boolean escapes = switch (ex.rule()) {
                case PATH_TRAVERSAL, PATH_ABSOLUTE, PATH_DRIVE_LETTER -> true;
                default -> false;
            };
            throw new BundleRejection(escapes ? BundleRule.MANIFEST_PATH_ESCAPES
                    : BundleRule.MANIFEST_PATH_NOT_CANONICAL,
                    (escapes ? "S1: " : "S2: ") + where + " '" + path + "' is refused as an"
                            + " archive member would be -- " + ex.getMessage());
        }
    }
}
