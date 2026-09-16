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
package eu.openanalytics.shinyproxy.publisher.registry;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A publisher-settable content path, and the rules it has to satisfy.
 *
 * <p>Separate from any identifier. Paths are renameable and content is identified by its
 * UUID, so nothing durable may be derived from what is written here.
 *
 * <p><b>Case.</b> The publisher's capitalisation is preserved for display and matching is
 * case-insensitive, which means a normalised key decides uniqueness. That key is computed
 * here, in ASCII, rather than by {@code lower()} in a database index: {@code lower()} is
 * collation-dependent — in a Turkish collation {@code 'I'} lower-cases to a dotless
 * {@code 'ı'} — so a {@code lower(path)} unique index means different things on different
 * installations. Restricting paths to ASCII and lowering with {@link Locale#ROOT} makes the
 * answer the same everywhere, and the schema stores the key in a {@code COLLATE "C"} column
 * so comparison is byte-wise too.
 */
public final class ContentPath {

    /** Bounds how much URL space one content item can own, and keeps resolution cheap. */
    public static final int MAX_SEGMENTS = 3;

    private static final int MAX_SEGMENT_LENGTH = 50;

    private static final Pattern SEGMENT = Pattern.compile("^[a-z0-9][a-z0-9-]{0,49}$");

    private ContentPath() {
    }

    /**
     * Validates a publisher-supplied path and returns its normalised key.
     *
     * @throws IllegalArgumentException with a message intended for the publisher
     */
    public static String normalise(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("path is required");
        }
        String trimmed = path.trim();

        if (trimmed.startsWith("/") || trimmed.endsWith("/")) {
            throw new IllegalArgumentException(
                "path must not start or end with '/' (got '" + trimmed + "')");
        }
        if (!trimmed.chars().allMatch(c -> c < 128)) {
            throw new IllegalArgumentException(
                "path must be ASCII; non-ASCII characters have no single agreed lower-case form "
                    + "across database collations, so they cannot be matched reliably");
        }

        String key = trimmed.toLowerCase(Locale.ROOT);
        String[] segments = key.split("/", -1);

        if (segments.length > MAX_SEGMENTS) {
            throw new IllegalArgumentException("path may have at most " + MAX_SEGMENTS
                + " segments, got " + segments.length + " in '" + trimmed + "'");
        }
        for (String segment : segments) {
            if (!SEGMENT.matcher(segment).matches()) {
                throw new IllegalArgumentException("path segment '" + segment
                    + "' must start with a letter or digit and contain only lower-case letters, "
                    + "digits and hyphens, at most " + MAX_SEGMENT_LENGTH + " characters");
            }
        }
        return key;
    }

    /**
     * Whether one path would sit inside the other's subtree.
     *
     * <p>Content owns its whole subtree, so {@code team} and {@code team/reports} cannot both
     * exist: a request for {@code /c/team/reports} would be satisfiable two ways and the
     * resolver has no basis to choose. It is refused when the second one is published rather
     * than resolved at request time.
     *
     * <p>Equal keys are not a conflict <em>here</em> — that is ordinary uniqueness, reported
     * separately so the publisher gets the more specific message.
     */
    public static boolean conflicts(String keyA, String keyB) {
        return keyA.startsWith(keyB + "/") || keyB.startsWith(keyA + "/");
    }

}
