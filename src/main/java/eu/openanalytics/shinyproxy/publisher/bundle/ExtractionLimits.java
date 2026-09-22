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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * The bounds an extraction runs under: what they default to, how far an operator may move
 * them, and why a bad value stops the application instead of being quietly adjusted.
 *
 * <p><b>The numbers are not here.</b> They live in {@code spec/extraction-limits-v1.json},
 * packaged onto the classpath at {@link #SPEC_RESOURCE}, and this class reads them. Q3 made
 * limits operator configuration and owed in the same breath that "the defaults must appear
 * in one place that the documentation and the code agree on, or they will drift". A constant
 * here would be a second place. The agreement is therefore structural rather than checked:
 * there is nothing to compare because there is nothing to compare against.
 *
 * <p>What this class does check is that the spec and the code describe the same set of
 * bounds. A bound named in the file but absent from {@link Bound}, or the reverse, fails at
 * load — that is the drift an external checker would be looking for, caught where it happens.
 *
 * <p><b>A configured value is untrusted input.</b> Each override must parse as an integer,
 * be positive, and be at most the bound's {@code absolute_max}. Anything else throws and the
 * application does not start. It is deliberately not clamped: a clamped limit is one the
 * operator believes is in force and is not, which is worse than a refusal because nothing
 * ever says so. An unknown key is refused for the same reason — {@code max-file-byte} set to
 * a careful value is not a smaller limit, it is no limit, and silence would hide that.
 *
 * <p>Making the bounds configurable does not make them optional. There is no value meaning
 * unbounded, and zero is not one: it is refused like any other non-positive number.
 */
public final class ExtractionLimits {

    /** Packaged from {@code spec/} by the {@code <resources>} block in pom.xml. */
    public static final String SPEC_RESOURCE = "/skald/spec/extraction-limits-v1.json";

    /**
     * The bounds, named exactly as {@code spec/extraction-limits-v1.json}, the corpus
     * expectations and the oracle's {@code --limits} payload name them.
     */
    public enum Bound {
        MAX_COMPRESSED_BYTES,
        MAX_EXPANDED_BYTES,
        MAX_FILE_BYTES,
        MAX_ENTRIES,
        MAX_MANIFEST_BYTES,
        MAX_EXTENDED_HEADER_BYTES,
        MAX_PATH_BYTES,
        MAX_SEGMENT_BYTES,
        MAX_DEPTH,
        EXTRACTION_DEADLINE_SECONDS;

        /** The key in the spec file, in the corpus, and on the oracle's command line. */
        public String specName() {
            return name().toLowerCase(Locale.ROOT);
        }

        /** The configuration property an operator sets, under Spring's relaxed binding. */
        public String propertyName() {
            return "skald.bundle.limits." + specName().replace('_', '-');
        }

        static Bound bySpecName(String specName) {
            for (Bound b : values()) {
                if (b.specName().equals(specName)) {
                    return b;
                }
            }
            return null;
        }
    }

    /** One bound as the spec declares it: what it defaults to and how far it may be moved. */
    public record Declaration(long defaultValue, long absoluteMax) { }

    private static final Map<Bound, Declaration> SPEC = loadSpec(SPEC_RESOURCE);

    private final Map<Bound, Long> values;

    private ExtractionLimits(Map<Bound, Long> values) {
        this.values = values;
    }

    /** Every bound at its documented default. */
    public static ExtractionLimits defaults() {
        return fromOverrides(Map.of());
    }

    /**
     * The documented defaults with operator overrides applied.
     *
     * @param overrides keys in either the spec's {@code max_file_bytes} spelling or Spring's
     *                  relaxed {@code max-file-bytes} one; values as decimal integers. An
     *                  unrecognised key is an error, not an ignored line.
     * @throws LimitConfigurationException on an unknown key, an unparseable value, a
     *                                     non-positive value, or one above its absolute max
     */
    public static ExtractionLimits fromOverrides(Map<String, ?> overrides) {
        Map<Bound, Long> resolved = new EnumMap<>(Bound.class);
        for (Map.Entry<Bound, Declaration> e : SPEC.entrySet()) {
            resolved.put(e.getKey(), e.getValue().defaultValue());
        }
        for (Map.Entry<String, ?> e : overrides.entrySet()) {
            String key = e.getKey() == null ? "" : e.getKey().trim().replace('-', '_')
                    .toLowerCase(Locale.ROOT);
            Bound bound = Bound.bySpecName(key);
            if (bound == null) {
                throw new LimitConfigurationException(
                        "unknown extraction limit '" + e.getKey() + "'; known limits are "
                                + new TreeSet<>(specNames()));
            }
            resolved.put(bound, validated(bound, e.getValue()));
        }
        return new ExtractionLimits(resolved);
    }

    /**
     * The same validation applied to a JSON object of bounds, which is how the corpus oracle
     * hands a profile to the extractor. Every bound must be present: a partial payload would
     * silently mix a caller's profile with these defaults, and a corpus run whose boundary
     * fixtures straddle one number while the extractor enforces another proves nothing.
     */
    public static ExtractionLimits fromJson(String json) {
        JsonNode node;
        try {
            node = new ObjectMapper().readTree(json);
        } catch (IOException ex) {
            throw new LimitConfigurationException("limits payload is not JSON: " + ex.getMessage());
        }
        if (node == null || !node.isObject()) {
            throw new LimitConfigurationException("limits payload is not a JSON object");
        }
        Map<String, Object> supplied = new LinkedHashMap<>();
        node.fields().forEachRemaining(f -> supplied.put(f.getKey(),
                f.getValue().isNumber() || f.getValue().isTextual() ? f.getValue().asText()
                        : f.getValue().toString()));
        for (Bound bound : Bound.values()) {
            if (!supplied.containsKey(bound.specName())
                    && !supplied.containsKey(bound.specName().replace('_', '-'))) {
                throw new LimitConfigurationException(
                        "limits payload is missing '" + bound.specName() + "'");
            }
        }
        return fromOverrides(supplied);
    }

    private static long validated(Bound bound, Object raw) {
        String text = raw == null ? "" : String.valueOf(raw).trim();
        long value;
        try {
            value = Long.parseLong(text);
        } catch (NumberFormatException ex) {
            throw new LimitConfigurationException(
                    bound.propertyName() + ": '" + text + "' is not an integer");
        }
        if (value <= 0) {
            throw new LimitConfigurationException(
                    bound.propertyName() + ": " + value + " is not positive. Every bound is"
                            + " mandatory; there is no value meaning unbounded");
        }
        long max = SPEC.get(bound).absoluteMax();
        if (value > max) {
            throw new LimitConfigurationException(
                    bound.propertyName() + ": " + value + " exceeds the absolute maximum "
                            + max + ". Refused rather than clamped, because a clamped limit is"
                            + " one the operator believes is in force and is not");
        }
        return value;
    }

    public long get(Bound bound) {
        return values.get(bound);
    }

    public long maxCompressedBytes() {
        return get(Bound.MAX_COMPRESSED_BYTES);
    }

    public long maxExpandedBytes() {
        return get(Bound.MAX_EXPANDED_BYTES);
    }

    public long maxFileBytes() {
        return get(Bound.MAX_FILE_BYTES);
    }

    public long maxEntries() {
        return get(Bound.MAX_ENTRIES);
    }

    public long maxManifestBytes() {
        return get(Bound.MAX_MANIFEST_BYTES);
    }

    public long maxExtendedHeaderBytes() {
        return get(Bound.MAX_EXTENDED_HEADER_BYTES);
    }

    public long maxPathBytes() {
        return get(Bound.MAX_PATH_BYTES);
    }

    public long maxSegmentBytes() {
        return get(Bound.MAX_SEGMENT_BYTES);
    }

    public long maxDepth() {
        return get(Bound.MAX_DEPTH);
    }

    public long extractionDeadlineSeconds() {
        return get(Bound.EXTRACTION_DEADLINE_SECONDS);
    }

    /** The resolved bounds under their spec names, for logging and for the CLI's echo. */
    public Map<String, Long> asMap() {
        Map<String, Long> out = new LinkedHashMap<>();
        for (Bound bound : Bound.values()) {
            out.put(bound.specName(), values.get(bound));
        }
        return out;
    }

    /** What the spec declares for one bound, exposed so tests need no second copy either. */
    public static Declaration declaration(Bound bound) {
        return SPEC.get(bound);
    }

    private static TreeSet<String> specNames() {
        TreeSet<String> names = new TreeSet<>();
        for (Bound bound : Bound.values()) {
            names.add(bound.specName());
        }
        return names;
    }

    private static Map<Bound, Declaration> loadSpec(String resource) {
        JsonNode root;
        try (InputStream in = ExtractionLimits.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new LimitConfigurationException(
                        "extraction limits spec missing from the classpath at " + resource
                                + "; spec/ is packaged by the <resources> block in pom.xml");
            }
            root = new ObjectMapper().readTree(in);
        } catch (IOException ex) {
            throw new LimitConfigurationException(
                    "extraction limits spec at " + resource + " is unreadable: " + ex.getMessage());
        }
        return parseSpec(root, resource);
    }

    /**
     * Separated from the classpath read so that the parity rules below are reachable from a
     * test with a document in hand. They are the whole point of keeping the numbers in one
     * file, and a rule nothing can exercise is a rule nobody has watched fail.
     */
    static Map<Bound, Declaration> parseSpec(JsonNode root, String resource) {
        JsonNode bounds = root == null ? null : root.path("bounds");
        if (bounds == null || !bounds.isObject() || bounds.isEmpty()) {
            throw new LimitConfigurationException(
                    "extraction limits spec at " + resource + " declares no bounds");
        }

        Map<Bound, Declaration> declared = new EnumMap<>(Bound.class);
        bounds.fields().forEachRemaining(field -> {
            Bound bound = Bound.bySpecName(field.getKey());
            if (bound == null) {
                // The spec names a bound the code does not implement. Enforcing nothing for
                // it would be the drift this arrangement exists to prevent.
                throw new LimitConfigurationException(
                        "extraction limits spec declares '" + field.getKey()
                                + "', which no Bound implements");
            }
            JsonNode entry = field.getValue();
            if (!entry.path("default").isIntegralNumber()
                    || !entry.path("absolute_max").isIntegralNumber()) {
                throw new LimitConfigurationException(
                        "extraction limits spec entry '" + field.getKey()
                                + "' needs integral 'default' and 'absolute_max'");
            }
            long defaultValue = entry.path("default").asLong();
            long absoluteMax = entry.path("absolute_max").asLong();
            // No separate absoluteMax <= 0 clause: with a positive default it can only
            // be reached through 'default > absolute_max', so it would never be the
            // sole reason a spec is refused.
            if (defaultValue <= 0 || defaultValue > absoluteMax) {
                throw new LimitConfigurationException(
                        "extraction limits spec entry '" + field.getKey() + "' is incoherent:"
                                + " default " + defaultValue + ", absolute_max " + absoluteMax);
            }
            declared.put(bound, new Declaration(defaultValue, absoluteMax));
        });
        for (Bound bound : Bound.values()) {
            if (!declared.containsKey(bound)) {
                throw new LimitConfigurationException(
                        "extraction limits spec does not declare '" + bound.specName() + "'");
            }
        }
        return declared;
    }

    /** Refusal to start under a limit configuration that cannot be honoured as written. */
    public static class LimitConfigurationException extends IllegalStateException {
        public LimitConfigurationException(String message) {
            super(message);
        }
    }
}
