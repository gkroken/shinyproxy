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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The manifest as a document: one strict JSON value, valid against the published schema for
 * the version it declares.
 *
 * <p><b>The schema is the authority, and it is read, not copied.</b> The documents in
 * {@code schemas/manifest/} ship on the classpath and are validated against with networknt
 * (dialect 2020-12). A Java restatement of their rules would be a second definition that
 * drifts from the one publishers and tools are given. The version is selected through
 * {@code index.json}, as that file says anything that validates must do.
 *
 * <p><b>What JSON Schema cannot say is refused before it runs.</b> A repeated key, bytes
 * after the value, nesting past a small bound and invalid UTF-8 all parse into SOME tree
 * under a lenient reader, and then the schema validates whatever that reader chose. Two
 * readers of one manifest must not be able to disagree about what it says, so the parser
 * refuses them instead ({@link BundleRule#MANIFEST_DUPLICATE_KEY},
 * {@link BundleRule#MANIFEST_NOT_JSON}).
 *
 * <p><b>Nothing is fetched.</b> The registry is given the shipped documents under their own
 * ids and a loader that refuses every other location, so a {@code $ref} to a URL — in a
 * future schema, or anywhere else — fails rather than reaching the network. "No network
 * schema lookup" is the plan's wording and a test holds it with a live server that must see
 * no request.
 *
 * <p>This decides shape only. Whether paths stay inside the payload, whether the entrypoint
 * resolves and whether the inventory describes the bytes that arrive are the semantic rules,
 * and are not here.
 */
public final class ManifestSchema {

    /** Where the shipped schema documents live on the classpath. */
    static final String RESOURCE_ROOT = "/skald/";

    /**
     * Deep enough for any valid manifest, which nests four levels, with room for an error to
     * be reported by the schema rather than the parser. A cheap bound on work, not a rule.
     */
    static final int MAX_NESTING_DEPTH = 16;

    private static final ObjectMapper STRICT = strictMapper();
    private static final Map<Integer, Schema> SCHEMAS = loadSchemas();

    private ManifestSchema() {
    }

    /**
     * Parses and validates {@code manifest}.
     *
     * @return the document, which has passed the schema for its declared version
     * @throws BundleRejection naming what was wrong with it
     */
    public static JsonNode validate(byte[] manifest) {
        JsonNode document = parse(manifest);
        JsonNode version = document.path("schema_version");
        if (!version.isIntegralNumber()) {
            // No version to select a schema by. Validated against the current one so the
            // publisher hears what every schema requires, not only that this is missing.
            reject(document, SCHEMAS.get(currentVersion()));
        }
        Schema schema = version.canConvertToInt() ? SCHEMAS.get(version.intValue()) : null;
        if (schema == null) {
            throw new BundleRejection(BundleRule.MANIFEST_SCHEMA_VERSION_UNSUPPORTED,
                    "schema_version " + version.asText() + " is not one this platform"
                            + " validates; it knows " + SCHEMAS.keySet());
        }
        reject(document, schema);
        return document;
    }

    static JsonNode parse(byte[] manifest) {
        String text = strictUtf8(manifest);
        try {
            JsonNode document = STRICT.readTree(text);
            if (document == null || document.isMissingNode()) {
                throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                        "the manifest is empty");
            }
            return document;
        } catch (StreamConstraintsException ex) {
            throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                    "the manifest nests deeper than " + MAX_NESTING_DEPTH + " levels");
        } catch (com.fasterxml.jackson.core.JsonParseException ex) {
            if (ex.getMessage() != null && ex.getMessage().startsWith("Duplicate field")) {
                throw new BundleRejection(BundleRule.MANIFEST_DUPLICATE_KEY,
                        firstLine(ex.getOriginalMessage()) + ". Which of the two values counts"
                                + " would depend on who reads it");
            }
            throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                    firstLine(ex.getOriginalMessage()));
        } catch (com.fasterxml.jackson.databind.exc.MismatchedInputException ex) {
            // FAIL_ON_TRAILING_TOKENS: a second value after the first.
            throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                    firstLine(ex.getOriginalMessage()));
        } catch (IOException ex) {
            throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                    ex.getClass().getSimpleName() + ": " + firstLine(ex.getMessage()));
        }
    }

    /**
     * The bytes as UTF-8, or a refusal. Decoded here, strictly, and never by the JSON parser.
     *
     * <p>Jackson's byte-level parser detects the encoding itself and accepts what a strict
     * decoder refuses: {@code C0 AF} decodes to '/', so {@code C0 AE C0 AE C0 AF} reads as
     * "../"; {@code F4 90 80 80} (past U+10FFFF) becomes lone surrogates; a manifest in
     * UTF-16 or UTF-32 is read as one (finding 04e3d93-F1). Python's json, jq and any strict
     * consumer refuse all of those, so the manifest would mean one thing here and nothing, or
     * something else, there. The JDK's decoder with REPORT refuses overlongs, surrogates and
     * anything past U+10FFFF; UTF-16 and UTF-32 either fail it or decode to NULs, which the
     * parser then refuses as control characters.
     *
     * <p><b>A byte order mark is refused, not stripped.</b> RFC 8259 forbids sending one and
     * lets a reader ignore it, and Python's json does ignore it. It is refused because the
     * uploaded bundle is stored as it arrived, and a strict reader of that stored
     * manifest.json (jq refuses a BOM) would then fail on a manifest this platform accepted.
     * None of this project's tools emit one, and the refusal says exactly what to remove.
     */
    private static String strictUtf8(byte[] manifest) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(manifest))
                    .toString();
        } catch (CharacterCodingException ex) {
            throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                    "the manifest is not valid UTF-8 (" + ex.getClass().getSimpleName()
                            + "): an overlong form, a surrogate, a value past U+10FFFF or a"
                            + " truncated sequence. It must be UTF-8, with no other"
                            + " encoding detected on its behalf");
        }
        if (text.startsWith("\uFEFF")) {
            throw new BundleRejection(BundleRule.MANIFEST_NOT_JSON,
                    "the manifest begins with a byte order mark (EF BB BF). Save it as UTF-8"
                            + " without one");
        }
        return text;
    }

    private static void reject(JsonNode document, Schema schema) {
        List<Error> errors = schema.validate(document);
        if (errors.isEmpty()) {
            return;
        }
        // Sorted, so the same manifest is refused in the same words every time; bounded,
        // because a publisher needs the first few, not the whole cascade.
        List<String> messages = errors.stream()
                .map(error -> where(error) + " " + error.getMessage())
                .sorted(Comparator.naturalOrder())
                .distinct()
                .collect(Collectors.toList());
        String shown = String.join("; ", messages.subList(0, Math.min(5, messages.size())));
        throw new BundleRejection(BundleRule.MANIFEST_SCHEMA_INVALID, shown
                + (messages.size() > 5 ? "; and " + (messages.size() - 5) + " more" : ""));
    }

    /** The JSON Pointer of the offending value, which is empty for the document itself. */
    private static String where(Error error) {
        String pointer = String.valueOf(error.getInstanceLocation());
        return pointer.isEmpty() ? "(the manifest)" : pointer;
    }

    private static ObjectMapper strictMapper() {
        JsonFactory factory = JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(MAX_NESTING_DEPTH)
                        .build())
                .build();
        factory.disable(JsonParser.Feature.ALLOW_COMMENTS);
        return new ObjectMapper(factory)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
    }

    /** index.json's versions, each loaded from the classpath under the path it names. */
    private static Map<Integer, Schema> loadSchemas() {
        JsonNode index = readResource("schemas/manifest/index.json");
        Map<String, String> documents = new HashMap<>();
        Map<Integer, String> ids = new HashMap<>();
        index.path("versions").fields().forEachRemaining(entry -> {
            String path = entry.getValue().asText();
            JsonNode schema = readResource(path);
            String id = schema.path("$id").asText();
            if (id.isEmpty()) {
                throw new IllegalStateException(path + " has no $id to be loaded under");
            }
            documents.put(id, schema.toString());
            ids.put(Integer.parseInt(entry.getKey()), id);
        });
        if (ids.isEmpty()) {
            throw new IllegalStateException("schemas/manifest/index.json lists no versions");
        }
        SchemaRegistry registry = registry(documents);
        Map<Integer, Schema> schemas = new HashMap<>();
        ids.forEach((version, id) -> schemas.put(version,
                registry.getSchema(SchemaLocation.of(id))));
        return Map.copyOf(schemas);
    }

    /**
     * A registry that knows {@code documents} by id and loads nothing else: remote fetching
     * off, and every location not in the map blocked outright rather than left to the
     * library's defaults. Package-private so the refusal can be tested.
     */
    static SchemaRegistry registry(Map<String, String> documents) {
        return SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12,
                builder -> builder
                        .schemas(documents)
                        .schemaLoader(loader -> loader
                                .fetchRemoteResources(false)
                                .block(iri -> !documents.containsKey(iri.toString()))));
    }

    private static int currentVersion() {
        return readResource("schemas/manifest/index.json").path("current_version").asInt();
    }

    private static JsonNode readResource(String path) {
        String resource = RESOURCE_ROOT + path;
        try (InputStream in = ManifestSchema.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException(resource + " is not on the classpath; the"
                        + " manifest cannot be validated without the schema it is judged by");
            }
            return new ObjectMapper().readTree(in);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static String firstLine(String message) {
        if (message == null) {
            return "unreadable";
        }
        int newline = message.indexOf('\n');
        return newline < 0 ? message : message.substring(0, newline);
    }
}
