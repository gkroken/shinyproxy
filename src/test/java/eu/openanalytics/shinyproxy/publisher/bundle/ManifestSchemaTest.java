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
import com.networknt.schema.SchemaLocation;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The manifest fixtures T1 froze, through the server-side validator.
 *
 * <p>{@code dev/validate-manifests.sh} puts the same fixtures through Python's jsonschema,
 * deliberately a different implementation. This is the one that ships, judged by the same
 * expectations file, so the two validators cannot quietly disagree about a fixture.
 */
public class ManifestSchemaTest {

    private static final Path FIXTURES = Path.of("dev/fixtures/manifests");

    @Test
    public void everyFixtureIsClassifiedAsItsExpectationsSay() throws IOException {
        JsonNode expectations = new ObjectMapper().readTree(
                FIXTURES.resolve("expectations.json").toFile());
        List<String> wrong = new ArrayList<>();
        Set<String> seen = new TreeSet<>();

        for (String name : names(expectations.path("valid"))) {
            seen.add(name);
            try {
                ManifestSchema.validate(read("valid", name));
            } catch (BundleRejection ex) {
                wrong.add("valid/" + name + " refused: " + ex.getMessage());
            }
        }
        // Structurally valid ON PURPOSE: the schema must accept them and the semantic rules
        // refuse them. A schema that refused these would be doing the semantic validator's
        // work badly, and would hide whether that validator does it at all.
        for (String name : names(expectations.path("semantic_invalid"))) {
            seen.add(name);
            try {
                ManifestSchema.validate(read("invalid", name));
            } catch (BundleRejection ex) {
                wrong.add("semantic_invalid/" + name + " refused by the schema: "
                        + ex.getMessage());
            }
        }
        for (String name : names(expectations.path("schema_invalid"))) {
            seen.add(name);
            BundleRule expected = name.equals("future-schema-version")
                    ? BundleRule.MANIFEST_SCHEMA_VERSION_UNSUPPORTED
                    : BundleRule.MANIFEST_SCHEMA_INVALID;
            try {
                ManifestSchema.validate(read("invalid", name));
                wrong.add("schema_invalid/" + name + " ACCEPTED");
            } catch (BundleRejection ex) {
                if (ex.rule() != expected) {
                    wrong.add("schema_invalid/" + name + " refused as " + ex.rule()
                            + ", expected " + expected + ": " + ex.getMessage());
                }
            }
        }
        assertEquals(List.of(), wrong);

        // And nothing on disk escaped classification: a fixture added without an
        // expectation would otherwise be silently skipped by all three loops.
        Set<String> onDisk = new TreeSet<>();
        for (String dir : List.of("valid", "invalid")) {
            try (Stream<Path> files = Files.list(FIXTURES.resolve(dir))) {
                files.forEach(f -> onDisk.add(f.getFileName().toString().replace(".json", "")));
            }
        }
        assertEquals(onDisk, seen, "fixtures on disk and fixtures with an expectation differ");
        assertTrue(seen.size() > 40, "suspiciously few fixtures: " + seen.size());
    }

    @Test
    public void whatAParserWouldHaveToGuessAboutIsRefusedBeforeTheSchemaRuns() {
        String valid = new String(read("valid", "r-root-single-file"), StandardCharsets.UTF_8);

        assertEquals(BundleRule.MANIFEST_DUPLICATE_KEY, ruleOf(
                valid.replaceFirst("\"type\": \"shiny\"", "\"type\": \"shiny\", \"type\": \"plumber\"")));
        assertEquals(BundleRule.MANIFEST_NOT_JSON, ruleOf(valid + " {}"),
                "a second value after the first");
        assertEquals(BundleRule.MANIFEST_NOT_JSON, ruleOf("// a comment\n" + valid));
        assertEquals(BundleRule.MANIFEST_NOT_JSON, ruleOf(""));
        assertEquals(BundleRule.MANIFEST_NOT_JSON, ruleOf(valid.substring(0, valid.length() / 2)));
        String deep = "[".repeat(ManifestSchema.MAX_NESTING_DEPTH + 1)
                + "]".repeat(ManifestSchema.MAX_NESTING_DEPTH + 1);
        assertEquals(BundleRule.MANIFEST_NOT_JSON,
                ruleOf(valid.replaceFirst("\\{", "{\"deep\": " + deep + ",")));

        // The control: the untouched document passes, so each refusal above is the edit's.
        ManifestSchema.validate(valid.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void onlyStrictUtf8IsAManifest() {
        // 04e3d93-F1. Each sequence is placed inside the entrypoint string of a valid
        // manifest, where a lenient decoder turns it into path text: C0 AE C0 AE C0 AF is
        // "../" to Jackson's own byte parser, and "src/<C0 AF>app.py" is "src//app.py".
        String valid = new String(read("valid", "python-root"), StandardCharsets.UTF_8);
        Map<String, int[]> malformed = new java.util.LinkedHashMap<>();
        malformed.put("overlong '/'", new int[] {0xC0, 0xAF});
        malformed.put("overlong '.'", new int[] {0xC0, 0xAE});
        malformed.put("overlong traversal", new int[] {0xC0, 0xAE, 0xC0, 0xAE, 0xC0, 0xAF});
        malformed.put("three-byte overlong '/'", new int[] {0xE0, 0x80, 0xAF});
        malformed.put("past U+10FFFF", new int[] {0xF4, 0x90, 0x80, 0x80});
        malformed.put("invalid lead F5", new int[] {0xF5, 0x80, 0x80, 0x80});
        malformed.put("encoded surrogate", new int[] {0xED, 0xA0, 0x80});
        malformed.put("bare continuation", new int[] {0x80});
        malformed.put("truncated sequence", new int[] {0xE2, 0x82});
        List<String> accepted = new ArrayList<>();
        for (Map.Entry<String, int[]> row : malformed.entrySet()) {
            byte[] bytes = withEntrypointBytes(valid, row.getValue());
            try {
                ManifestSchema.validate(bytes);
                accepted.add(row.getKey() + " ACCEPTED");
            } catch (BundleRejection ex) {
                // The UTF-8 refusal specifically: a schema or path refusal of the decoded
                // text would mean a lenient decode had already happened.
                if (ex.rule() != BundleRule.MANIFEST_NOT_JSON
                        || !ex.getMessage().contains("not valid UTF-8")) {
                    accepted.add(row.getKey() + " refused for the wrong reason: "
                            + ex.getMessage());
                }
            }
        }
        assertEquals(List.of(), accepted);

        // Other encodings are not detected on the manifest's behalf.
        for (java.nio.charset.Charset other : List.of(StandardCharsets.UTF_16LE,
                StandardCharsets.UTF_16BE, StandardCharsets.UTF_16,
                java.nio.charset.Charset.forName("UTF-32BE"))) {
            assertEquals(BundleRule.MANIFEST_NOT_JSON, assertThrows(BundleRejection.class,
                    () -> ManifestSchema.validate(valid.getBytes(other))).rule(),
                    other.name());
        }
        // A BOM is refused by decision, not by accident; the message says which.
        byte[] bom = ("\uFEFF" + valid).getBytes(StandardCharsets.UTF_8);
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> ManifestSchema.validate(bom));
        assertTrue(ex.getMessage().contains("byte order mark"), ex.getMessage());

        // The control: the same document, and a legitimate multi-byte name, both pass.
        ManifestSchema.validate(valid.getBytes(StandardCharsets.UTF_8));
        ManifestSchema.validate(withEntrypointBytes(valid, new int[] {0xC3, 0xA9}));  // é
    }

    /** The manifest with {@code raw} inserted into its entrypoint, as bytes. */
    private static byte[] withEntrypointBytes(String manifest, int[] raw) {
        String marked = manifest.replaceFirst("\"entrypoint\": \"", "\"entrypoint\": \"\u0001");
        byte[] bytes = marked.getBytes(StandardCharsets.UTF_8);
        int at = indexOf(bytes, (byte) 0x01);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(bytes, 0, at);
        for (int b : raw) {
            out.write(b);
        }
        out.write(bytes, at + 1, bytes.length - at - 1);
        return out.toByteArray();
    }


    @Test
    public void aReferenceToAUrlIsRefusedWithoutAnyRequestBeingMade() throws Exception {
        HttpServer server = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        AtomicInteger requests = new AtomicInteger();
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            byte[] body = "{\"type\": \"string\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            String remote = "http://127.0.0.1:" + server.getAddress().getPort() + "/x.json";
            String schema = "{\"$schema\": \"https://json-schema.org/draft/2020-12/schema\","
                    + " \"$id\": \"urn:test:remote-ref\", \"$ref\": \"" + remote + "\"}";
            var registry = ManifestSchema.registry(Map.of("urn:test:remote-ref", schema));

            assertThrows(RuntimeException.class, () -> registry
                    .getSchema(SchemaLocation.of("urn:test:remote-ref"))
                    .validate(new ObjectMapper().readTree("\"anything\"")));
            // The control: the server answers, so zero requests means none were made rather
            // than that none could have been.
            var control = java.net.http.HttpClient.newHttpClient().send(
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create(remote)).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(200, control.statusCode());
            assertEquals(1, requests.get(), "the validator fetched the remote schema");
        } finally {
            server.stop(0);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static BundleRule ruleOf(String manifest) {
        return assertThrows(BundleRejection.class,
                () -> ManifestSchema.validate(manifest.getBytes(StandardCharsets.UTF_8))).rule();
    }

    private static List<String> names(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    private static byte[] read(String dir, String name) {
        try {
            return Files.readAllBytes(FIXTURES.resolve(dir).resolve(name + ".json"));
        } catch (IOException ex) {
            throw new java.io.UncheckedIOException(ex);
        }
    }

    private static int indexOf(byte[] haystack, byte needle) {
        for (int i = 0; i < haystack.length; i++) {
            if (haystack[i] == needle) {
                return i;
            }
        }
        throw new AssertionError("not found");
    }
}
