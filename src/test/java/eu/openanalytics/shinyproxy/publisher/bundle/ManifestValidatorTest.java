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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S1-S9 against the fixtures T1 froze and the table in the plan that assigns them.
 */
public class ManifestValidatorTest {

    private static final Path FIXTURES = Path.of("dev/fixtures/manifests");
    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    public void everySemanticFixtureIsRefusedByTheRuleThePlanAssignsIt() throws IOException {
        // The plan's semantic-validation table names, per rule, the fixtures that rule owns.
        // Read from the table rather than restated here, so the plan and the validator
        // cannot drift: a fixture moved to another rule in one is a failure in the other.
        Map<String, String> ruleOfFixture = planTable();
        List<String> semantic = names(expectations().path("semantic_invalid"));
        assertEquals(new java.util.TreeSet<>(semantic), ruleOfFixture.keySet(),
                "the plan's table and the semantic_invalid list name different fixtures");

        List<String> wrong = new ArrayList<>();
        for (String name : semantic) {
            String expected = ruleOfFixture.get(name) + ": ";
            try {
                ManifestValidator.validate(read("invalid", name), LIMITS);
                wrong.add(name + " ACCEPTED, expected " + expected);
            } catch (BundleRejection ex) {
                if (!ex.getMessage().contains(": " + expected)) {
                    wrong.add(name + " refused as '" + ex.getMessage() + "', expected "
                            + expected);
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    public void everyValidFixtureIsAcceptedAndReadBackExactly() throws IOException {
        for (String name : names(expectations().path("valid"))) {
            byte[] bytes = read("valid", name);
            ManifestValidator.Manifest manifest = ManifestValidator.validate(bytes, LIMITS,
                    Optional.of("shiny"));
            JsonNode doc = JSON.readTree(bytes);
            assertEquals(doc.path("files").size(), manifest.files().size(), name);
            assertEquals(doc.path("entrypoint").asText(), manifest.entrypoint(), name);
            JsonNode first = doc.path("files").get(0);
            ManifestValidator.Declared declared = manifest.files().get(first.path("path").asText());
            assertEquals(first.path("size").asLong(), declared.size(), name);
            assertEquals(first.path("sha256").asText(), declared.sha256(), name);
        }
    }

    @Test
    public void aSizeIsAnExactWholeNumberOrItIsRefused() {
        // Recorded in 04e3d93's review: 2020-12's "integer" admits all three, and asLong()
        // wraps the 23-digit one to its low 64 bits.
        assertEquals(64, sizeOf("64.0"), "64.0 is the integer 64 under the schema's dialect");
        // 2^64 + 12 first. asLong() wraps it to 12, a size nothing else would refuse, which
        // is the case this rule exists for. The others would also be caught by the per-file
        // limit if read wrongly (the 23-digit one wraps to about 2e17), so on their own they
        // could not tell a correct reading from a wrapped one.
        for (String literal : List.of("18446744073709551628", "99999999999999999999999",
                "1e20", "9223372036854775808")) {
            BundleRejection ex = assertThrows(BundleRejection.class, () -> sizeOf(literal));
            assertEquals(BundleRule.MANIFEST_SIZE_INVALID, ex.rule(), literal);
        }
        assertEquals(12, sizeOf("12"));
    }

    @Test
    public void anUnpairedSurrogateCannotStandInForAnyCharacter() {
        // 0573fc2's review: "\ud800" passes the strict decode and the schema, and getBytes
        // would turn it into '?' -- matching a real member named with a '?'.
        for (String escaped : List.of("\\ud800", "\\udfff", "\\ud800x")) {
            String manifest = text("r-root-single-file")
                    .replace("\"app.R\"", "\"a" + escaped + "pp.R\"");
            BundleRejection ex = assertThrows(BundleRejection.class, () ->
                    ManifestValidator.validate(manifest.getBytes(StandardCharsets.UTF_8), LIMITS));
            assertEquals(BundleRule.MANIFEST_NOT_JSON, ex.rule(), escaped);
            assertTrue(ex.getMessage().contains("surrogate"), ex.getMessage());
        }
        String entrypoint = text("python-root").replace("\"entrypoint\": \"app.py\"",
                "\"entrypoint\": \"\\ud800app.py\"");
        assertEquals(BundleRule.MANIFEST_NOT_JSON, assertThrows(BundleRejection.class, () ->
                ManifestValidator.validate(entrypoint.getBytes(StandardCharsets.UTF_8), LIMITS))
                .rule());
        // A proper pair is one real code point, and a real file name.
        String pair = text("r-with-assets").replaceFirst("\"www/", "\"www/\\ud83d\\ude00");
        ManifestValidator.validate(pair.getBytes(StandardCharsets.UTF_8), LIMITS);
    }

    @Test
    public void pathsAreJudgedExactlyAsArchiveMembersAre() {
        // S2 through MemberPath: a decomposed name is refused, as it would be in the archive,
        // rather than normalised into a different name than the one declared.
        assertRule(BundleRule.MANIFEST_PATH_NOT_CANONICAL, "S2", withFile("cafe\u0301.txt"));
        assertRule(BundleRule.MANIFEST_PATH_NOT_CANONICAL, "S2", withFile("a//b.txt"));
        assertRule(BundleRule.MANIFEST_PATH_NOT_CANONICAL, "S2",
                withFile("s".repeat((int) LIMITS.maxSegmentBytes() + 1)));
        assertRule(BundleRule.MANIFEST_PATH_ESCAPES, "S1", withFile("www/../../x"));
        // S3 on the archive's own folding key.
        assertRule(BundleRule.MANIFEST_PATH_DUPLICATE, "S3", withFile("App.R"));
        // The lockfile and the entrypoint are paths too.
        assertRule(BundleRule.MANIFEST_PATH_ESCAPES, "S1", edit("r-root-single-file",
                doc -> ((ObjectNode) doc.path("dependencies")).put("path", "../renv.lock")));
        assertRule(BundleRule.MANIFEST_PATH_NOT_CANONICAL, "S2", edit("python-root",
                doc -> ((ObjectNode) doc).put("entrypoint", "src/./app.py")));
        // Controls: the same fixture with an ordinary extra file, and a composed é, pass.
        ManifestValidator.validate(withFile("caf\u00e9.txt"), LIMITS);
    }

    @Test
    public void theTargetTypeIsCheckedOnlyWhenThereIsOne() {
        byte[] shiny = read("valid", "r-root-single-file");
        assertRule(BundleRule.MANIFEST_TYPE_MISMATCH, "S9", shiny, Optional.of("plumber"));
        ManifestValidator.validate(shiny, LIMITS, Optional.of("shiny"));
        ManifestValidator.validate(shiny, LIMITS);
    }

    @Test
    public void declaredSizesThatBreakALimitAreRefusedBeforeAByteIsRead() {
        ExtractionLimits small = ExtractionLimits.fromOverrides(Map.of(
                "max_file_bytes", "100", "max_expanded_bytes", "150", "max_entries", "3"));
        byte[] base = read("valid", "r-root-single-file");     // app.R and renv.lock
        assertEquals(BundleRule.ENTRY_TOO_LARGE, ruleOf(edit(base,
                doc -> ((ObjectNode) doc.path("files").get(0)).put("size", 101)), small));
        assertEquals(BundleRule.ARCHIVE_TOO_LARGE_EXPANDED, ruleOf(edit(base, doc -> {
            ((ObjectNode) doc.path("files").get(0)).put("size", 100);
            ((ObjectNode) doc.path("files").get(1)).put("size", 51);
        }), small));
        assertEquals(BundleRule.ENTRY_COUNT_EXCEEDED, ruleOf(edit(base, doc -> {
            ArrayNode files = (ArrayNode) doc.path("files");
            files.add(entry("a.txt"));
            files.add(entry("b.txt"));
        }), small));
        // At the limits exactly: accepted.
        ManifestValidator.validate(edit(base, doc -> {
            ((ObjectNode) doc.path("files").get(0)).put("size", 100);
            ((ObjectNode) doc.path("files").get(1)).put("size", 50);
            ((ArrayNode) doc.path("files")).add(entry("c.txt"));
        }), small);
    }

    // ------------------------------------------------------------------ helpers

    /** Fixture name -> S-number, from the table in WORKPLAN-BUNDLES.md. */
    private static Map<String, String> planTable() throws IOException {
        Map<String, String> out = new TreeMap<>();
        Pattern row = Pattern.compile("^\\| (S\\d+) \\|.*\\| ([^|]*) \\|$");
        Pattern name = Pattern.compile("`([a-z0-9-]+)`");
        for (String line : Files.readAllLines(Path.of("WORKPLAN-BUNDLES.md"))) {
            Matcher m = row.matcher(line);
            if (m.matches()) {
                Matcher n = name.matcher(m.group(2));
                while (n.find()) {
                    out.put(n.group(1), m.group(1));
                }
            }
        }
        assertFalse(out.isEmpty(), "the plan's S-table was not found");
        return out;
    }

    private static JsonNode expectations() throws IOException {
        return JSON.readTree(FIXTURES.resolve("expectations.json").toFile());
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

    private static String text(String valid) {
        return new String(read("valid", valid), StandardCharsets.UTF_8);
    }

    private static long sizeOf(String literal) {
        String manifest = text("r-root-single-file")
                .replaceFirst("\"size\": [0-9]+", "\"size\": " + literal);
        ManifestValidator.Manifest m = ManifestValidator.validate(
                manifest.getBytes(StandardCharsets.UTF_8), LIMITS);
        return m.files().values().iterator().next().size();
    }

    private static ObjectNode entry(String path) {
        return JSON.createObjectNode().put("path", path).put("size", 0)
                .put("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    private static byte[] withFile(String path) {
        return edit("r-root-single-file", doc -> ((ArrayNode) doc.path("files")).add(entry(path)));
    }

    private static byte[] edit(String valid, Consumer<JsonNode> change) {
        return edit(read("valid", valid), change);
    }

    private static byte[] edit(byte[] manifest, Consumer<JsonNode> change) {
        try {
            JsonNode doc = JSON.readTree(manifest);
            change.accept(doc);
            return JSON.writeValueAsBytes(doc);
        } catch (IOException ex) {
            throw new java.io.UncheckedIOException(ex);
        }
    }

    private static BundleRule ruleOf(byte[] manifest, ExtractionLimits limits) {
        return assertThrows(BundleRejection.class,
                () -> ManifestValidator.validate(manifest, limits)).rule();
    }

    private static void assertRule(BundleRule rule, String sNumber, byte[] manifest) {
        assertRule(rule, sNumber, manifest, Optional.empty());
    }

    private static void assertRule(BundleRule rule, String sNumber, byte[] manifest,
                                   Optional<String> target) {
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> ManifestValidator.validate(manifest, LIMITS, target));
        assertEquals(rule, ex.rule(), ex.getMessage());
        assertTrue(ex.getMessage().contains(": " + sNumber + ": "), ex.getMessage());
    }
}
