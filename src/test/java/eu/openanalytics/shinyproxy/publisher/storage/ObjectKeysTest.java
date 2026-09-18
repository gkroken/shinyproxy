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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The key layout, checked against the plan that fixes it and against hostile paths.
 *
 * <p>The layout table in {@code WORKPLAN-BUNDLES.md} is parsed rather than restated. Two
 * copies of a layout is how the retention policy came to disagree with its own collector
 * for two commits (finding {@code d4f5baf-F1}), and a key layout is worse than a retention
 * policy to get wrong: objects outlive the code that wrote them.
 */
class ObjectKeysTest {

    private static final UUID C = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID U = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final UUID B = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID V = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final UUID R = UUID.fromString("12345678-1234-1234-1234-123456789abc");

    // ---------------------------------------------------------------- the plan's table

    /**
     * Every key template the plan's storage table names, with C/U/B/V/R substituted.
     *
     * <p>Fails if the table cannot be found or yields nothing: a parser that silently
     * matches no rows would make every assertion below pass for free, which is the shape
     * this project has produced at three levels already.
     */
    private List<String> templatesFromThePlan() throws IOException {
        Path plan = Path.of("WORKPLAN-BUNDLES.md");
        assertTrue(Files.exists(plan), "WORKPLAN-BUNDLES.md is the source of this layout "
                + "and was not found; the test cannot check what it cannot read");
        String text = Files.readString(plan, StandardCharsets.UTF_8);

        int start = text.indexOf("### Storage layout and completion protocol");
        assertTrue(start > 0, "the storage layout section is gone from the plan");
        int end = text.indexOf("###", start + 10);
        String section = end > start ? text.substring(start, end) : text.substring(start);

        // The table writes siblings as bare names sharing the previous key's prefix:
        //   | bundles | `v1/content/C/bundles/U/manifest.json`, `inventory.json`, ... |
        // so a row is read in order, a `v1/...` item sets the prefix, and a bare name
        // after it is a sibling under that prefix. Reading only the `v1/` items would
        // silently miss three objects and still look like a working parser.
        List<String> found = new ArrayList<>();
        for (String line : section.split("\n")) {
            if (!line.startsWith("|")) {
                continue;
            }
            String prefix = null;
            Matcher m = Pattern.compile("`([^`]+)`").matcher(line);
            while (m.find()) {
                String item = m.group(1).trim();
                if (item.startsWith("v1/")) {
                    found.add(item);
                    prefix = item.substring(0, item.lastIndexOf('/'));
                } else if (prefix != null && !item.contains("/")) {
                    found.add(prefix + "/" + item);
                }
            }
        }
        assertFalse(found.isEmpty(), "parsed no key templates out of the plan's storage "
                + "table; the pattern has broken and every check below would pass for free");
        return found;
    }

    @Test
    @DisplayName("every key template in the plan's table is produced by this class")
    void everyTemplateIsProduced() throws IOException {
        List<String> produced = List.of(
                ObjectKeys.bundleObject(C, U, ObjectKeys.BUNDLE_ARCHIVE),
                ObjectKeys.bundleObject(C, U, ObjectKeys.BUNDLE_MANIFEST),
                ObjectKeys.bundleObject(C, U, ObjectKeys.BUNDLE_INVENTORY),
                ObjectKeys.bundleObject(C, U, ObjectKeys.BUNDLE_RECEIPT),
                ObjectKeys.logChunk(C, B, 1),
                ObjectKeys.logObject(C, B, ObjectKeys.LOG_INDEX),
                ObjectKeys.logObject(C, B, ObjectKeys.LOG_FINAL),
                ObjectKeys.renditionFile(C, V, R, "report.html"),
                ObjectKeys.renditionDescriptor(C, V, R));

        List<String> expected = new ArrayList<>();
        for (String template : templatesFromThePlan()) {
            expected.add(template
                    .replace("content/C/", "content/" + C + "/")
                    .replace("bundles/U/", "bundles/" + U + "/")
                    .replace("builds/B/", "builds/" + B + "/")
                    .replace("versions/V/", "versions/" + V + "/")
                    .replace("renditions/R/", "renditions/" + R + "/")
                    .replace("<validated-relative-path>", "report.html"));
        }

        for (String want : expected) {
            assertTrue(produced.contains(want),
                    "the plan's table names a key this class does not build: " + want
                            + "\n  built: " + produced);
        }
        assertEquals(expected.size(), produced.size(),
                "this class builds a different number of key shapes than the plan's table "
                        + "names; either the plan gained a key or this class did"
                        + "\n  plan:  " + expected + "\n  built: " + produced);
    }

    // ---------------------------------------------------------------- chunk sequences

    @Test
    @DisplayName("chunk sequences are padded so they sort in replay order")
    void chunksSortLexicographically() {
        String first = ObjectKeys.logChunk(C, B, 1);
        String tenth = ObjectKeys.logChunk(C, B, 10);
        String big = ObjectKeys.logChunk(C, B, ObjectKeys.MAX_SEQUENCE);

        assertTrue(first.endsWith("/000000000001.jsonl"), first);
        assertTrue(first.compareTo(tenth) < 0, "1 must sort before 10");
        assertTrue(tenth.compareTo(big) < 0, "10 must sort before the maximum");

        // The property, not just three examples: ascending sequences must give ascending
        // keys, which is what a reader replaying an index relies on.
        String previous = null;
        for (long seq : new long[]{1, 2, 9, 10, 11, 99, 100, 999, 1000, 123456789L,
                ObjectKeys.MAX_SEQUENCE}) {
            String key = ObjectKeys.logChunk(C, B, seq);
            if (previous != null) {
                assertTrue(previous.compareTo(key) < 0,
                        "sequence " + seq + " sorts before its predecessor: " + key);
            }
            previous = key;
        }
    }

    @Test
    @DisplayName("a sequence outside the padded width is refused, not silently widened")
    void sequenceBoundsAreEnforced() {
        assertThrows(IllegalArgumentException.class, () -> ObjectKeys.logChunk(C, B, 0));
        assertThrows(IllegalArgumentException.class, () -> ObjectKeys.logChunk(C, B, -1));
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.logChunk(C, B, ObjectKeys.MAX_SEQUENCE + 1));
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.logChunk(C, B, Long.MAX_VALUE));
    }

    // ---------------------------------------------------------------- hostile paths

    @Test
    @DisplayName("a rendition path that could address another prefix is refused")
    void hostileRenditionPathsAreRefused() {
        String[] hostile = {
                "../escape.txt",
                "a/../../escape.txt",
                "..",
                ".",
                "./report.html",
                "a/./b.html",
                "/etc/passwd",
                "a//b.html",
                "a/",
                "",
                "dir\\file.html",
                "report\u0000.html",
                "report\nname.html",
                "report\rname.html",
                "tab\there.html",
        };
        for (String path : hostile) {
            assertThrows(IllegalArgumentException.class,
                    () -> ObjectKeys.renditionFile(C, V, R, path),
                    "accepted a hostile rendition path: " + quoted(path));
        }
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.renditionFile(C, V, R, "a".repeat(1025)));
    }

    @Test
    @DisplayName("the assembled KEY is bounded, not just the path")
    void assembledKeyStaysWithinTheStorageLimit() {
        // 2b483fb-F1. The schema's limit is on the path and spends the whole budget on it;
        // the store's limit is on the key and counts UTF-8 bytes. Measured on the parent:
        // 1024 ASCII chars produced a 1172-byte key and 400 Japanese characters a 1348-byte
        // one, both accepted.
        assertEquals(148, ObjectKeys.RENDITION_PREFIX_BYTES,
                "the rendition prefix changed width; the path budget below is derived from "
                        + "it and every bound in this test moves with it");
        assertEquals(ObjectKeys.MAX_KEY_BYTES - ObjectKeys.RENDITION_PREFIX_BYTES,
                ObjectKeys.MAX_RENDITION_PATH_BYTES);

        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.renditionFile(C, V, R, "a".repeat(1024)),
                "a path the SCHEMA allows still produced an over-length key");
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.renditionFile(C, V, R, "\u65e5".repeat(400)),
                "400 multi-byte characters are inside 1024 chars but over the byte budget");

        // The boundary, both halves, in bytes rather than characters.
        String atLimit = "a".repeat(ObjectKeys.MAX_RENDITION_PATH_BYTES);
        String key = ObjectKeys.renditionFile(C, V, R, atLimit);
        assertEquals(ObjectKeys.MAX_KEY_BYTES, key.getBytes(StandardCharsets.UTF_8).length,
                "a path at the budget must produce a key exactly at the limit");
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.renditionFile(C, V, R, "a".repeat(
                        ObjectKeys.MAX_RENDITION_PATH_BYTES + 1)));

        // And a multi-byte path at the same BYTE budget, which has far fewer characters.
        String jp = "\u65e5".repeat(ObjectKeys.MAX_RENDITION_PATH_BYTES / 3);
        assertEquals(ObjectKeys.MAX_KEY_BYTES,
                ObjectKeys.renditionFile(C, V, R, jp).getBytes(StandardCharsets.UTF_8).length);
    }

    @Test
    @DisplayName("a path that is not NFC is refused, not silently normalised")
    void nonNfcPathsAreRefused() {
        // 2b483fb-F2. The plan says "Reject, rather than normalize away" -- normalising
        // rewrites a publisher's filename, and a descriptor naming the original would then
        // not describe the object that exists.
        String nfc = Normalizer.normalize("r\u00e9sum\u00e9.pdf", Normalizer.Form.NFC);
        String nfd = Normalizer.normalize("r\u00e9sum\u00e9.pdf", Normalizer.Form.NFD);
        assertFalse(nfc.equals(nfd), "the fixture is not exercising two normalisations");

        String key = ObjectKeys.renditionFile(C, V, R, nfc);
        assertTrue(key.endsWith("/files/" + nfc), "NFC must pass through untouched");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.renditionFile(C, V, R, nfd),
                "NFD was accepted, so one filename is two objects in one rendition");
        assertTrue(e.getMessage().contains("NFC"), e.getMessage());

        // Not rewritten into NFC on the way through, which would be the other failure.
        assertFalse(ObjectKeys.validatedRenditionPath(nfc).equals(nfd));
    }

    @Test
    @DisplayName("case collisions are NOT this class's to refuse, and it says so")
    void caseCollisionsAreLeftToTheFileListOwner() {
        // Deliberately asserting the gap rather than leaving it undocumented. Two paths
        // collide only relative to each other, so a per-path validator cannot decide it;
        // the obligation belongs to whatever assembles a rendition's complete file list.
        // If that ever moves here, this test fails and names what has to change.
        String upper = ObjectKeys.renditionFile(C, V, R, "Report.html");
        String lower = ObjectKeys.renditionFile(C, V, R, "report.html");
        assertFalse(upper.equals(lower),
                "case is preserved, so these are two distinct keys");
        assertTrue(upper.endsWith("/Report.html") && lower.endsWith("/report.html"),
                "case must be preserved, never folded");
    }

    @Test
    @DisplayName("names needing URL encoding are carried literally, not encoded here")
    void awkwardNamesSurviveLiterally() {
        // The same set T1(b) pinned for the descriptor. Encoding belongs at the HTTP
        // boundary; a key that arrives already percent-encoded is a different object.
        String[] awkward = {
                "a file with spaces.html",
                "100%.html",
                "100%25.html",
                "r\u00e9sum\u00e9.pdf",
                "\u65e5\u672c\u8a9e/\u30da\u30fc\u30b8.html",
                "plus+and&amp.html",
                "quote'apostrophe.html",
                "hash#fragment.html",
        };
        for (String name : awkward) {
            String key = ObjectKeys.renditionFile(C, V, R, name);
            assertTrue(key.endsWith("/files/" + name),
                    "name was altered on its way into the key: " + quoted(name)
                            + " produced " + key);
            assertFalse(key.contains("%25") && !name.contains("%25"),
                    "the key looks percent-encoded, which this layer must not do: " + key);
        }
    }

    @Test
    @DisplayName("a path this class accepts is one the released schema also accepts")
    void acceptedPathsSatisfyTheReleasedSchema() throws IOException {
        // The schema leaves containment to the writer, so this class must be STRICTER --
        // never more permissive. A path we accept but the descriptor schema rejects would
        // write an object that its own descriptor cannot describe.
        Path schema = Path.of("schemas/output-descriptor/v1.schema.json");
        assertTrue(Files.exists(schema), "the released descriptor schema was not found");
        String text = Files.readString(schema, StandardCharsets.UTF_8);

        Matcher m = Pattern.compile("\"renditionPath\"\\s*:\\s*\\{.*?\"pattern\"\\s*:\\s*\"(.*?)\"",
                Pattern.DOTALL).matcher(text);
        assertTrue(m.find(), "could not read renditionPath's pattern out of the schema; "
                + "without it this test would assert nothing");
        String json = m.group(1);
        // JSON escaping -> Java regex source.
        String regex = json.replace("\\\\", "\\").replace("\\u0000", "\u0000");
        Pattern schemaPattern = Pattern.compile(regex);

        String[] accepted = {
                "report.html", "a/b/c.txt", "a file with spaces.html",
                "r\u00e9sum\u00e9.pdf", "100%.html", "plus+and&amp.html",
        };
        for (String path : accepted) {
            ObjectKeys.validatedRenditionPath(path);
            assertTrue(schemaPattern.matcher(path).matches(),
                    "this class accepts a path the released schema rejects: " + quoted(path));
        }

        // And the converse direction, which is the one that matters: the schema accepts
        // these and we must not, because it says so in its own description.
        for (String leftToTheWriter : new String[]{"../escape.txt", "a/./b", "a//b", "."}) {
            assertTrue(schemaPattern.matcher(leftToTheWriter).matches(),
                    "the schema is expected to accept " + quoted(leftToTheWriter)
                            + " and leave it to the writer; if that changed, this test's "
                            + "premise is stale");
            try {
                ObjectKeys.validatedRenditionPath(leftToTheWriter);
                fail("this class accepted " + quoted(leftToTheWriter)
                        + ", which the schema explicitly leaves to the writer to refuse");
            } catch (IllegalArgumentException expected) {
                // the writer refused it, which is the contract
            }
        }
    }

    // ---------------------------------------------------------------- identifiers

    @Test
    @DisplayName("an unknown object name is refused rather than invented")
    void unknownObjectNamesAreRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.bundleObject(C, U, "bundle.zip"));
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.bundleObject(C, U, "../receipt.json"));
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.logObject(C, B, "chunks/1.jsonl"));
        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.bundleObject(null, U, ObjectKeys.BUNDLE_RECEIPT));
    }

    @Test
    @DisplayName("UUIDs appear in one spelling, because a key is case-sensitive")
    void uuidsAreLowerCased() {
        UUID upper = UUID.fromString("ABCDEF01-2345-6789-ABCD-EF0123456789");
        String key = ObjectKeys.bundleObject(upper, U, ObjectKeys.BUNDLE_RECEIPT);
        assertTrue(key.contains("abcdef01-2345-6789-abcd-ef0123456789"), key);
        assertFalse(key.contains("ABCDEF01"), "an upper-case UUID would be a second object: " + key);
    }

    private static String quoted(String value) {
        return "'" + value.replace("\n", "\\n").replace("\r", "\\r").replace("\u0000", "\\0") + "'";
    }
}
