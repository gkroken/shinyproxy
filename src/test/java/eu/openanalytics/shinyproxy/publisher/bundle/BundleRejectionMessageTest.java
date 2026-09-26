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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A rejection's message is printable ASCII whatever name it reports (t5-e5e3071-F2).
 *
 * <p>The message goes to logs, to the publisher and to terminals, and the names in it are
 * attacker-chosen. The gate's probes put a raw U+202E and a raw U+0085 into three rules'
 * messages through the real extractor. Each case here drives a real entry point (the
 * extractor, the manifest validator or the member parser) with a hostile name, and
 * requires two things. The message must be printable ASCII. For a name that is printable
 * text, only not ASCII, the escaped name must also appear, so a case cannot pass by being
 * refused somewhere that never quoted the name at all.
 */
public class BundleRejectionMessageTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();
    private static final byte[] BYTES = "abc".getBytes(StandardCharsets.UTF_8);
    private static final String E_ACUTE = "\u00e9";
    private static final String E_ACUTE_RENDERED = "\\xc3\\xa9";

    @Test
    public void theConstructorEscapesWhateverItIsGiven() {
        // C0, DEL, C1 (NEL and CSI), bidi override, BOM, line separator, a letter outside
        // ASCII, and a supplementary-plane character. Nothing of it may survive raw.
        String hostile = "a\u0007\n\u007f\u0085\u009b\u202e\ufeff\u2028" + E_ACUTE
                + new String(Character.toChars(0x1F600)) + "\\z";
        BundleRejection ex = new BundleRejection(BundleRule.PATH_TRAVERSAL, hostile);
        assertPrintable(ex);
        assertEquals("PATH_TRAVERSAL: a\\x07\\x0a\\x7f\\xc2\\x85\\xc2\\x9b\\xe2\\x80\\xae"
                + "\\xef\\xbb\\xbf\\xe2\\x80\\xa8\\xc3\\xa9\\xf0\\x9f\\x98\\x80\\z",
                ex.getMessage(), "one \\xNN per UTF-8 byte, as render() spells it; a"
                        + " backslash already in the text is left as it is");
    }

    @Test
    public void everyExtractorRuleThatQuotesANameEscapesIt(@TempDir Path workspace)
            throws Exception {
        Map<String, byte[]> payload = TarArchives.shinyPayload();

        // S11, the gate's s11-rtl and s11-nel: a member the manifest does not list.
        refused(workspace, TarArchives.bundle(payload).file("app/ok\u202etxt.R", BYTES));
        refused(workspace, TarArchives.bundle(payload).file("app/ok\u0085FAKE.R", BYTES));
        quoted(workspace, TarArchives.bundle(payload).file("app/caf" + E_ACUTE + ".txt", BYTES),
                BundleRule.INVENTORY_UNDECLARED_FILE, "caf" + E_ACUTE_RENDERED + ".txt");

        // S10: declared "cafe.txt" at 3 bytes, delivered with 4.
        Map<String, byte[]> declared = new LinkedHashMap<>(payload);
        declared.put("caf" + E_ACUTE + ".txt", BYTES);
        quoted(workspace, TarArchives.archive()
                        .file("manifest.json", TarArchives.manifestFor(declared))
                        .file("app/app.R", payload.get("app.R"))
                        .file("app/renv.lock", payload.get("renv.lock"))
                        .file("app/caf" + E_ACUTE + ".txt", "abcd".getBytes(StandardCharsets.UTF_8)),
                BundleRule.INVENTORY_SIZE_MISMATCH, "caf" + E_ACUTE_RENDERED + ".txt");

        // MemberPath's rules that quote the decoded text (trav-nel is the gate's third).
        refused(workspace, TarArchives.bundle(payload).file("app/\u0085/../x", BYTES));
        quoted(workspace, TarArchives.bundle(payload).file("app/" + E_ACUTE + "/../x", BYTES),
                BundleRule.PATH_TRAVERSAL, E_ACUTE_RENDERED + "/../x");
        quoted(workspace, TarArchives.bundle(payload).file("app/" + E_ACUTE + "/./x", BYTES),
                BundleRule.PATH_DOT_SEGMENT, E_ACUTE_RENDERED + "/./x");
        quoted(workspace, TarArchives.bundle(payload).file("app/" + E_ACUTE + "//x", BYTES),
                BundleRule.PATH_EMPTY_SEGMENT, E_ACUTE_RENDERED + "//x");
        quoted(workspace, TarArchives.bundle(payload).file("/" + E_ACUTE + "tc/x", BYTES),
                BundleRule.PATH_ABSOLUTE, "/" + E_ACUTE_RENDERED + "tc/x");
        quoted(workspace, TarArchives.bundle(payload).file(E_ACUTE + "vil.txt", BYTES),
                BundleRule.LAYOUT_UNEXPECTED_MEMBER, E_ACUTE_RENDERED + "vil.txt");
        quoted(workspace, TarArchives.bundle(payload).file("app/" + E_ACUTE + ".txt/", BYTES),
                BundleRule.PATH_TRAILING_SLASH, E_ACUTE_RENDERED + ".txt/");

        // MemberIndex: the same name twice.
        Map<String, byte[]> twice = new LinkedHashMap<>(payload);
        twice.put(E_ACUTE + ".txt", BYTES);
        quoted(workspace, TarArchives.bundle(twice).file("app/" + E_ACUTE + ".txt", BYTES),
                BundleRule.DUPLICATE_MEMBER, E_ACUTE_RENDERED + ".txt");
    }

    @Test
    public void everyManifestRuleThatQuotesAPathEscapesIt() {
        // S2 with NEL: 80f5f4c's review showed the S2 prefix quoting the path raw while
        // the member half, from MemberPath, was rendered.
        manifestRefused(doc -> files(doc).add(entry("spl\u0085it.R")));
        manifestRefused(doc -> ((ObjectNode) doc.path("dependencies"))
                .put("path", "a\u202e.lock"));
        manifestQuoted(doc -> files(doc).add(entry(E_ACUTE + "/../x")),
                BundleRule.MANIFEST_PATH_ESCAPES, E_ACUTE_RENDERED + "/../x");
        // S3: two paths equal under case folding.
        manifestQuoted(doc -> {
            files(doc).add(entry("\u00c9.txt"));
            files(doc).add(entry(E_ACUTE + ".txt"));
        }, BundleRule.MANIFEST_PATH_DUPLICATE, E_ACUTE_RENDERED + ".txt");
        // S6: a lockfile path that is not in files.
        manifestQuoted(doc -> ((ObjectNode) doc.path("dependencies"))
                        .put("path", E_ACUTE + ".lock"),
                BundleRule.MANIFEST_LOCKFILE_NOT_IN_INVENTORY, E_ACUTE_RENDERED + ".lock");
        // S5: an R entrypoint directory with no app in it.
        manifestQuoted(doc -> ((ObjectNode) doc).put("entrypoint", E_ACUTE),
                null, "'" + E_ACUTE_RENDERED + "'");
    }

    @Test
    public void bytesThatAreNotUtf8AreEscapedToo() {
        byte[] name = {'a', 'p', 'p', '/', (byte) 0xff, (byte) 0xc2, '.', 'R'};
        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> MemberPath.parse(name, false, LIMITS));
        assertPrintable(ex);
        assertTrue(ex.getMessage().contains("app/\\xff\\xc2.R"), ex.getMessage());
    }

    // ------------------------------------------------------------------ helpers

    private static void refused(Path workspace, TarArchives archive) throws IOException {
        assertPrintable(extract(workspace, archive));
    }

    private static void quoted(Path workspace, TarArchives archive, BundleRule rule,
                               String rendered) throws IOException {
        BundleRejection ex = extract(workspace, archive);
        assertPrintable(ex);
        assertEquals(rule, ex.rule(), ex.getMessage());
        assertTrue(ex.getMessage().contains(rendered),
                "the name should appear escaped as '" + rendered + "': " + ex.getMessage());
    }

    private static BundleRejection extract(Path workspace, TarArchives archive)
            throws IOException {
        byte[] upload = gzip(archive.end());
        try {
            BundleExtractor.extract(new ByteArrayInputStream(upload), upload.length, workspace,
                    LIMITS).root().close();
        } catch (BundleRejection ex) {
            return ex;
        }
        return fail("accepted a bundle this case expects refused");
    }

    private static void manifestRefused(Consumer<ObjectNode> change) {
        assertPrintable(validate(change));
    }

    private static void manifestQuoted(Consumer<ObjectNode> change, BundleRule rule,
                                       String rendered) {
        BundleRejection ex = validate(change);
        assertPrintable(ex);
        if (rule != null) {
            assertEquals(rule, ex.rule(), ex.getMessage());
        }
        assertTrue(ex.getMessage().contains(rendered),
                "the path should appear escaped as '" + rendered + "': " + ex.getMessage());
    }

    private static BundleRejection validate(Consumer<ObjectNode> change) {
        ObjectMapper json = new ObjectMapper();
        try {
            ObjectNode doc = (ObjectNode) json.readTree(
                    TarArchives.manifestFor(TarArchives.shinyPayload()));
            change.accept(doc);
            byte[] manifest = json.writeValueAsBytes(doc);
            return assertThrows(BundleRejection.class,
                    () -> ManifestValidator.validate(manifest, LIMITS));
        } catch (IOException ex) {
            throw new java.io.UncheckedIOException(ex);
        }
    }

    private static ArrayNode files(ObjectNode doc) {
        return (ArrayNode) doc.path("files");
    }

    private static ObjectNode entry(String path) {
        return new ObjectMapper().createObjectNode().put("path", path).put("size", 3)
                .put("sha256", TarArchives.sha256(BYTES));
    }

    private static void assertPrintable(BundleRejection ex) {
        String message = ex.getMessage();
        for (int i = 0; i < message.length(); i++) {
            char c = message.charAt(i);
            if (c < 0x20 || c >= 0x7F) {
                fail(String.format("%s: U+%04X at %d is not printable ASCII: %s", ex.rule(),
                        (int) c, i, message.codePoints().mapToObj(cp -> cp >= 0x20 && cp < 0x7F
                                ? Character.toString(cp) : String.format("<U+%04X>", cp))
                        .collect(java.util.stream.Collectors.joining())));
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
}
