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
package eu.openanalytics.shinyproxy.publisher.recipe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.openanalytics.shinyproxy.publisher.recipe.LockRejection.Reason;
import eu.openanalytics.shinyproxy.publisher.recipe.RenvLockPolicy.RenvLock;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The R lockfile policy against a real renv.lock (generated through forge for the R Shiny
 * fixture app) and against that same lock with one thing made hostile at a time, so each
 * refusal is shown on an otherwise valid document.
 */
public class RenvLockPolicyTest {

    private static final Path FIXTURE = Path.of("dev/fixtures/apps/r-shiny/renv.lock");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final URI MIRROR = URI.create("http://mirror.invalid/repository/cran-public/");

    @Test
    public void theRealFixtureLockIsAcceptedAndReadExactly() throws IOException {
        RenvLock lock = RenvLockPolicy.check(fixture(), "4.6.1");
        JsonNode doc = JSON.readTree(fixture());
        assertEquals(doc.path("Packages").size(), lock.packages().size());
        assertEquals(46, lock.packages().size());
        assertEquals("1.14.0", lock.packages().get("shiny"));
        assertEquals("4.6.1", lock.rVersion());
    }

    @Test
    public void theRenderingCarriesOnlyWhatARestoreNeedsAndTheServersMirror() throws IOException {
        RenvLock lock = RenvLockPolicy.check(fixture(), "4.6.1");
        byte[] rendered = lock.render(MIRROR);
        JsonNode doc = JSON.readTree(rendered);
        assertEquals(List.of("R", "Packages"), names(doc));
        assertEquals(List.of("Version", "Repositories"), names(doc.path("R")));
        assertEquals(1, doc.path("R").path("Repositories").size());
        assertEquals(MIRROR.toString(), doc.path("R").path("Repositories").get(0).path("URL").asText());
        for (JsonNode record : doc.path("Packages")) {
            assertEquals(List.of("Package", "Version", "Source", "Repository"), names(record));
        }
        String text = new String(rendered, StandardCharsets.UTF_8);
        // The upload's own repository URL, and a DESCRIPTION field one package carries that
        // names other repositories, are both gone.
        assertTrue(new String(fixture(), StandardCharsets.UTF_8).contains("localhost:18082"));
        assertTrue(new String(fixture(), StandardCharsets.UTF_8).contains("Additional_repositories"));
        assertFalse(text.contains("localhost:18082"));
        assertFalse(text.contains("Additional_repositories"));
        // And it is itself an accepted lock with the same content.
        assertEquals(lock, RenvLockPolicy.check(rendered, "4.6.1"));
    }

    @Test
    public void theMirrorMustBeAnAbsoluteHttpUrl() throws IOException {
        RenvLock lock = RenvLockPolicy.check(fixture(), "4.6.1");
        for (String bad : List.of("file:///srv/cran", "ftp://mirror/", "mirror/cran")) {
            assertThrows(IllegalArgumentException.class, () -> lock.render(URI.create(bad)), bad);
        }
    }

    @Test
    public void everyNonCranSourceIsRefusedByName() {
        List<String> wrong = new ArrayList<>();
        for (String source : List.of("GitHub", "GitLab", "Bitbucket", "git", "URL", "Local",
                "Bioconductor", "unknown")) {
            expect(wrong, "Source " + source, Reason.NOT_FROM_REPOSITORY,
                    m -> pkg(m, "shiny").put("Source", source));
        }
        for (String repository : List.of("RSPM", "P3M", "BioCsoft", "https://evil.invalid/cran")) {
            expect(wrong, "Repository " + repository, Reason.NOT_FROM_REPOSITORY,
                    m -> pkg(m, "httpuv").put("Repository", repository));
        }
        // A Remote* field on an otherwise CRAN-looking record: how renv records a package
        // installed from GitHub, kept even when Source is edited.
        for (String field : List.of("RemoteType", "RemoteUrl", "RemoteSha", "RemoteRepos",
                "RemoteHost")) {
            expect(wrong, field, Reason.NOT_FROM_REPOSITORY,
                    m -> pkg(m, "later").put(field, "https://github.com/evil/later"));
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    public void everyOtherRuleRefusesWithItsReason() {
        List<String> wrong = new ArrayList<>();
        expect(wrong, "a Bioconductor section", Reason.UNKNOWN_FIELD,
                m -> m.putObject("Bioconductor").put("Version", "3.20"));
        expect(wrong, "a Python section", Reason.UNKNOWN_FIELD,
                m -> m.putObject("Python").put("Version", "3.13"));
        expect(wrong, "an unknown R field", Reason.UNKNOWN_FIELD,
                m -> ((ObjectNode) m.get("R")).put("Bootstrap", "https://evil.invalid/b.R"));
        expect(wrong, "another R version", Reason.RUNTIME_MISMATCH,
                m -> ((ObjectNode) m.get("R")).put("Version", "4.5.0"));
        expect(wrong, "no R section", Reason.SYNTAX, m -> m.remove("R"));
        expect(wrong, "no Packages", Reason.SYNTAX, m -> m.remove("Packages"));
        expect(wrong, "Repositories not an array", Reason.SYNTAX,
                m -> ((ObjectNode) m.get("R")).put("Repositories", "CRAN"));
        expect(wrong, "a record not an object", Reason.SYNTAX,
                m -> ((ObjectNode) m.get("Packages")).put("mime", "0.13"));
        expect(wrong, "a version that is not a string", Reason.SYNTAX,
                m -> pkg(m, "mime").put("Version", 13));
        expect(wrong, "no version", Reason.SYNTAX, m -> pkg(m, "mime").remove("Version"));
        expect(wrong, "a key unlike its Package", Reason.BAD_NAME,
                m -> pkg(m, "mime").put("Package", "evil"));
        expect(wrong, "a traversal name", Reason.BAD_NAME, m -> rename(m, "mime", "../mime"));
        expect(wrong, "a one-letter name", Reason.BAD_NAME, m -> rename(m, "mime", "m"));
        expect(wrong, "a name with a trailing dot", Reason.BAD_NAME, m -> rename(m, "mime", "mime."));
        for (String version : List.of("latest", "1", "1.0.*", ">= 1.0", "1..0", "1.0 ", "")) {
            expect(wrong, "version '" + version + "'", Reason.NOT_PINNED,
                    m -> pkg(m, "mime").put("Version", version));
        }
        expect(wrong, "no shiny", Reason.FRAMEWORK_MISSING,
                m -> ((ObjectNode) m.get("Packages")).remove("shiny"));
        assertEquals(List.of(), wrong);
    }

    @Test
    public void malformedDocumentsAreRefusedAsSyntax() {
        String good = new String(fixture(), StandardCharsets.UTF_8);
        List<String> wrong = new ArrayList<>();
        // A duplicate key is the classic parser-differential: the last one wins in jsonlite.
        String duplicate = good.replaceFirst("\"Packages\": \\{",
                "\"Packages\": {\n    \"shiny\": {\"Package\": \"shiny\", \"Version\": \"0.1\","
                + " \"Source\": \"GitHub\", \"Repository\": \"CRAN\"},");
        assertTrue(!duplicate.equals(good));
        for (var c : List.of(
                List.of("duplicate key", duplicate),
                List.of("trailing tokens", good + "{}"),
                List.of("a comment", "// x\n" + good),
                List.of("an array", "[]"),
                List.of("a scalar", "1"),
                List.of("empty", ""),
                List.of("truncated", good.substring(0, good.length() / 2)))) {
            try {
                RenvLockPolicy.check(c.get(1).getBytes(StandardCharsets.UTF_8), "4.6.1");
                wrong.add(c.get(0) + ": ACCEPTED");
            } catch (LockRejection e) {
                if (e.reason() != Reason.SYNTAX) {
                    wrong.add(c.get(0) + ": " + e.getMessage());
                }
            }
        }
        // A lone 0xC0 in place of a title's first letter: not UTF-8 at all.
        byte[] invalidUtf8 = fixture();
        invalidUtf8[good.indexOf("\"Title\": \"") + 10] = (byte) 0xC0;
        LockRejection e = assertThrows(LockRejection.class,
                () -> RenvLockPolicy.check(invalidUtf8, "4.6.1"));
        assertEquals(Reason.SYNTAX, e.reason(), e.getMessage());
        assertEquals(List.of(), wrong);
    }

    @Test
    public void sizeLimitsAreEnforced() {
        LockRejection bytes = assertThrows(LockRejection.class, () -> RenvLockPolicy.check(
                new byte[RenvLockPolicy.MAX_BYTES + 1], "4.6.1"));
        assertEquals(Reason.TOO_LARGE, bytes.reason());
        LockRejection count = assertThrows(LockRejection.class, () -> RenvLockPolicy.check(
                mutate(m -> {
                    ObjectNode packages = (ObjectNode) m.get("Packages");
                    for (int i = 0; packages.size() <= RenvLockPolicy.MAX_PACKAGES; i++) {
                        packages.putObject("pkg" + i).put("Package", "pkg" + i)
                                .put("Version", "1.0").put("Source", "Repository")
                                .put("Repository", "CRAN");
                    }
                }), "4.6.1"));
        assertEquals(Reason.TOO_LARGE, count.reason());
    }

    @Test
    public void aRejectionMessageIsPrintableAsciiWhateverItQuotes() {
        LockRejection e = assertThrows(LockRejection.class, () -> RenvLockPolicy.check(
                mutate(m -> rename(m, "mime", "mi\u202Eme")), "4.6.1"));
        assertTrue(e.getMessage().chars().allMatch(c -> c >= 0x20 && c < 0x7F), e.getMessage());
    }

    // ------------------------------------------------------------------ helpers

    private static void expect(List<String> wrong, String label, Reason reason,
                               Consumer<ObjectNode> mutation) {
        try {
            RenvLockPolicy.check(mutate(mutation), "4.6.1");
            wrong.add(label + ": ACCEPTED, expected " + reason);
        } catch (LockRejection e) {
            if (e.reason() != reason) {
                wrong.add(label + ": " + e.getMessage() + ", expected " + reason);
            }
        }
    }

    private static byte[] mutate(Consumer<ObjectNode> mutation) {
        try {
            ObjectNode doc = (ObjectNode) JSON.readTree(fixture());
            mutation.accept(doc);
            return JSON.writeValueAsBytes(doc);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static ObjectNode pkg(ObjectNode doc, String name) {
        ObjectNode record = (ObjectNode) doc.get("Packages").get(name);
        if (record == null) {
            throw new IllegalStateException(name + " is not in the fixture; the case proves nothing");
        }
        return record;
    }

    private static void rename(ObjectNode doc, String from, String to) {
        ObjectNode packages = (ObjectNode) doc.get("Packages");
        ObjectNode record = (ObjectNode) packages.remove(from);
        if (record == null) {
            throw new IllegalStateException(from + " is not in the fixture");
        }
        record.put("Package", to);
        packages.set(to, record);
    }

    private static List<String> names(JsonNode node) {
        List<String> out = new ArrayList<>();
        Iterator<String> it = node.fieldNames();
        it.forEachRemaining(out::add);
        return out;
    }

    private static byte[] fixture() {
        try {
            return Files.readAllBytes(FIXTURE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
