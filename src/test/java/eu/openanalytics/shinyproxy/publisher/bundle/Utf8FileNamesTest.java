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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The extractor under the locale it is deployed with (gate finding t5-f4f5f32-F4).
 *
 * <p>Path encoding is fixed when the JVM starts, from the locale, so the only honest test is
 * a second JVM started under that locale. Under LC_ALL=C a bundle with a non-ASCII file name
 * ended in an unchecked InvalidPathException; it must now be refused before anything is
 * written, with the operator's fix named. Under a UTF-8 locale the same bundle is extracted,
 * which is the control: without it, a refusal could be the bundle's fault.
 */
public class Utf8FileNamesTest {

    // U+FB01 LATIN SMALL LIGATURE FI: NFC, accepted by the contract, not ASCII.
    private static final String NON_ASCII = "data/\ufb01le.csv";

    /** The child: extract one bundle carrying a non-ASCII name, and say what happened. */
    public static void main(String[] args) throws Exception {
        Map<String, byte[]> payload = TarArchives.shinyPayload();
        payload.put(NON_ASCII, "a,b\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
            out.write(TarArchives.bundle(payload).end());
        }
        byte[] upload = gz.toByteArray();
        try {
            BundleExtractor.Extracted done = BundleExtractor.extract(
                    new ByteArrayInputStream(upload), upload.length, Path.of(args[0]),
                    ExtractionLimits.defaults());
            System.out.println("EXTRACTED " + done.files());
            done.root().deleteTree();
        } catch (Throwable failure) {
            System.out.println("REFUSED " + failure.getClass().getName() + ": "
                    + failure.getMessage());
        }
    }

    private static String runUnder(String locale, Path workspace) throws Exception {
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                Utf8FileNamesTest.class.getName(), workspace.toString()));
        ProcessBuilder child = new ProcessBuilder(command).redirectErrorStream(true);
        child.environment().keySet().removeIf(k -> k.equals("LANG") || k.startsWith("LC_"));
        child.environment().put("LC_ALL", locale);
        Process process = child.start();
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "the child JVM did not finish");
        // The child's own verdict line; logging on the test classpath prints its start-up
        // lines first.
        return out.lines().filter(l -> l.startsWith("EXTRACTED ") || l.startsWith("REFUSED "))
                .reduce((first, last) -> last).orElse("NO VERDICT:\n" + out);
    }

    @Test
    public void underTheCLocaleTheExtractorRefusesBeforeWritingAndNamesTheFix(@TempDir Path tmp)
            throws Exception {
        String out = runUnder("C", tmp);
        assertTrue(out.startsWith("REFUSED java.lang.IllegalStateException")
                && out.contains("not UTF-8") && out.contains("LANG=C.UTF-8"), out);
        try (var left = Files.list(tmp)) {
            assertEquals(List.of(), left.toList(), "something was written before the refusal");
        }
    }

    @Test
    public void underAUtf8LocaleTheSameBundleIsExtracted(@TempDir Path tmp) throws Exception {
        String out = runUnder("C.UTF-8", tmp);
        assertTrue(out.startsWith("EXTRACTED"), out);
    }
}
