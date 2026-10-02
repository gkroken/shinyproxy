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

import eu.openanalytics.shinyproxy.publisher.recipe.LockRejection.Reason;
import eu.openanalytics.shinyproxy.publisher.recipe.PipLockPolicy.PipLock;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Python lockfile policy against a real hash-locked requirements.lock (resolved through
 * forge for the Python Shiny fixture app, each hash checked against the index's), and
 * against that lock with one hostile line added or changed at a time.
 */
public class PipLockPolicyTest {

    private static final Path FIXTURE = Path.of("dev/fixtures/apps/python-shiny/requirements.lock");
    private static final String H = "--hash=sha256:" + "ab".repeat(32);
    private static final String H2 = "--hash=sha256:" + "cd".repeat(32);

    @Test
    public void theRealFixtureLockIsAcceptedAndReadExactly() {
        PipLock lock = PipLockPolicy.check(fixture().getBytes(StandardCharsets.US_ASCII));
        assertEquals(32, lock.requirements().size());
        assertEquals("1.8.0", lock.requirements().get("shiny").version());
        assertEquals(1, lock.requirements().get("shiny").sha256().size());
        // Keys are PEP 503 normalised: the file says annotated-types, typing_extensions.
        assertTrue(lock.requirements().containsKey("typing-extensions"));
    }

    @Test
    public void theRenderingIsCanonicalAndReadsBackToTheSameLock() {
        PipLock lock = PipLockPolicy.check(fixture().getBytes(StandardCharsets.US_ASCII));
        byte[] rendered = lock.render();
        assertEquals(lock, PipLockPolicy.check(rendered));
        String text = new String(rendered, StandardCharsets.US_ASCII);
        for (String line : text.split("\n")) {
            assertTrue(line.matches("[a-z0-9-]+==[A-Za-z0-9.!+_-]+ \\\\")
                    || line.matches("    --hash=sha256:[0-9a-f]{64}( \\\\)?"), line);
        }
    }

    @Test
    public void commentsContinuationsAndCrlfAreReadAsPipReadsThem() {
        List<String> wrong = new ArrayList<>();
        accept(wrong, "full-line and indented comments",
                "# generated\n    # via shiny\n" + fixture());
        accept(wrong, "an inline comment after a hash",
                fixture().replaceFirst("(--hash=sha256:[0-9a-f]{64})", "$1  # pinned"));
        accept(wrong, "CRLF line ends", fixture().replace("\n", "\r\n"));
        accept(wrong, "blank lines", "\n\n" + fixture() + "\n\n");
        // pip never treats a comment line as a continuation. Read as one, it would swallow
        // the next line: here, the only shiny line, so the lock would lose its framework.
        String withoutShiny = fixture().replaceFirst("shiny==1\\.8\\.0 \\\\\n    --hash=sha256:[0-9a-f]{64}\n", "");
        assertFalse(withoutShiny.equals(fixture()));
        String shinyLine = "shiny==1.8.0 " + H;
        PipLock lock = PipLockPolicy.check(("# note \\\n" + shinyLine + "\n" + withoutShiny)
                .getBytes(StandardCharsets.US_ASCII));
        assertTrue(lock.requirements().containsKey("shiny"), "the comment swallowed the next line");
        assertEquals(List.of(), wrong);
    }

    @Test
    public void extrasAreAcceptedAndDroppedBecauseNoDepsMakesThemInert() {
        PipLock lock = PipLockPolicy.check((fixture().replace("uvicorn==", "uvicorn[standard]=="))
                .getBytes(StandardCharsets.US_ASCII));
        assertFalse(new String(lock.render(), StandardCharsets.US_ASCII).contains("["));
        assertEquals("0.54.0", lock.requirements().get("uvicorn").version());
    }

    @Test
    public void everyDangerousFormIsRefusedByName() {
        List<String> wrong = new ArrayList<>();
        // Options pip honours inside a requirements file: includes, index and trust changes,
        // editables, find-links, and the short spellings of each.
        for (String option : List.of("-r other.txt", "--requirement=other.txt", "-c constraints.txt",
                "--index-url https://evil.invalid/simple", "-i https://evil.invalid/simple",
                "--extra-index-url https://evil.invalid/simple", "--trusted-host evil.invalid",
                "-f https://evil.invalid/wheels", "--find-links=/tmp", "-e .", "--editable git+https://x/y",
                "--no-binary :all:", "--pre", "--use-feature=truststore", H)) {
            refuse(wrong, option, Reason.OPTION_REFUSED, option);
        }
        // Per-requirement options change how a package is built.
        refuse(wrong, "a per-requirement option", Reason.OPTION_REFUSED,
                "numpy==2.0 " + H + " --config-settings=x=y");
        refuse(wrong, "a space-separated hash", Reason.OPTION_REFUSED, "numpy==2.0 --hash sha256:" + "ab".repeat(32));
        // Direct references bypass the index.
        for (String direct : List.of("shiny @ https://evil.invalid/shiny-1.0-py3-none-any.whl " + H,
                "git+https://github.com/evil/shiny " + H, "./vendor/shiny " + H, "/abs/shiny.whl " + H,
                "https://evil.invalid/x.whl " + H, "shiny@git+https://x/y " + H,
                "file:shiny.whl " + H)) {
            refuse(wrong, direct, Reason.NOT_FROM_REPOSITORY, direct);
        }
        for (String loose : List.of("numpy " + H, "numpy>=2.0 " + H, "numpy~=2.0 " + H,
                "numpy!=2.0 " + H, "numpy==2.* " + H, "numpy===2.0 " + H, "numpy<3 " + H,
                "numpy == 2.0 " + H)) {
            refuse(wrong, loose, Reason.NOT_PINNED, loose);
        }
        refuse(wrong, "unhashed", Reason.UNHASHED, "numpy==2.0");
        refuse(wrong, "sha512", Reason.UNHASHED, "numpy==2.0 --hash=sha512:" + "ab".repeat(64));
        refuse(wrong, "md5", Reason.UNHASHED, "numpy==2.0 --hash=md5:" + "ab".repeat(16));
        refuse(wrong, "upper-case hex", Reason.UNHASHED, "numpy==2.0 --hash=sha256:" + "AB".repeat(32));
        refuse(wrong, "a short hash", Reason.UNHASHED, "numpy==2.0 --hash=sha256:" + "ab".repeat(31));
        refuse(wrong, "a marker", Reason.MARKER_UNSUPPORTED,
                "numpy==2.0 ; python_version >= \"3.8\" " + H);
        refuse(wrong, "a bad name", Reason.BAD_NAME, "_numpy==2.0 " + H);
        refuse(wrong, "a name ending in a separator", Reason.BAD_NAME, "numpy_==2.0 " + H);
        assertEquals(List.of(), wrong);
    }

    @Test
    public void duplicatesAreFoundAfterNormalisation() {
        List<String> wrong = new ArrayList<>();
        for (String twin : List.of("shiny==1.0 " + H2, "Shiny==1.8.0 " + H2, "SHINY==1.8.0 " + H2)) {
            refuse(wrong, twin, Reason.DUPLICATE, twin);
        }
        refuse(wrong, "typing.extensions", Reason.DUPLICATE, "typing.extensions==4.0 " + H2);
        refuse(wrong, "typing--extensions", Reason.DUPLICATE, "Typing--Extensions==4.0 " + H2);
        assertEquals(List.of(), wrong);
    }

    @Test
    public void encodingAndShapeAreChecked() {
        List<String> wrong = new ArrayList<>();
        refuseWhole(wrong, "a bare CR (a line break to pip's splitlines)", Reason.SYNTAX,
                fixture().replaceFirst("\n", "\r"));
        refuseWhole(wrong, "a non-ASCII letter", Reason.SYNTAX,
                fixture() + "nump" + (char) 0xFD + "==2.0 " + H + "\n");
        refuseWhole(wrong, "a non-breaking space", Reason.SYNTAX,
                fixture() + "numpy==2.0" + (char) 0xA0 + H + "\n");
        refuseWhole(wrong, "a form feed", Reason.SYNTAX, fixture() + "\f");
        refuseWhole(wrong, "a trailing continuation", Reason.SYNTAX, fixture() + "numpy==2.0 \\");
        refuseWhole(wrong, "no shiny", Reason.FRAMEWORK_MISSING,
                fixture().replaceAll("(?m)^shiny==.*\\n(    --hash.*\\n)+", ""));
        refuseWhole(wrong, "empty", Reason.FRAMEWORK_MISSING, "");
        byte[] invalid = fixture().getBytes(StandardCharsets.US_ASCII);
        invalid[3] = (byte) 0xC0;
        LockRejection e = assertThrows(LockRejection.class, () -> PipLockPolicy.check(invalid));
        if (e.reason() != Reason.SYNTAX) {
            wrong.add("invalid UTF-8: " + e.getMessage());
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    public void sizeLimitsAreEnforced() {
        assertEquals(Reason.TOO_LARGE, assertThrows(LockRejection.class, () -> PipLockPolicy.check(
                new byte[PipLockPolicy.MAX_BYTES + 1])).reason());
        StringBuilder many = new StringBuilder(fixture());
        for (int i = 0; i <= PipLockPolicy.MAX_REQUIREMENTS; i++) {
            many.append("pkg").append(i).append("==1.0 ").append(H).append('\n');
        }
        assertEquals(Reason.TOO_LARGE, assertThrows(LockRejection.class, () -> PipLockPolicy.check(
                many.toString().getBytes(StandardCharsets.US_ASCII))).reason());
        StringBuilder hashes = new StringBuilder(fixture()).append("numpy==2.0");
        for (int i = 0; i <= PipLockPolicy.MAX_HASHES; i++) {
            hashes.append(" --hash=sha256:").append(String.format("%064x", i));
        }
        assertEquals(Reason.TOO_LARGE, assertThrows(LockRejection.class, () -> PipLockPolicy.check(
                hashes.append('\n').toString().getBytes(StandardCharsets.US_ASCII))).reason());
    }

    @Test
    public void aRejectionNamesItsLineAndIsPrintableAscii() {
        // A bidi override is refused by the decoder before any rule could quote it; the
        // refusal names it as U+202E, so the message stays printable either way.
        String hostile = "-r ev" + (char) 0x202E + "il.txt";
        LockRejection e = assertThrows(LockRejection.class, () -> PipLockPolicy.check(
                ("# x\n" + fixture() + "-r other.txt\n").getBytes(StandardCharsets.US_ASCII)));
        int lines = fixture().split("\n").length + 2;
        assertTrue(e.getMessage().contains("line " + lines), e.getMessage());
        LockRejection unicode = assertThrows(LockRejection.class, () -> PipLockPolicy.check(
                hostile.getBytes(StandardCharsets.UTF_8)));
        assertTrue(unicode.getMessage().chars().allMatch(c -> c >= 0x20 && c < 0x7F),
                unicode.getMessage());
    }

    // ------------------------------------------------------------------ helpers

    private static void accept(List<String> wrong, String label, String lock) {
        try {
            PipLock read = PipLockPolicy.check(lock.getBytes(StandardCharsets.US_ASCII));
            if (read.requirements().size() != 32) {
                wrong.add(label + ": read " + read.requirements().size() + " requirements");
            }
        } catch (LockRejection e) {
            wrong.add(label + ": REFUSED " + e.getMessage());
        }
    }

    /** The fixture plus one hostile line, which must be refused for the given reason. */
    private static void refuse(List<String> wrong, String label, Reason reason, String line) {
        refuseWhole(wrong, label, reason, fixture() + line + "\n");
    }

    private static void refuseWhole(List<String> wrong, String label, Reason reason, String lock) {
        try {
            PipLockPolicy.check(lock.getBytes(StandardCharsets.UTF_8));
            wrong.add(label + ": ACCEPTED, expected " + reason);
        } catch (LockRejection e) {
            if (e.reason() != reason) {
                wrong.add(label + ": " + e.getMessage() + ", expected " + reason);
            }
        }
    }

    private static String fixture() {
        try {
            return Files.readString(FIXTURE, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
