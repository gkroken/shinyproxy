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

import eu.openanalytics.shinyproxy.publisher.bundle.ManifestValidator.Manifest;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Base;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Mirrors;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Recipe;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The generator against golden recipes for the two fixture apps. dev/recipes-probe.py
 * BUILDS exactly those golden files (substituting only the FROM line's digest) and runs the
 * images, so this test is what ties the live proof to the code: a generator change that is
 * not reflected in the goldens fails here, and one that is gets built there.
 *
 * <p>Regenerate the goldens with {@code -Dskald.recipes.write=true}, then review the diff.
 */
public class RecipeGeneratorTest {

    static final Path GOLDEN = Path.of("dev/fixtures/recipes");
    static final Path APPS = Path.of("dev/fixtures/apps");
    /** A placeholder the probe replaces with the digest of the base it built and pushed. */
    static final String PLACEHOLDER = "@sha256:" + "0".repeat(64);
    static final Base R_BASE = new Base("skald-probe.invalid/base/r-shiny" + PLACEHOLDER,
            "r", "4.6.1", "10001", "10001");
    static final Base PY_BASE = new Base("skald-probe.invalid/base/python-shiny" + PLACEHOLDER,
            "python", "3.13.16", "10001", "10001");
    /** bases-probe's forge, which the probe starts. */
    static final Mirrors MIRRORS = new Mirrors(
            URI.create("http://localhost:18081/repository/cran-public/"),
            URI.create("http://localhost:18081/repository/pypi-public/simple/"));

    @Test
    public void theRRecipeIsTheGoldenOne() {
        golden("r-shiny", RecipeGenerator.generate(R_BASE, MIRRORS, rManifest("."),
                read(APPS.resolve("r-shiny/renv.lock"))));
    }

    @Test
    public void thePythonRecipeIsTheGoldenOne() {
        golden("python-shiny", RecipeGenerator.generate(PY_BASE, MIRRORS, pyManifest("app.py"),
                read(APPS.resolve("python-shiny/requirements.lock"))));
    }

    @Test
    public void theBuildReadsOnlyTheRenderedLockNeverTheUpload() {
        // 1a66ae7 review N1: what the build invokes. The lock it installs is skald/<lock>,
        // whose bytes are the policy's render() of the upload; no instruction names app/'s
        // copy; and the package-manager options are the server's.
        byte[] rUpload = read(APPS.resolve("r-shiny/renv.lock"));
        Recipe r = RecipeGenerator.generate(R_BASE, MIRRORS, rManifest("."), rUpload);
        assertEquals(List.of("skald/renv.lock"), List.copyOf(r.files().keySet()));
        assertArrayEquals(RenvLockPolicy.check(rUpload, "4.6.1").render(MIRRORS.cran()),
                r.files().get("skald/renv.lock"));
        assertTrue(r.dockerfile().contains("COPY skald/renv.lock /opt/skald/renv.lock\n"));
        assertTrue(r.dockerfile().contains("lockfile = \\\"/opt/skald/renv.lock\\\""));
        assertTrue(r.dockerfile().contains("repos = c(CRAN = \\\"" + MIRRORS.cran() + "\\\")"));

        byte[] pyUpload = read(APPS.resolve("python-shiny/requirements.lock"));
        Recipe py = RecipeGenerator.generate(PY_BASE, MIRRORS, pyManifest("app.py"), pyUpload);
        assertEquals(List.of("skald/requirements.lock"), List.copyOf(py.files().keySet()));
        assertArrayEquals(PipLockPolicy.check(pyUpload).render(), py.files().get("skald/requirements.lock"));
        assertTrue(py.dockerfile().contains("\"--index-url\",\"" + MIRRORS.pypiIndex()
                + "\",\"--require-hashes\",\"--only-binary=:all:\",\"--no-deps\",\"-r\","
                + "\"/opt/skald/requirements.lock\""));

        for (Recipe recipe : List.of(r, py)) {
            for (String line : recipe.dockerfile().split("\n")) {
                assertFalse(line.contains("app/renv.lock") || line.contains("app/requirements.lock")
                        || line.contains("/app/renv.lock") || line.contains("/app/requirements.lock"),
                        line);
                if (line.startsWith("COPY ")) {
                    assertTrue(line.startsWith("COPY skald/") || line.equals("COPY app/ /app/"), line);
                }
            }
        }
        // And the upload's own extras cannot flow through: two uploads that differ only in
        // what the policy drops give byte-identical build files.
        String noisy = "# a comment\n" + new String(pyUpload, StandardCharsets.US_ASCII)
                .replace("uvicorn==", "uvicorn[standard]==").replace("\n", "\r\n");
        assertArrayEquals(py.files().get("skald/requirements.lock"), RecipeGenerator.generate(
                PY_BASE, MIRRORS, pyManifest("app.py"), noisy.getBytes(StandardCharsets.US_ASCII))
                .files().get("skald/requirements.lock"));
    }

    @Test
    public void everyRunAndTheCmdAreExecForm() {
        for (Recipe recipe : List.of(
                RecipeGenerator.generate(R_BASE, MIRRORS, rManifest("."), read(APPS.resolve("r-shiny/renv.lock"))),
                RecipeGenerator.generate(PY_BASE, MIRRORS, pyManifest("app.py"),
                        read(APPS.resolve("python-shiny/requirements.lock"))))) {
            for (String line : recipe.dockerfile().split("\n")) {
                if (line.startsWith("RUN ") || line.startsWith("CMD ")) {
                    assertTrue(line.substring(4).startsWith("[\"") && line.endsWith("\"]"), line);
                }
            }
            assertTrue(recipe.dockerfile().contains("\nUSER 10001:10001\n"));
        }
    }

    @Test
    public void thePythonLauncherRunsIsolatedSoTheUploadCannotShadowShiny() {
        // 19c759c-F1: `python -m shiny` in WORKDIR /app searched /app first, so an uploaded
        // shiny.py replaced the launcher. The live case is in recipes-probe --self-test.
        String cmd = RecipeGenerator.generate(PY_BASE, MIRRORS, pyManifest("app.py"),
                read(APPS.resolve("python-shiny/requirements.lock"))).dockerfile().lines()
                .filter(l -> l.startsWith("CMD ")).findFirst().orElseThrow();
        assertTrue(cmd.startsWith("CMD [\"/opt/skald/venv/bin/python\",\"-I\",\"-m\",\"shiny\","), cmd);
    }

    @Test
    public void unsafeInputsAreRefused() {
        byte[] rLock = read(APPS.resolve("r-shiny/renv.lock"));
        byte[] pyLock = read(APPS.resolve("python-shiny/requirements.lock"));
        List<String> accepted = new ArrayList<>();
        refuse(accepted, "a base by tag", () -> new Base("rocker/r-ver:4.6.1", "r", "4.6.1", "10001", "10001"));
        refuse(accepted, "a root base user", () -> new Base(R_BASE.reference(), "r", "4.6.1", "0", "0"));
        // 1ffdb20-F1: root by another spelling, and root's group.
        for (String[] ids : new String[][] {{"00", "00"}, {"000000000", "10001"}, {"010001", "10001"},
                {"10001", "0"}, {"10001", "00"}, {"0", "10001"}}) {
            refuse(accepted, "base user " + ids[0] + ":" + ids[1],
                    () -> new Base(R_BASE.reference(), "r", "4.6.1", ids[0], ids[1]));
        }
        refuse(accepted, "a named base user", () -> new Base(R_BASE.reference(), "r", "4.6.1", "skald", "skald"));
        // Each a valid URI, so the refusal is the generator's rule and not URI parsing: a
        // mirror is interpolated into an R string and a pip argument, so it gets no '%', '@',
        // '?', quote or space, and must be an http(s) directory.
        for (String mirror : List.of("file:///srv/cran/", "ftp://m/", "http://user@m/",
                "http://m/a%20b/", "http://m/a%22b/", "http://m/?x=1", "http://m/cran", "http:/m/")) {
            refuse(accepted, "mirror " + mirror, () -> new Mirrors(URI.create(mirror), MIRRORS.pypiIndex()));
            refuse(accepted, "index " + mirror, () -> new Mirrors(MIRRORS.cran(), URI.create(mirror)));
        }
        refuse(accepted, "an R entrypoint other than '.'", () -> RecipeGenerator.generate(
                R_BASE, MIRRORS, rManifest("app"), rLock));
        for (String entry : List.of("app:app", "-m.py", "../app.py", "./app.py", "app", "a b.py",
                "/app.py", "sub/.hidden.py", "app.py:x")) {
            refuse(accepted, "python entrypoint " + entry, () -> RecipeGenerator.generate(
                    PY_BASE, MIRRORS, pyManifest(entry), pyLock));
        }
        refuse(accepted, "a language mismatch", () -> RecipeGenerator.generate(
                R_BASE, MIRRORS, pyManifest("app.py"), pyLock));
        refuse(accepted, "a version mismatch", () -> RecipeGenerator.generate(
                new Base(R_BASE.reference(), "r", "4.5.0", "10001", "10001"), MIRRORS, rManifest("."), rLock));
        assertEquals(List.of(), accepted);
        // A lock the policy refuses never becomes a recipe.
        assertThrows(LockRejection.class, () -> RecipeGenerator.generate(PY_BASE, MIRRORS,
                pyManifest("app.py"), ("-i http://evil.invalid/simple\n" + new String(pyLock,
                StandardCharsets.US_ASCII)).getBytes(StandardCharsets.US_ASCII)));
        assertTrue(RecipeGenerator.generate(PY_BASE, MIRRORS, pyManifest("sub/app.py"), pyLock)
                .dockerfile().contains(",\"sub/app.py\"]\n"), "a nested entrypoint is accepted");
    }

    // ------------------------------------------------------------------ helpers

    private interface Throwing {
        Object run() throws Exception;
    }

    private static void refuse(List<String> accepted, String label, Throwing action) {
        try {
            action.run();
            accepted.add(label);
        } catch (IllegalArgumentException | LockRejection expected) {
            // refused
        } catch (Exception e) {
            accepted.add(label + " (threw " + e + ")");
        }
    }

    static Manifest rManifest(String entrypoint) {
        return new Manifest("shiny", "r", "4.6.1", entrypoint, "renv", "renv.lock", Map.of());
    }

    static Manifest pyManifest(String entrypoint) {
        return new Manifest("shiny", "python", "3.13.16", entrypoint, "pip-hashed",
                "requirements.lock", Map.of());
    }

    private static void golden(String name, Recipe recipe) {
        Path dir = GOLDEN.resolve(name);
        if (Boolean.getBoolean("skald.recipes.write")) {
            try {
                Files.createDirectories(dir.resolve("skald"));
                Files.writeString(dir.resolve("Dockerfile"), recipe.dockerfile(), StandardCharsets.US_ASCII);
                for (Map.Entry<String, byte[]> f : recipe.files().entrySet()) {
                    Files.write(dir.resolve(f.getKey()), f.getValue());
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        assertEquals(new String(read(dir.resolve("Dockerfile")), StandardCharsets.US_ASCII),
                recipe.dockerfile(), name + "/Dockerfile differs from the generator's output");
        for (Map.Entry<String, byte[]> f : recipe.files().entrySet()) {
            assertArrayEquals(read(dir.resolve(f.getKey())), f.getValue(), name + "/" + f.getKey());
        }
    }

    private static byte[] read(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
