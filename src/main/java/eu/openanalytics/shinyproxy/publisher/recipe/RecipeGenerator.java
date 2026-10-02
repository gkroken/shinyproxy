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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.shinyproxy.publisher.bundle.ManifestValidator.Manifest;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Writes the server-owned Dockerfile for a validated bundle (WORKPLAN-BUNDLES.md "Base
 * images, recipes and runtime projection"; T7). Nothing the publisher uploaded is
 * interpolated into it except the Python entrypoint, which is checked against a narrow
 * grammar first and then written as a JSON string.
 *
 * <p><b>The lock the build installs is the policy's rendering, never the upload.</b>
 * {@link #generate} takes the uploaded lock's BYTES and runs the language's policy on them
 * itself, so there is no way to hand it an unchecked lock, and the only lock file it
 * produces is {@code skald/<lock>} from {@code render()}. The uploaded copy stays inside
 * {@code app/} as an ordinary payload file that no instruction reads (1a66ae7 review N1).
 *
 * <p><b>Layout of the build context</b> the driver assembles: {@code app/} is the verified
 * payload and {@code skald/} holds {@link Recipe#files()}. The Dockerfile itself is passed
 * outside the context.
 *
 * <p><b>Order and identity.</b> The lock is copied and restored before the application, so a
 * source-only change reuses the dependency layer (decision 7's cache builds on this). The
 * restore runs as the base's unprivileged user, not root: installing an R source package or
 * a wheel runs package code, and that code is untrusted. The application is copied
 * root-owned, so the running app cannot rewrite itself. Every RUN and the CMD are exec form:
 * no shell parses anything here.
 */
public final class RecipeGenerator {

    /** The container port every Shiny recipe listens on (the plan's fixed launcher). */
    public static final int PORT = 3838;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern DIGEST_REFERENCE =
            Pattern.compile("[a-z0-9]+(?:[._:/-][a-z0-9]+)*@sha256:[0-9a-f]{64}");
    /** Characters a mirror URL may carry: enough for scheme://host:port/path/, no quoting. */
    private static final Pattern MIRROR =
            Pattern.compile("https?://[A-Za-z0-9.:-]+(?:/[A-Za-z0-9._~-]+)*/");
    /**
     * A Python entrypoint shiny run reads as a FILE: no ':' (it would be read as
     * module:attribute), no leading '-' (an option), contained segments only.
     */
    private static final Pattern PY_ENTRY =
            Pattern.compile("(?:[A-Za-z0-9_][A-Za-z0-9_.-]*/)*[A-Za-z0-9_][A-Za-z0-9_.-]*\\.py");
    private static final Pattern ID = Pattern.compile("[0-9]{1,9}");

    private RecipeGenerator() {
    }

    /**
     * A trusted base, as resolved from the catalog: its digest reference, language and exact
     * version, and the fixed unprivileged identity.
     */
    public record Base(String reference, String language, String version, String uid, String gid) {

        public Base {
            if (!DIGEST_REFERENCE.matcher(reference).matches()) {
                throw new IllegalArgumentException("a base must be referenced by digest: " + reference);
            }
            if (!ID.matcher(uid).matches() || !ID.matcher(gid).matches() || uid.equals("0")) {
                throw new IllegalArgumentException("a base's user must be a non-root numeric id");
            }
        }
    }

    /** The operator's package mirrors: a CRAN-like repository and a PyPI simple index. */
    public record Mirrors(URI cran, URI pypiIndex) {

        public Mirrors {
            for (URI u : List.of(cran, pypiIndex)) {
                if (!MIRROR.matcher(u.toString()).matches()) {
                    throw new IllegalArgumentException("a mirror must be a plain http(s) URL "
                            + "ending in '/': " + u);
                }
            }
        }
    }

    /** The Dockerfile, and the server-written files it reads, keyed by context path. */
    public record Recipe(String dockerfile, Map<String, byte[]> files) {

        public Recipe {
            files = Map.copyOf(files);
        }
    }

    /**
     * The recipe for a manifest that passed validation, with the uploaded lock's bytes.
     *
     * @throws LockRejection when the lock fails its language's policy
     * @throws IllegalArgumentException when manifest and base disagree, or the entrypoint is
     *         outside what this recipe launches
     */
    public static Recipe generate(Base base, Mirrors mirrors, Manifest manifest, byte[] uploadedLock) {
        if (!base.language().equals(manifest.language())
                || !base.version().equals(manifest.runtimeVersion())) {
            throw new IllegalArgumentException("the base is " + base.language() + " "
                    + base.version() + "; the manifest names " + manifest.language() + " "
                    + manifest.runtimeVersion());
        }
        if (!"shiny".equals(manifest.type())) {
            throw new IllegalArgumentException("no recipe for type " + manifest.type());
        }
        return switch (manifest.language()) {
            case "r" -> forR(base, mirrors, manifest,
                    RenvLockPolicy.check(uploadedLock, manifest.runtimeVersion()));
            case "python" -> forPython(base, mirrors, manifest, PipLockPolicy.check(uploadedLock));
            default -> throw new IllegalArgumentException("no recipe for " + manifest.language());
        };
    }

    private static Recipe forR(Base base, Mirrors mirrors, Manifest manifest,
                               RenvLockPolicy.RenvLock lock) {
        // The plan admits only '.' for R Shiny: the payload root is the application.
        if (!".".equals(manifest.entrypoint())) {
            throw new IllegalArgumentException("an R Shiny entrypoint must be '.'");
        }
        String restore = "renv::restore(lockfile = \"/opt/skald/renv.lock\", "
                + "library = \"/opt/skald/library\", repos = c(CRAN = \"" + mirrors.cran()
                + "\"), prompt = FALSE)";
        String launch = ".libPaths(c(\"/opt/skald/library\", .libPaths())); "
                + "shiny::runApp(\".\", host = \"0.0.0.0\", port = " + PORT
                + ", launch.browser = FALSE)";
        String user = base.uid() + ":" + base.gid();
        String dockerfile = header(base)
                // renv's own defaults that would reach past the mirror or the build: Posit
                // Package Manager, the global package cache (decision 7 decides caching),
                // and the project autoloader. HOME: the user has no home directory.
                + "ENV RENV_CONFIG_PPM_ENABLED=FALSE RENV_CONFIG_CACHE_ENABLED=FALSE \\\n"
                + "    RENV_CONFIG_AUTOLOADER_ENABLED=FALSE RENV_DOWNLOAD_METHOD=libcurl HOME=/tmp\n"
                + "RUN " + exec("mkdir", "-p", "/opt/skald/library") + "\n"
                + "RUN " + exec("chown", user, "/opt/skald/library") + "\n"
                + "COPY skald/renv.lock /opt/skald/renv.lock\n"
                + "USER " + user + "\n"
                + "RUN " + exec("Rscript", "--vanilla", "-e", restore) + "\n"
                + "COPY app/ /app/\n"
                + "WORKDIR /app\n"
                + "EXPOSE " + PORT + "\n"
                + "CMD " + exec("Rscript", "--vanilla", "-e", launch) + "\n";
        return new Recipe(dockerfile, Map.of("skald/renv.lock", lock.render(mirrors.cran())));
    }

    private static Recipe forPython(Base base, Mirrors mirrors, Manifest manifest,
                                    PipLockPolicy.PipLock lock) {
        String entry = manifest.entrypoint();
        if (!PY_ENTRY.matcher(entry).matches()) {
            throw new IllegalArgumentException("a Python Shiny entrypoint must be a plain "
                    + "relative .py path without ':'");
        }
        String user = base.uid() + ":" + base.gid();
        String pip = "/opt/skald/venv/bin/python";
        String dockerfile = header(base)
                + "RUN " + exec("python", "-m", "venv", "/opt/skald/venv") + "\n"
                + "RUN " + exec("chown", "-R", user, "/opt/skald/venv") + "\n"
                + "COPY skald/requirements.lock /opt/skald/requirements.lock\n"
                + "USER " + user + "\n"
                // Every option is the server's; the file is the policy's rendering. Wheels
                // only (no sdist build backends), every file hash-checked, nothing resolved.
                + "RUN " + exec(pip, "-m", "pip", "install", "--no-input",
                        "--index-url", mirrors.pypiIndex().toString(), "--require-hashes",
                        "--only-binary=:all:", "--no-deps", "-r", "/opt/skald/requirements.lock")
                + "\n"
                // --no-deps cannot notice a lock that is missing a dependency; pip check can,
                // so an incomplete lock fails the build instead of the first request.
                + "RUN " + exec(pip, "-m", "pip", "check") + "\n"
                + "COPY app/ /app/\n"
                + "WORKDIR /app\n"
                + "EXPOSE " + PORT + "\n"
                + "CMD " + exec(pip, "-m", "shiny", "run", "--host", "0.0.0.0",
                        "--port", String.valueOf(PORT), entry) + "\n";
        return new Recipe(dockerfile, Map.of("skald/requirements.lock", lock.render()));
    }

    private static String header(Base base) {
        return "# Generated by Skald (publisher.recipe.RecipeGenerator). Do not edit.\n"
                + "FROM " + base.reference() + "\n";
    }

    /** An exec-form instruction argument list: a JSON array of strings. */
    private static String exec(String... argv) {
        try {
            return JSON.writeValueAsString(argv);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
