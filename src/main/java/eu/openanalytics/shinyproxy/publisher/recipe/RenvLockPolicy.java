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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.openanalytics.shinyproxy.publisher.bundle.BundleRejection;
import eu.openanalytics.shinyproxy.publisher.recipe.LockRejection.Reason;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * The R recipe's lockfile policy: an uploaded {@code renv.lock} is read strictly and reduced
 * to what a restore needs -- the R version and, per package, an exact version from CRAN --
 * then re-rendered (WORKPLAN-BUNDLES.md: "The initial R recipe rejects remote mutable VCS
 * references and local package dependencies"; "Permit no renv.lock URL outside the egress
 * policy").
 *
 * <p><b>What is refused.</b> A package whose {@code Source} is not {@code Repository}
 * (GitHub, GitLab, Bitbucket, git, URL, Local, Bioconductor, ...), one whose
 * {@code Repository} is not {@code CRAN}, and any {@code Remote*} field, which is how renv
 * records where a non-repository package came from. Top-level sections other than {@code R}
 * and {@code Packages} ({@code Bioconductor}, {@code Python}) are refused, not skipped.
 *
 * <p><b>What is dropped.</b> renv 1.x copies a package's whole DESCRIPTION into its record
 * (Title, URL, Config/..., Additional_repositories); those fields are arbitrary per package,
 * so they cannot be allow-listed, and none of them changes what is installed. The lock's own
 * {@code Repositories} URLs are dropped too: the rendering names the server's mirror, and
 * the restore passes the same mirror as {@code repos}, so no uploaded URL reaches renv.
 *
 * <p><b>What this does not give.</b> renv.lock carries no hash of a package's tarball (its
 * {@code Hash}, when present, covers DESCRIPTION fields). An R restore's package bytes are
 * as trustworthy as the operator's mirror; Python's lock, by contrast, pins each file.
 */
public final class RenvLockPolicy {

    /** The framework the R Shiny recipe launches; the lock must contain it. */
    public static final String FRAMEWORK = "shiny";

    static final int MAX_BYTES = 16 * 1024 * 1024;
    static final int MAX_PACKAGES = 4000;
    private static final int MAX_NESTING_DEPTH = 16;

    /** R's own rule for package names ("Writing R Extensions" 1.1.1), at least two characters. */
    private static final Pattern NAME = Pattern.compile("[A-Za-z][A-Za-z0-9.]*[A-Za-z0-9]");
    /** At least two non-negative integers separated by single '.' or '-'. */
    private static final Pattern VERSION = Pattern.compile("[0-9]+(?:[.-][0-9]+)+");
    private static final Set<String> TOP_LEVEL = Set.of("R", "Packages");
    private static final Set<String> R_SECTION = Set.of("Version", "Repositories");

    private static final ObjectMapper STRICT = strictMapper();
    private static final ObjectMapper RENDER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private RenvLockPolicy() {
    }

    /** A lock that passed: the R version and every package's exact CRAN version. */
    public record RenvLock(String rVersion, SortedMap<String, String> packages) {

        public RenvLock {
            packages = Collections.unmodifiableSortedMap(new TreeMap<>(packages));
        }

        /**
         * The canonical lockfile the build restores from: nothing but the R version, the
         * mirror as the only repository, and Package/Version/Source/Repository per package.
         */
        public byte[] render(URI mirror) {
            String scheme = mirror.getScheme();
            if (!("http".equals(scheme) || "https".equals(scheme)) || mirror.getHost() == null) {
                throw new IllegalArgumentException("the mirror must be an absolute http(s) URL");
            }
            ObjectNode root = RENDER.createObjectNode();
            ObjectNode r = root.putObject("R");
            r.put("Version", rVersion);
            ArrayNode repositories = r.putArray("Repositories");
            repositories.addObject().put("Name", "CRAN").put("URL", mirror.toString());
            ObjectNode out = root.putObject("Packages");
            packages.forEach((name, version) -> out.putObject(name)
                    .put("Package", name)
                    .put("Version", version)
                    .put("Source", "Repository")
                    .put("Repository", "CRAN"));
            try {
                return (RENDER.writeValueAsString(root) + "\n").getBytes(StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * The lock, checked against the manifest's exact R version.
     *
     * @throws LockRejection naming the first rule it breaks
     */
    public static RenvLock check(byte[] lock, String runtimeVersion) {
        if (lock.length > MAX_BYTES) {
            throw new LockRejection(Reason.TOO_LARGE,
                    "renv.lock is " + lock.length + " bytes; the limit is " + MAX_BYTES);
        }
        JsonNode root;
        try {
            root = STRICT.readTree(lock);
        } catch (JsonProcessingException e) {
            throw new LockRejection(Reason.SYNTAX, "renv.lock is not valid JSON: "
                    + e.getOriginalMessage());
        } catch (IOException e) {
            throw new LockRejection(Reason.SYNTAX, "renv.lock could not be read: " + e);
        }
        if (root == null || !root.isObject()) {
            throw new LockRejection(Reason.SYNTAX, "renv.lock is not a JSON object");
        }
        onlyFields(root, TOP_LEVEL, "renv.lock");

        JsonNode r = root.get("R");
        if (r == null || !r.isObject()) {
            throw new LockRejection(Reason.SYNTAX, "renv.lock has no R section");
        }
        onlyFields(r, R_SECTION, "renv.lock's R section");
        String rVersion = text(r.get("Version"), "R.Version");
        if (!rVersion.equals(runtimeVersion)) {
            throw new LockRejection(Reason.RUNTIME_MISMATCH, "renv.lock is for R " + rVersion
                    + "; the manifest names R " + runtimeVersion);
        }
        JsonNode repositories = r.get("Repositories");
        if (repositories != null && !repositories.isArray()) {
            throw new LockRejection(Reason.SYNTAX, "R.Repositories is not an array");
        }

        JsonNode packages = root.get("Packages");
        if (packages == null || !packages.isObject()) {
            throw new LockRejection(Reason.SYNTAX, "renv.lock has no Packages object");
        }
        if (packages.size() > MAX_PACKAGES) {
            throw new LockRejection(Reason.TOO_LARGE, "renv.lock lists " + packages.size()
                    + " packages; the limit is " + MAX_PACKAGES);
        }
        SortedMap<String, String> pinned = new TreeMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = packages.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> entry = it.next();
            pinned.put(entry.getKey(), checkPackage(entry.getKey(), entry.getValue()));
        }
        if (!pinned.containsKey(FRAMEWORK)) {
            throw new LockRejection(Reason.FRAMEWORK_MISSING,
                    "renv.lock does not contain " + FRAMEWORK);
        }
        return new RenvLock(rVersion, pinned);
    }

    /** The package's exact version, once its record says it is CRAN's and nothing else. */
    private static String checkPackage(String key, JsonNode record) {
        String where = "package " + BundleRejection.quote(key);
        if (!NAME.matcher(key).matches()) {
            throw new LockRejection(Reason.BAD_NAME, where + " is not a valid R package name");
        }
        if (!record.isObject()) {
            throw new LockRejection(Reason.SYNTAX, where + " is not an object");
        }
        Iterator<String> fields = record.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if (field.startsWith("Remote")) {
                throw new LockRejection(Reason.NOT_FROM_REPOSITORY, where + " has "
                        + BundleRejection.quote(field) + ": only CRAN packages are accepted");
            }
        }
        String name = text(record.get("Package"), where + ".Package");
        if (!name.equals(key)) {
            throw new LockRejection(Reason.BAD_NAME, where + " records Package "
                    + BundleRejection.quote(name));
        }
        String source = text(record.get("Source"), where + ".Source");
        if (!source.equals("Repository")) {
            throw new LockRejection(Reason.NOT_FROM_REPOSITORY, where + " comes from "
                    + BundleRejection.quote(source) + ": only CRAN packages are accepted");
        }
        String repository = text(record.get("Repository"), where + ".Repository");
        if (!repository.equals("CRAN")) {
            throw new LockRejection(Reason.NOT_FROM_REPOSITORY, where + " comes from repository "
                    + BundleRejection.quote(repository) + ": only CRAN packages are accepted");
        }
        String version = text(record.get("Version"), where + ".Version");
        if (!VERSION.matcher(version).matches()) {
            throw new LockRejection(Reason.NOT_PINNED, where + " has version "
                    + BundleRejection.quote(version) + ", which is not an exact R version");
        }
        return version;
    }

    private static void onlyFields(JsonNode node, Set<String> allowed, String where) {
        Iterator<String> names = node.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (!allowed.contains(name)) {
                throw new LockRejection(Reason.UNKNOWN_FIELD, where + " has "
                        + BundleRejection.quote(name) + ", which this recipe does not accept");
            }
        }
    }

    private static String text(JsonNode node, String where) {
        if (node == null || !node.isTextual()) {
            throw new LockRejection(Reason.SYNTAX, where + " is missing or not a string");
        }
        return node.textValue();
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
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }
}
