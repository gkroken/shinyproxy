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
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Base;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The trusted bases a build may start from, each by the digest the OPERATOR built and pushed
 * (4dd3f76 review N1: "a build can be FROM it by digest rather than by tag").
 *
 * <p>Two documents, because they have two owners. {@code images/catalog.json} is reviewed and
 * shipped: what each base is (type, language, exact version, architecture, recipe revision,
 * the unprivileged user), FROM which upstream digest, and what it contains. The published
 * bases file is the deployment's: built bases are not byte-reproducible (timestamps, package
 * state), so their digests exist only once an operator has built and pushed them, with
 * {@code dev/publish-bases.py}. It names the catalog it was built from by SHA-256, so a
 * catalog that changed since is refused rather than mixed with old images.
 *
 * <p>Published bases file, strict (unknown keys refused):
 * <pre>
 * {"layout_version": 1,
 *  "catalog_sha256": "&lt;64 hex: sha256 of the catalog.json bytes it was built from&gt;",
 *  "registry": "&lt;host[:port] as the build worker reaches it&gt;",
 *  "bases": {"&lt;catalog id&gt;": "&lt;registry&gt;/skald/base/&lt;id&gt;@sha256:&lt;64 hex&gt;"}}
 * </pre>
 * Each reference must be exactly that repository for that id, so a published file cannot
 * point one base's id at another image. A catalog base that is not published cannot be
 * resolved; a published id that the catalog does not have is refused.
 */
public final class BaseCatalog {

    /** The shipped catalog (pom.xml packages images/catalog.json here). */
    public static final String CATALOG_RESOURCE = "skald/images/catalog.json";

    /** One catalog entry, as far as a build needs it. */
    public record Entry(String id, String type, String language, String version, String architecture,
                        int recipeRevision, String uid, String gid) { }

    private static final ObjectMapper JSON = new ObjectMapper();
    /** host[:port], lower case: the same name the build worker's gateway allows. */
    private static final Pattern REGISTRY = Pattern.compile(
            "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[0-9]{1,5})?");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern USER = Pattern.compile("([0-9]{1,9}):([0-9]{1,9})");

    private final List<Entry> entries;
    private final Map<String, String> published;

    private BaseCatalog(List<Entry> entries, Map<String, String> published) {
        this.entries = List.copyOf(entries);
        this.published = Map.copyOf(published);
    }

    /** The shipped catalog with the deployment's published bases. */
    public static BaseCatalog load(InputStream publishedBases) throws IOException {
        try (InputStream in = BaseCatalog.class.getClassLoader().getResourceAsStream(CATALOG_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(CATALOG_RESOURCE + " is not on the classpath");
            }
            return load(in.readAllBytes(), publishedBases.readAllBytes());
        }
    }

    static BaseCatalog load(byte[] catalogBytes, byte[] publishedBytes) throws IOException {
        List<Entry> entries = new ArrayList<>();
        JsonNode catalog = JSON.readTree(catalogBytes);
        if (catalog.path("layout_version").asInt() != 1 || !catalog.path("bases").isArray()) {
            throw new IllegalArgumentException("catalog: not layout_version 1 with a bases list");
        }
        for (JsonNode b : catalog.path("bases")) {
            var user = USER.matcher(b.path("user").asText(""));
            if (!user.matches() || user.group(1).equals("0")) {
                throw new IllegalArgumentException("catalog: base " + b.path("id").asText() + " has no non-root user");
            }
            entries.add(new Entry(text(b, "id"), text(b, "type"), text(b, "language"), text(b, "version"),
                    text(b, "architecture"), b.path("recipe_revision").asInt(0), user.group(1), user.group(2)));
        }
        Set<String> ids = new java.util.HashSet<>();
        for (Entry e : entries) {
            if (!ids.add(e.id())) {
                throw new IllegalArgumentException("catalog: id " + e.id() + " twice");
            }
        }

        JsonNode p = JSON.readTree(publishedBytes);
        if (p == null || !p.isObject()) {
            throw new IllegalArgumentException("published bases: not a JSON object");
        }
        for (Iterator<String> it = p.fieldNames(); it.hasNext(); ) {
            String key = it.next();
            if (!Set.of("layout_version", "catalog_sha256", "registry", "bases").contains(key)) {
                throw new IllegalArgumentException("published bases: unknown key " + key);
            }
        }
        if (!p.path("layout_version").isInt() || p.path("layout_version").asInt() != 1) {
            throw new IllegalArgumentException("published bases: layout_version must be 1");
        }
        String want = sha256(catalogBytes);
        String got = p.path("catalog_sha256").asText("");
        if (!HEX64.matcher(got).matches() || !got.equals(want)) {
            throw new IllegalArgumentException("published bases were built from another catalog (catalog_sha256 "
                    + got + ", this catalog is " + want + "): publish the bases again");
        }
        String registry = p.path("registry").asText("");
        if (registry.length() > 253 || !REGISTRY.matcher(registry).matches()) {
            throw new IllegalArgumentException("published bases: not a registry host[:port]: " + registry);
        }
        if (!p.path("bases").isObject()) {
            throw new IllegalArgumentException("published bases: bases must be an object");
        }
        Map<String, String> published = new LinkedHashMap<>();
        for (Iterator<Map.Entry<String, JsonNode>> it = p.path("bases").fields(); it.hasNext(); ) {
            Map.Entry<String, JsonNode> f = it.next();
            if (!ids.contains(f.getKey())) {
                throw new IllegalArgumentException("published bases: " + f.getKey() + " is not in the catalog");
            }
            String ref = f.getValue().isTextual() ? f.getValue().asText() : "";
            String prefix = registry + "/skald/base/" + f.getKey() + "@sha256:";
            if (!ref.startsWith(prefix) || !HEX64.matcher(ref.substring(prefix.length())).matches()) {
                throw new IllegalArgumentException("published bases: " + f.getKey() + " must be " + prefix
                        + "<64 hex>, not " + ref);
            }
            published.put(f.getKey(), ref);
        }
        return new BaseCatalog(entries, published);
    }

    /**
     * The base for a manifest's type, language and exact version on an architecture: the
     * catalog's newest recipe revision of it, by its published digest. Empty if the catalog
     * has no such base; an IllegalStateException if it has one that was not published.
     */
    public Optional<Base> resolve(String type, String language, String version, String architecture) {
        Optional<Entry> entry = entries.stream()
                .filter(e -> e.type().equals(type) && e.language().equals(language)
                        && e.version().equals(version) && e.architecture().equals(architecture))
                .max(Comparator.comparingInt(Entry::recipeRevision));
        if (entry.isEmpty()) {
            return Optional.empty();
        }
        String ref = published.get(entry.get().id());
        if (ref == null) {
            throw new IllegalStateException("base " + entry.get().id() + " is in the catalog but was not published");
        }
        Entry e = entry.get();
        return Optional.of(new Base(ref, e.language(), e.version(), e.uid(), e.gid()));
    }

    /** The catalog's entries, in order. */
    public List<Entry> entries() {
        return entries;
    }

    private static String text(JsonNode node, String field) {
        String v = node.path(field).asText("");
        if (v.isEmpty()) {
            throw new IllegalArgumentException("catalog: a base has no " + field);
        }
        return v;
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
