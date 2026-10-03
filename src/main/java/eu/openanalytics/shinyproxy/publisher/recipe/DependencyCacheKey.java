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

import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Base;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Mirrors;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Recipe;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/**
 * The dependency layer's cache key (WORKPLAN-BUNDLES.md decision 7): "a SHA-256 of a
 * canonical, domain-separated record containing recipe revision, exact base digest, target
 * architecture, language and package-manager versions, repository/mirror policy revision,
 * exact lockfile bytes and hashes of any local dependency inputs".
 *
 * <p>The record is a domain tag followed by named fields, each name and value
 * length-prefixed (4 bytes, big endian), so no two different inputs encode the same bytes
 * however their values are chosen. The fields:
 * <ul>
 *   <li>recipe_revision, base (the published digest reference), architecture, language,
 *       language_version: from the catalog entry and the resolved base;</li>
 *   <li>package_manager: every name=version the catalog records for the base, sorted;</li>
 *   <li>mirrors: the configured CRAN and PyPI mirrors. They are the "repository policy",
 *       and the same lockfile can resolve differently against another mirror;</li>
 *   <li>lock: for every server-written file the recipe installs from (skald/*), its name
 *       and the SHA-256 of its bytes. That is the RENDERED lock, which is what is
 *       installed, not the upload.</li>
 * </ul>
 * Local dependencies are not a field because no policy accepts one: both lock policies
 * refuse local and VCS sources, so there are none to hash. A future policy that admits
 * them must add their trees here.
 *
 * <p>The key is scoped further by the caller: the cache reference is per content item
 * (BuildKitClient.Cache), so equal keys of two content items never share a cache.
 */
public final class DependencyCacheKey {

    static final String DOMAIN = "skald-dependency-cache-v1";

    private DependencyCacheKey() {
    }

    /** The key, 64 lower-case hex characters. */
    public static String of(BaseCatalog.Entry entry, Base base, Mirrors mirrors, Recipe recipe) {
        Map<String, String> fields = new java.util.LinkedHashMap<>();
        fields.put("recipe_revision", Integer.toString(entry.recipeRevision()));
        fields.put("base", base.reference());
        fields.put("architecture", entry.architecture());
        fields.put("language", entry.language());
        fields.put("language_version", entry.version());
        StringBuilder pm = new StringBuilder();
        new TreeMap<>(entry.packageManager()).forEach((k, v) -> pm.append(k).append('=').append(v).append('\n'));
        fields.put("package_manager", pm.toString());
        fields.put("mirrors", "cran=" + mirrors.cran() + "\npypi=" + mirrors.pypiIndex() + "\n");
        StringBuilder lock = new StringBuilder();
        new TreeMap<>(recipe.files()).forEach((name, bytes) -> lock.append(name).append('=').append(sha256Hex(bytes))
                .append('\n'));
        fields.put("lock", lock.toString());
        return sha256Hex(encode(fields));
    }

    static byte[] encode(Map<String, String> fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        field(out, DOMAIN.getBytes(StandardCharsets.UTF_8));
        fields.forEach((name, value) -> {
            field(out, name.getBytes(StandardCharsets.UTF_8));
            field(out, value.getBytes(StandardCharsets.UTF_8));
        });
        return out.toByteArray();
    }

    private static void field(ByteArrayOutputStream out, byte[] bytes) {
        out.writeBytes(ByteBuffer.allocate(4).putInt(bytes.length).array());
        out.writeBytes(bytes);
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
