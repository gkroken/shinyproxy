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
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Decision 7's key: every input moves it, nothing else does, and the encoding cannot be shifted. */
public class DependencyCacheKeyTest {

    private static final BaseCatalog.Entry ENTRY = new BaseCatalog.Entry("python-shiny-3.13.16-amd64-r1", "shiny",
            "python", "3.13.16", "amd64", 1, "10001", "10001", Map.of("pip", "25.2"));
    private static final Base BASE = new Base("reg:5000/skald/base/python-shiny-3.13.16-amd64-r1@sha256:" + "a".repeat(64),
            "python", "3.13.16", "10001", "10001");
    private static final Mirrors MIRRORS = new Mirrors(URI.create("http://forge:8080/cran/"),
            URI.create("http://forge:8080/pypi/simple/"));
    private static final Recipe RECIPE = new Recipe("FROM x\n",
            Map.of("skald/requirements.lock", "shiny==1.0 --hash=sha256:00\n".getBytes(StandardCharsets.UTF_8)));

    private static BaseCatalog.Entry entry(int revision, String arch, String language, String version, Map<String, String> pm) {
        return new BaseCatalog.Entry(ENTRY.id(), "shiny", language, version, arch, revision, "10001", "10001", pm);
    }

    @Test
    public void everyInputMovesTheKeyAndEqualInputsGiveEqualKeys() {
        String key = DependencyCacheKey.of(ENTRY, BASE, MIRRORS, RECIPE);
        assertTrue(key.matches("[0-9a-f]{64}"));
        assertEquals(key, DependencyCacheKey.of(ENTRY, BASE, MIRRORS, RECIPE), "deterministic");
        // The Dockerfile is not an input: it follows from the base, mirrors and lock, and an
        // app-source edit must not move the key.
        assertEquals(key, DependencyCacheKey.of(ENTRY, BASE, MIRRORS, new Recipe("FROM x\nCOPY app/ /app/\n", RECIPE.files())));
        Map<String, String> variants = new LinkedHashMap<>();
        variants.put("recipe revision", DependencyCacheKey.of(entry(2, "amd64", "python", "3.13.16", Map.of("pip", "25.2")), BASE, MIRRORS, RECIPE));
        variants.put("architecture", DependencyCacheKey.of(entry(1, "arm64", "python", "3.13.16", Map.of("pip", "25.2")), BASE, MIRRORS, RECIPE));
        variants.put("language", DependencyCacheKey.of(entry(1, "amd64", "r", "3.13.16", Map.of("pip", "25.2")), BASE, MIRRORS, RECIPE));
        variants.put("language version", DependencyCacheKey.of(entry(1, "amd64", "python", "3.13.17", Map.of("pip", "25.2")), BASE, MIRRORS, RECIPE));
        variants.put("package manager version", DependencyCacheKey.of(entry(1, "amd64", "python", "3.13.16", Map.of("pip", "25.3")), BASE, MIRRORS, RECIPE));
        variants.put("another package manager", DependencyCacheKey.of(entry(1, "amd64", "python", "3.13.16", Map.of("pip", "25.2", "uv", "1")), BASE, MIRRORS, RECIPE));
        variants.put("base digest", DependencyCacheKey.of(ENTRY, new Base(BASE.reference().replace("aaaa", "aaab"), "python",
                "3.13.16", "10001", "10001"), MIRRORS, RECIPE));
        variants.put("cran mirror", DependencyCacheKey.of(ENTRY, BASE, new Mirrors(URI.create("http://other:8080/cran/"),
                MIRRORS.pypiIndex()), RECIPE));
        variants.put("pypi mirror", DependencyCacheKey.of(ENTRY, BASE, new Mirrors(MIRRORS.cran(),
                URI.create("http://other:8080/pypi/simple/")), RECIPE));
        variants.put("lock bytes", DependencyCacheKey.of(ENTRY, BASE, MIRRORS, new Recipe("FROM x\n",
                Map.of("skald/requirements.lock", "shiny==1.1 --hash=sha256:00\n".getBytes(StandardCharsets.UTF_8)))));
        variants.put("lock name", DependencyCacheKey.of(ENTRY, BASE, MIRRORS, new Recipe("FROM x\n",
                Map.of("skald/other.lock", RECIPE.files().get("skald/requirements.lock")))));
        Set<String> seen = new HashSet<>(List.of(key));
        variants.forEach((what, k) -> assertTrue(seen.add(k), what + " did not move the key"));
    }

    @Test
    public void theEncodingCannotBeShiftedAcrossFieldBoundaries() {
        Map<String, String> a = new LinkedHashMap<>();
        a.put("a", "bc");
        Map<String, String> b = new LinkedHashMap<>();
        b.put("ab", "c");
        assertFalse(java.util.Arrays.equals(DependencyCacheKey.encode(a), DependencyCacheKey.encode(b)));
        Map<String, String> c = new LinkedHashMap<>();
        c.put("a", "b");
        c.put("c", "");
        Map<String, String> d = new LinkedHashMap<>();
        d.put("a", "bc");
        assertFalse(java.util.Arrays.equals(DependencyCacheKey.encode(c), DependencyCacheKey.encode(d)));
        assertTrue(new String(DependencyCacheKey.encode(Map.of()), StandardCharsets.UTF_8).contains(DependencyCacheKey.DOMAIN));
    }
}
