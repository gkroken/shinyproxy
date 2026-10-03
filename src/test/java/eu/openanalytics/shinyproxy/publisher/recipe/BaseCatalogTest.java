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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Base;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The shipped catalog with a deployment's published bases: what resolves, and what is refused. */
public class BaseCatalogTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String R = "r-shiny-4.6.1-amd64-r1";
    private static final String PY = "python-shiny-3.13.16-amd64-r1";
    private static final String REG = "skald-registry:5000";

    private static byte[] catalog() throws Exception {
        return Files.readAllBytes(Path.of("images/catalog.json"));
    }

    private static String ref(String id, char fill) {
        return REG + "/skald/base/" + id + "@sha256:" + String.valueOf(fill).repeat(64);
    }

    private static ObjectNode published(byte[] catalog) {
        ObjectNode p = JSON.createObjectNode();
        p.put("layout_version", 1);
        p.put("catalog_sha256", BaseCatalog.sha256(catalog));
        p.put("registry", REG);
        p.putObject("bases").put(R, ref(R, 'a')).put(PY, ref(PY, 'b'));
        return p;
    }

    private static byte[] bytes(ObjectNode n) {
        return n.toString().getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void eachManifestResolvesToItsPublishedDigestAndTheUnprivilegedUser() throws Exception {
        byte[] c = catalog();
        BaseCatalog cat = BaseCatalog.load(c, bytes(published(c)));
        Base r = cat.resolve("shiny", "r", "4.6.1", "amd64").orElseThrow();
        assertEquals(ref(R, 'a'), r.reference());
        assertEquals("r", r.language());
        assertEquals("4.6.1", r.version());
        assertEquals("10001", r.uid());
        assertEquals("10001", r.gid());
        assertEquals(ref(PY, 'b'), cat.resolve("shiny", "python", "3.13.16", "amd64").orElseThrow().reference());
        assertEquals(Optional.empty(), cat.resolve("shiny", "r", "4.5.0", "amd64"), "no such base");
        assertEquals(Optional.empty(), cat.resolve("shiny", "r", "4.6.1", "arm64"));
        assertEquals(Optional.empty(), cat.resolve("quarto", "r", "4.6.1", "amd64"));
    }

    @Test
    public void theShippedCatalogIsTheReviewedFileByteForByte() throws Exception {
        try (InputStream in = BaseCatalog.class.getClassLoader().getResourceAsStream(BaseCatalog.CATALOG_RESOURCE)) {
            assertArrayEquals(catalog(), in.readAllBytes(), "the resource is images/catalog.json, unfiltered");
        }
        byte[] c = catalog();
        BaseCatalog cat = BaseCatalog.load(new ByteArrayInputStream(bytes(published(c))));
        assertEquals(List.of(R, PY), cat.entries().stream().map(BaseCatalog.Entry::id).toList());
    }

    @Test
    public void aBaseThatWasNotPublishedCannotBeBuiltFrom() throws Exception {
        byte[] c = catalog();
        ObjectNode p = published(c);
        ((ObjectNode) p.get("bases")).remove(PY);
        BaseCatalog cat = BaseCatalog.load(c, bytes(p));
        assertTrue(cat.resolve("shiny", "r", "4.6.1", "amd64").isPresent());
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> cat.resolve("shiny", "python", "3.13.16", "amd64"));
        assertTrue(e.getMessage().contains("not published"), e.getMessage());
    }

    @Test
    public void aPublishedFileFromAnotherCatalogIsRefused() throws Exception {
        byte[] c = catalog();
        byte[] p = bytes(published(c));
        byte[] changed = new String(c, StandardCharsets.UTF_8).replace("\"port\": 3838", "\"port\": 3839")
                .getBytes(StandardCharsets.UTF_8);
        assertTrue(!java.util.Arrays.equals(c, changed), "the catalog changed");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(changed, p));
        assertTrue(e.getMessage().contains("publish the bases again"), e.getMessage());
    }

    @Test
    public void everyMalformedPublishedFileIsRefused() throws Exception {
        byte[] c = catalog();
        Map<String, Consumer<ObjectNode>> bad = new java.util.LinkedHashMap<>();
        bad.put("an unknown key", p -> p.put("note", "x"));
        bad.put("layout 2", p -> p.put("layout_version", 2));
        bad.put("layout as text", p -> p.put("layout_version", "1"));
        bad.put("no catalog hash", p -> p.remove("catalog_sha256"));
        bad.put("upper-case hash", p -> p.put("catalog_sha256", BaseCatalog.sha256(c).toUpperCase()));
        bad.put("upper-case registry", p -> p.put("registry", "Skald-Registry:5000"));
        bad.put("registry with a path", p -> p.put("registry", "skald-registry:5000/x"));
        bad.put("registry with a space", p -> p.put("registry", "skald registry"));
        bad.put("an id not in the catalog", p -> ((ObjectNode) p.get("bases")).put("r-shiny-9.9.9-amd64-r1",
                ref("r-shiny-9.9.9-amd64-r1", 'c')));
        bad.put("one id at another's repository", p -> ((ObjectNode) p.get("bases")).put(R, ref(PY, 'a')));
        bad.put("another registry", p -> ((ObjectNode) p.get("bases")).put(R,
                "elsewhere:5000/skald/base/" + R + "@sha256:" + "a".repeat(64)));
        bad.put("a tag", p -> ((ObjectNode) p.get("bases")).put(R, REG + "/skald/base/" + R + ":latest"));
        bad.put("a short digest", p -> ((ObjectNode) p.get("bases")).put(R, REG + "/skald/base/" + R + "@sha256:abc"));
        bad.put("upper-case digest", p -> ((ObjectNode) p.get("bases")).put(R,
                REG + "/skald/base/" + R + "@sha256:" + "A".repeat(64)));
        bad.put("a digest with more after it", p -> ((ObjectNode) p.get("bases")).put(R, ref(R, 'a') + "x"));
        bad.put("a reference that is not text", p -> ((ObjectNode) p.get("bases")).put(R, 7));
        bad.put("bases as a list", p -> p.putArray("bases"));
        for (Map.Entry<String, Consumer<ObjectNode>> b : bad.entrySet()) {
            ObjectNode p = published(c);
            b.getValue().accept(p);
            assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(c, bytes(p)), b.getKey());
        }
        assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(c, "[]".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void aRegistryThatIsNotAHostIsRefusedEvenWhenTheReferencesAgreeWithIt() throws Exception {
        // The references are rewritten to the bad registry, so the per-reference check passes
        // and only the registry's own check can refuse: a "registry" with a path would
        // otherwise let a published file point a base at any repository.
        byte[] c = catalog();
        for (String bad : List.of("skald-registry:5000/elsewhere", "Skald-Registry:5000", "skald registry",
                "skald-registry:", "-skald:5000", "skald..registry", "")) {
            ObjectNode p = published(c);
            p.put("registry", bad);
            ((ObjectNode) p.get("bases")).put(R, bad + "/skald/base/" + R + "@sha256:" + "a".repeat(64))
                    .put(PY, bad + "/skald/base/" + PY + "@sha256:" + "b".repeat(64));
            assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(c, bytes(p)), bad);
        }
        for (String good : List.of("skald-registry:5000", "registry", "registry.example.org:443", "10.0.0.5:5000")) {
            ObjectNode p = published(c);
            p.put("registry", good);
            ((ObjectNode) p.get("bases")).put(R, good + "/skald/base/" + R + "@sha256:" + "a".repeat(64))
                    .put(PY, good + "/skald/base/" + PY + "@sha256:" + "b".repeat(64));
            assertTrue(BaseCatalog.load(c, bytes(p)).resolve("shiny", "r", "4.6.1", "amd64").isPresent(), good);
        }
    }

    /**
     * An operator's check: with SKALD_PUBLISHED_BASES naming a file dev/publish-bases.py
     * wrote, the shipped catalog loads it and every base it published resolves to it.
     */
    @Test
    @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SKALD_PUBLISHED_BASES", matches = ".+")
    public void anOperatorsPublishedBasesFileLoadsAndResolves() throws Exception {
        Path file = Path.of(System.getenv("SKALD_PUBLISHED_BASES"));
        BaseCatalog cat;
        try (InputStream in = Files.newInputStream(file)) {
            cat = BaseCatalog.load(in);
        }
        var bases = JSON.readTree(file.toFile()).path("bases");
        assertTrue(bases.size() > 0, "the file publishes something");
        for (BaseCatalog.Entry e : cat.entries()) {
            if (bases.has(e.id())) {
                Base b = cat.resolve(e.type(), e.language(), e.version(), e.architecture()).orElseThrow();
                assertEquals(bases.path(e.id()).asText(), b.reference(), e.id());
                System.out.println("SKALD-PUBLISHED " + e.id() + " -> " + b.reference());
            }
        }
    }

    @Test
    public void theNewestRecipeRevisionIsChosen() throws Exception {
        ObjectNode cat = (ObjectNode) JSON.readTree(catalog());
        ObjectNode r2 = ((ObjectNode) cat.get("bases").get(0)).deepCopy();
        r2.put("id", "r-shiny-4.6.1-amd64-r2").put("recipe_revision", 2);
        ((com.fasterxml.jackson.databind.node.ArrayNode) cat.get("bases")).add(r2);
        byte[] c = bytes(cat);
        ObjectNode p = published(c);
        ((ObjectNode) p.get("bases")).put("r-shiny-4.6.1-amd64-r2", ref("r-shiny-4.6.1-amd64-r2", 'd'));
        assertEquals(ref("r-shiny-4.6.1-amd64-r2", 'd'),
                BaseCatalog.load(c, bytes(p)).resolve("shiny", "r", "4.6.1", "amd64").orElseThrow().reference());
    }

    @Test
    public void aCatalogWithARootUserOrADuplicateIdIsRefused() throws Exception {
        // 1ffdb20-F1: root by any spelling Docker reads as 0, and root's group.
        for (String user : List.of("0:0", "00:00", "000000000:0", "10001:0", "10001:00", "010001:10001",
                "0:10001", "root:root", "10001", "-1:10001")) {
            ObjectNode root = (ObjectNode) JSON.readTree(catalog());
            ((ObjectNode) root.get("bases").get(0)).put("user", user);
            byte[] c1 = bytes(root);
            assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(c1, bytes(published(c1))), user);
        }
        // c939203 review N2: a package-manager version that is not text would feed the cache
        // key as "".
        for (var badVersion : List.<java.util.function.Consumer<ObjectNode>>of(
                pm -> pm.put("renv", 1), pm -> pm.putNull("renv"), pm -> pm.put("renv", ""),
                pm -> pm.putObject("renv"))) {
            ObjectNode cat = (ObjectNode) JSON.readTree(catalog());
            badVersion.accept((ObjectNode) cat.get("bases").get(0).get("package_manager"));
            byte[] c3 = bytes(cat);
            assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(c3, bytes(published(c3))));
        }
        ObjectNode dup = (ObjectNode) JSON.readTree(catalog());
        ((ObjectNode) dup.get("bases").get(1)).put("id", R);
        byte[] c2 = bytes(dup);
        ObjectNode p = published(c2);
        ((ObjectNode) p.get("bases")).remove(PY);
        assertThrows(IllegalArgumentException.class, () -> BaseCatalog.load(c2, bytes(p)));
    }
}
