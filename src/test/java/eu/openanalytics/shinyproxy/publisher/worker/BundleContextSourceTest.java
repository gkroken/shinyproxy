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
package eu.openanalytics.shinyproxy.publisher.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Claimed;
import eu.openanalytics.shinyproxy.publisher.build.Lease;
import eu.openanalytics.shinyproxy.publisher.bundle.BundleRejection;
import eu.openanalytics.shinyproxy.publisher.bundle.ExtractionLimits;
import eu.openanalytics.shinyproxy.publisher.bundle.ManifestValidator;
import eu.openanalytics.shinyproxy.publisher.recipe.BaseCatalog;
import eu.openanalytics.shinyproxy.publisher.recipe.LockRejection;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Mirrors;
import eu.openanalytics.shinyproxy.publisher.storage.BundleReceipt;
import eu.openanalytics.shinyproxy.publisher.storage.BundleWriter;
import eu.openanalytics.shinyproxy.publisher.storage.TestObjectStore;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitDriver.Prepared;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A stored bundle to a build context, against real MinIO: what is produced, and what is refused. */
public class BundleContextSourceTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PY_ID = "python-shiny-3.13.16-amd64-r1";
    private static final String PY_REF = "skald-registry:5000/skald/base/" + PY_ID + "@sha256:" + "b".repeat(64);
    private static final Mirrors MIRRORS = new Mirrors(URI.create("http://forge:8080/repository/cran-public/"),
            URI.create("http://forge:8080/repository/pypi-public/simple/"));
    private static TestObjectStore objects;
    private static BundleWriter bundles;
    private static BaseCatalog catalog;

    @BeforeAll
    public static void start() throws Exception {
        objects = new TestObjectStore("skald-bcs-bundles");
        bundles = new BundleWriter(objects.store, objects.bucket);
        byte[] catalogBytes;
        try (InputStream in = BaseCatalog.class.getClassLoader().getResourceAsStream(BaseCatalog.CATALOG_RESOURCE)) {
            catalogBytes = in.readAllBytes();
        }
        ObjectNode published = JSON.createObjectNode().put("layout_version", 1)
                .put("catalog_sha256", sha256(catalogBytes)).put("registry", "skald-registry:5000");
        published.putObject("bases").put(PY_ID, PY_REF);
        catalog = BaseCatalog.load(new ByteArrayInputStream(published.toString().getBytes(StandardCharsets.UTF_8)));
    }

    @AfterAll
    public static void stop() {
        if (objects != null) {
            objects.close();
        }
    }

    private static String sha256(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    private static Map<String, byte[]> pythonApp() throws Exception {
        Map<String, byte[]> payload = new LinkedHashMap<>();
        payload.put("app.py", Files.readAllBytes(Path.of("dev/fixtures/apps/python-shiny/app.py")));
        payload.put("requirements.lock", Files.readAllBytes(Path.of("dev/fixtures/apps/python-shiny/requirements.lock")));
        return payload;
    }

    private static byte[] manifest(Map<String, byte[]> payload, String version) throws Exception {
        ObjectNode doc = JSON.createObjectNode();
        doc.put("schema_version", 1).put("type", "shiny");
        doc.putObject("runtime").put("language", "python").put("version", version);
        doc.put("entrypoint", "app.py");
        doc.putObject("dependencies").put("format", "pip-hashed").put("path", "requirements.lock");
        ArrayNode files = doc.putArray("files");
        for (Map.Entry<String, byte[]> f : payload.entrySet()) {
            files.addObject().put("path", f.getKey()).put("size", f.getValue().length).put("sha256", sha256(f.getValue()));
        }
        return JSON.writeValueAsBytes(doc);
    }

    /** manifest.json first, then every payload file under app/, as one gzip member. */
    private static byte[] archive(byte[] manifest, Map<String, byte[]> payload) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out); TarArchiveOutputStream tar = new TarArchiveOutputStream(gz)) {
            Map<String, byte[]> all = new LinkedHashMap<>();
            all.put("manifest.json", manifest);
            payload.forEach((k, v) -> all.put("app/" + k, v));
            for (Map.Entry<String, byte[]> f : all.entrySet()) {
                TarArchiveEntry e = new TarArchiveEntry(f.getKey());
                e.setSize(f.getValue().length);
                e.setMode(0644);
                tar.putArchiveEntry(e);
                tar.write(f.getValue());
                tar.closeArchiveEntry();
            }
        }
        return out.toByteArray();
    }

    /** Stores the bundle as the upload path does; {@code receiptSha} overrides the receipt's archive digest. */
    private static Claimed store(byte[] manifest, byte[] archive, String receiptSha) throws Exception {
        UUID content = UUID.randomUUID();
        UUID bundle = UUID.randomUUID();
        bundles.writeArchive(content, bundle, new ByteArrayInputStream(archive), archive.length);
        bundles.writeManifest(content, bundle, manifest);
        byte[] inventory = "{}".getBytes(StandardCharsets.UTF_8);
        bundles.writeInventory(content, bundle, inventory);
        bundles.commit(new BundleReceipt(1, 1, content, bundle, receiptSha == null ? sha256(archive) : receiptSha,
                archive.length, sha256(manifest), sha256(inventory))).orElseThrow();
        UUID build = UUID.randomUUID();
        return new Claimed(build, content, bundle, Map.of(), new Lease(build, 1, "test"));
    }

    private static BundleContextSource source(Path workspace) {
        return new BundleContextSource(bundles, objects.store, objects.bucket, ExtractionLimits.defaults(), workspace,
                catalog, MIRRORS, "amd64");
    }

    private static List<Path> left(Path workspace) throws Exception {
        try (Stream<Path> s = Files.list(workspace)) {
            return s.toList();
        }
    }

    @Test
    public void aStoredBundleBecomesItsPayloadAndTheServersRecipe(@TempDir Path workspace) throws Exception {
        Map<String, byte[]> app = pythonApp();
        byte[] manifest = manifest(app, "3.13.16");
        Claimed c = store(manifest, archive(manifest, app), null);
        Prepared p = source(workspace).prepare(c);
        try {
            assertEquals("content/" + c.contentId(), p.repository());
            assertTrue(Files.isRegularFile(p.payload().resolve("app.py")));
            assertTrue(java.util.Arrays.equals(app.get("app.py"), Files.readAllBytes(p.payload().resolve("app.py"))));
            assertTrue(p.recipe().dockerfile().contains("FROM " + PY_REF + "\n"), p.recipe().dockerfile());
            // The recipe the generator writes for this base, manifest and lock: nothing else.
            var expected = eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.generate(
                    catalog.resolve("shiny", "python", "3.13.16", "amd64").orElseThrow(), MIRRORS,
                    ManifestValidator.validate(manifest, ExtractionLimits.defaults()), app.get("requirements.lock"));
            assertEquals(expected.dockerfile(), p.recipe().dockerfile());
            assertEquals(expected.files().keySet(), p.recipe().files().keySet());
            for (String k : expected.files().keySet()) {
                assertTrue(java.util.Arrays.equals(expected.files().get(k), p.recipe().files().get(k)), k);
            }
        } finally {
            p.release().run();
        }
        assertFalse(Files.exists(p.payload().resolve("app.py")), "release deleted the payload");
    }

    @Test
    public void everyRefusalLeavesTheWorkspaceEmpty(@TempDir Path workspace) throws Exception {
        Map<String, byte[]> app = pythonApp();
        byte[] manifest = manifest(app, "3.13.16");
        byte[] archive = archive(manifest, app);
        BundleContextSource s = source(workspace);

        UUID content = UUID.randomUUID();
        Claimed none = new Claimed(UUID.randomUUID(), content, UUID.randomUUID(), Map.of(),
                new Lease(UUID.randomUUID(), 1, "test"));
        Exception e = assertThrows(IllegalStateException.class, () -> s.prepare(none));
        assertTrue(e.getMessage().contains("no receipt"), e.getMessage());

        // The stored archive is not the one its receipt names.
        Claimed tampered = store(manifest, archive, "0".repeat(64));
        e = assertThrows(IllegalStateException.class, () -> s.prepare(tampered));
        assertTrue(e.getMessage().contains("SHA-256"), e.getMessage());
        assertEquals(List.of(), left(workspace));

        // A runtime the catalog has no base for.
        byte[] old = manifest(app, "3.12");
        e = assertThrows(IllegalStateException.class, () -> s.prepare(store(old, archive(old, app), null)));
        assertTrue(e.getMessage().contains("no trusted base"), e.getMessage());
        assertEquals(List.of(), left(workspace));

        // A lock the policy refuses (no hashes).
        Map<String, byte[]> unhashed = new LinkedHashMap<>(app);
        unhashed.put("requirements.lock", "shiny==1.0.0\n".getBytes(StandardCharsets.UTF_8));
        byte[] um = manifest(unhashed, "3.13.16");
        assertThrows(LockRejection.class, () -> s.prepare(store(um, archive(um, unhashed), null)));
        assertEquals(List.of(), left(workspace));

        // An archive the extractor refuses: a file whose bytes are not what the manifest says.
        Map<String, byte[]> lying = new LinkedHashMap<>(app);
        lying.put("app.py", "print('not what the manifest hashed')\n".getBytes(StandardCharsets.UTF_8));
        byte[] lm = manifest(app, "3.13.16");
        assertThrows(BundleRejection.class, () -> s.prepare(store(lm, archive(lm, lying), null)));
        assertEquals(List.of(), left(workspace));
    }
}
