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
package eu.openanalytics.shinyproxy.publisher.storage;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The completion protocol, against real MinIO.
 *
 * <p>T4's Pass line asks for "no partial artifact advertised" and for writes killed between
 * an object and its descriptor. Both are here, and both need a real store: the protocol's
 * safety rests on conditional create, which is the store's behaviour and not ours.
 */
class BundleWriterTest {

    private static final String BUCKET = "skald-test-completion";
    private static final String USER = "skald";
    private static final String PASSWORD = "skaldskald";

    private static GenericContainer<?> minio;
    private static S3Client client;
    private static ObjectStore store;
    private static BundleWriter writer;

    @BeforeAll
    static void startMinio() {
        // Pinned by digest for the reason S3ObjectStoreTest records: the conditional-create
        // behaviour this protocol depends on belongs to a particular MinIO release.
        minio = new GenericContainer<>(DockerImageName.parse(
                "quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e"
                        + "708c1e2960462bd8936e"))
                .withCommand("server", "/data")
                .withEnv("MINIO_ROOT_USER", USER)
                .withEnv("MINIO_ROOT_PASSWORD", PASSWORD)
                .withExposedPorts(9000)
                .waitingFor(Wait.forHttp("/minio/health/live").forPort(9000));
        minio.start();

        client = S3Client.builder()
                .endpointOverride(URI.create(
                        "http://" + minio.getHost() + ":" + minio.getMappedPort(9000)))
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(USER, PASSWORD)))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
                .build();
        client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        store = new S3ObjectStore(client);
        writer = new BundleWriter(store, BUCKET);
    }

    @AfterAll
    static void stopMinio() {
        if (client != null) {
            client.close();
        }
        if (minio != null) {
            minio.stop();
        }
    }

    private static final byte[] ARCHIVE = "pretend this is a tar.gz".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MANIFEST = "{\"schema_version\":1}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INVENTORY = "{\"files\":[]}".getBytes(StandardCharsets.UTF_8);

    /** Writes the three objects a receipt describes, and returns the receipt to commit. */
    private BundleReceipt writeThreeObjects(UUID c, UUID b) {
        StoredObject archive = writer.writeArchive(c, b,
                new ByteArrayInputStream(ARCHIVE), ARCHIVE.length).orElseThrow();
        StoredObject manifest = writer.writeManifest(c, b, MANIFEST).orElseThrow();
        StoredObject inventory = writer.writeInventory(c, b, INVENTORY).orElseThrow();
        return new BundleReceipt(1, 1, c, b,
                archive.sha256().orElseThrow(), archive.size(),
                manifest.sha256().orElseThrow(), inventory.sha256().orElseThrow());
    }

    @Test
    @DisplayName("a bundle is complete only once its receipt is committed")
    void receiptIsWhatCompletesABundle() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        assertTrue(writer.readReceipt(c, b).isEmpty(), "nothing written yet");

        BundleReceipt receipt = writeThreeObjects(c, b);
        // Every byte is in the store. The bundle is still not a bundle.
        assertTrue(writer.readReceipt(c, b).isEmpty(),
                "all three objects are present but no receipt is; this must read as absent");

        assertTrue(writer.commit(receipt).isPresent());
        BundleReceipt back = writer.readReceipt(c, b).orElseThrow();
        assertEquals(receipt, back, "the receipt must survive a round trip unchanged");
        assertEquals(ARCHIVE.length, back.archiveBytes());
        assertEquals(S3ObjectStore.sha256(ARCHIVE), back.archiveSha256());
        assertEquals(S3ObjectStore.sha256(INVENTORY), back.inventorySha256());
    }

    @Test
    @DisplayName("a write killed before the receipt advertises nothing")
    void killedBetweenObjectAndReceipt() {
        // T4's Pass line: "no partial artifact advertised". Each prefix below is a crash at
        // a different point, and none of them may read as a usable bundle.
        UUID c = UUID.randomUUID();

        UUID afterArchive = UUID.randomUUID();
        writer.writeArchive(c, afterArchive, new ByteArrayInputStream(ARCHIVE), ARCHIVE.length);
        assertTrue(writer.readReceipt(c, afterArchive).isEmpty());

        UUID afterManifest = UUID.randomUUID();
        writer.writeArchive(c, afterManifest, new ByteArrayInputStream(ARCHIVE), ARCHIVE.length);
        writer.writeManifest(c, afterManifest, MANIFEST);
        assertTrue(writer.readReceipt(c, afterManifest).isEmpty());

        UUID afterInventory = UUID.randomUUID();
        writeThreeObjects(c, afterInventory);
        assertTrue(writer.readReceipt(c, afterInventory).isEmpty());

        // And the bytes really are there, so this is the protocol refusing rather than the
        // objects being absent. Without this, the three assertions above would also pass
        // against a store that had silently dropped every write.
        assertTrue(store.head(BUCKET,
                        ObjectKeys.bundleObject(c, afterInventory, ObjectKeys.BUNDLE_ARCHIVE))
                .isPresent(), "the archive must be present; otherwise this test proves nothing");
        assertTrue(store.head(BUCKET,
                        ObjectKeys.bundleObject(c, afterInventory, ObjectKeys.BUNDLE_INVENTORY))
                .isPresent());
    }

    @Test
    @DisplayName("a receipt is refused while any object it describes is missing")
    void receiptRefusedWhenAnObjectIsMissing() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        BundleReceipt claim = new BundleReceipt(1, 1, c, b,
                S3ObjectStore.sha256(ARCHIVE), ARCHIVE.length,
                S3ObjectStore.sha256(MANIFEST), S3ObjectStore.sha256(INVENTORY));

        ObjectStoreException nothing = assertThrows(ObjectStoreException.class,
                () -> writer.commit(claim));
        assertTrue(nothing.getMessage().contains(ObjectKeys.BUNDLE_ARCHIVE),
                nothing.getMessage());

        writer.writeArchive(c, b, new ByteArrayInputStream(ARCHIVE), ARCHIVE.length);
        ObjectStoreException noManifest = assertThrows(ObjectStoreException.class,
                () -> writer.commit(claim));
        assertTrue(noManifest.getMessage().contains(ObjectKeys.BUNDLE_MANIFEST),
                noManifest.getMessage());

        writer.writeManifest(c, b, MANIFEST);
        ObjectStoreException noInventory = assertThrows(ObjectStoreException.class,
                () -> writer.commit(claim));
        assertTrue(noInventory.getMessage().contains(ObjectKeys.BUNDLE_INVENTORY),
                noInventory.getMessage());

        writer.writeInventory(c, b, INVENTORY);
        assertTrue(writer.commit(claim).isPresent(), "all three present, so it commits");
    }

    @Test
    @DisplayName("a bundle id names particular bytes; a second writer is refused")
    void bundleBytesAreImmutable() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        BundleReceipt receipt = writeThreeObjects(c, b);
        writer.commit(receipt);

        byte[] different = "entirely different bytes".getBytes(StandardCharsets.UTF_8);

        // "Different bytes at the same id are the same 409 -- replacing content means a
        // fresh bundle id" -- spec/admin-transport-v1.json, bundle.upload.
        assertTrue(writer.writeArchive(c, b,
                        new ByteArrayInputStream(different), different.length).isEmpty(),
                "a second archive at the same bundle id must be refused");
        assertTrue(writer.writeManifest(c, b, different).isEmpty());
        assertTrue(writer.writeInventory(c, b, different).isEmpty());
        assertTrue(writer.commit(receipt).isEmpty(),
                "a second commit must be refused, not silently rewrite the receipt");

        // The refusals are worthless if the bytes moved anyway.
        assertArrayEquals(ARCHIVE, store.readVerified(BUCKET,
                ObjectKeys.bundleObject(c, b, ObjectKeys.BUNDLE_ARCHIVE),
                S3ObjectStore.sha256(ARCHIVE)));
        assertArrayEquals(MANIFEST, store.readVerified(BUCKET,
                ObjectKeys.bundleObject(c, b, ObjectKeys.BUNDLE_MANIFEST),
                S3ObjectStore.sha256(MANIFEST)));
        assertEquals(receipt, writer.readReceipt(c, b).orElseThrow(),
                "the committed receipt must be the original one");
    }

    @Test
    @DisplayName("the receipt records digests this platform computed, not the store's")
    void receiptCarriesOurOwnDigests() {
        UUID c = UUID.randomUUID(), b = UUID.randomUUID();
        BundleReceipt receipt = writeThreeObjects(c, b);
        writer.commit(receipt);

        Optional<StoredObject> stored = store.head(BUCKET,
                ObjectKeys.bundleObject(c, b, ObjectKeys.BUNDLE_MANIFEST));
        String etag = stored.orElseThrow().etag().replace("\"", "");
        assertFalse(receipt.archiveSha256().equals(etag),
                "a receipt digest must never be an ETag");
        assertEquals(64, receipt.archiveSha256().length());
        assertEquals(64, receipt.inventorySha256().length());

        // The inventory digest is the point of the field: it is what lets a later reader
        // tell that the file list it holds is the one that was validated.
        assertEquals(S3ObjectStore.sha256(INVENTORY), receipt.inventorySha256());
        byte[] fetched = store.readVerified(BUCKET,
                ObjectKeys.bundleObject(c, b, ObjectKeys.BUNDLE_INVENTORY),
                receipt.inventorySha256());
        assertArrayEquals(INVENTORY, fetched);
    }
}
