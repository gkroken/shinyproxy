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

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

/**
 * Writes one bundle's objects in the order the completion protocol requires.
 *
 * <p>The protocol is three sentences in the plan and every one of them is a rule here:
 *
 * <ul>
 *   <li>"{@code receipt.json} is written last" — so {@link #commit} is the only method that
 *       writes it, and it refuses unless the three objects it describes are already there.
 *   <li>"Bundle bytes are immutable once a receipt is committed" — so every object is
 *       written create-only, through the store's conditional put. A second writer at the
 *       same bundle id is refused by the store, not by a check in this process.
 *   <li>"Incomplete uploads and descriptors do not make objects public" — so
 *       {@link #readReceipt} is the only way to learn a bundle is usable, and it answers
 *       from {@code receipt.json} alone. A bundle whose archive is present and whose
 *       receipt is not reads as absent, which is what it is.
 * </ul>
 *
 * <p><b>Why the order is the safety property.</b> A crash between any two writes leaves
 * objects with no receipt. Those are inert: nothing can find them through this class, no
 * build can start from them, and the incomplete-upload rule collects them. The reverse
 * order would leave a receipt describing bytes that do not exist — a bundle that every
 * later check would accept and that no reader could fetch.
 */
public class BundleWriter {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ObjectStore store;
    private final String bucket;

    public BundleWriter(ObjectStore store, String bucket) {
        this.store = store;
        this.bucket = bucket;
    }

    /**
     * Streams the compressed archive in, create-only.
     *
     * @return the stored object, or empty if this bundle id already has an archive
     */
    public Optional<StoredObject> writeArchive(UUID contentId, UUID bundleId,
                                               InputStream archive, long declaredLength) {
        return store.putStreamingIfAbsent(bucket,
                ObjectKeys.bundleObject(contentId, bundleId, ObjectKeys.BUNDLE_ARCHIVE),
                archive, declaredLength, "application/gzip");
    }

    /** Writes {@code manifest.json}, create-only. */
    public Optional<StoredObject> writeManifest(UUID contentId, UUID bundleId,
                                                byte[] manifest) {
        return store.putIfAbsent(bucket,
                ObjectKeys.bundleObject(contentId, bundleId, ObjectKeys.BUNDLE_MANIFEST),
                manifest, "application/json");
    }

    /** Writes {@code inventory.json}, create-only. */
    public Optional<StoredObject> writeInventory(UUID contentId, UUID bundleId,
                                                 byte[] inventory) {
        return store.putIfAbsent(bucket,
                ObjectKeys.bundleObject(contentId, bundleId, ObjectKeys.BUNDLE_INVENTORY),
                inventory, "application/json");
    }

    /**
     * Commits the receipt, which is what completes the bundle.
     *
     * <p>Refuses unless the archive, manifest and inventory are all present. That check is
     * not belt-and-braces: a receipt is a claim that those three objects exist with those
     * digests, and this is the last moment anything can tell whether the claim is true.
     *
     * @return the receipt as stored, or empty if this bundle was already committed
     * @throws ObjectStoreException if an object the receipt would describe is missing
     */
    public Optional<BundleReceipt> commit(BundleReceipt receipt) {
        UUID c = receipt.contentId();
        UUID b = receipt.bundleId();
        requirePresent(c, b, ObjectKeys.BUNDLE_ARCHIVE);
        requirePresent(c, b, ObjectKeys.BUNDLE_MANIFEST);
        requirePresent(c, b, ObjectKeys.BUNDLE_INVENTORY);

        byte[] body;
        try {
            body = JSON.writeValueAsBytes(receipt);
        } catch (IOException e) {
            throw new ObjectStoreException("could not serialise the receipt for "
                    + c + "/" + b, e);
        }
        return store.putIfAbsent(bucket,
                        ObjectKeys.bundleObject(c, b, ObjectKeys.BUNDLE_RECEIPT),
                        body, "application/json")
                .map(stored -> receipt);
    }

    /**
     * The receipt, or empty if this bundle was never completed.
     *
     * <p>The only way to learn that a bundle is usable. Deliberately does not look at the
     * archive: an archive with no receipt is an abandoned upload, and reporting it as a
     * bundle is how a half-written artifact becomes a build input.
     */
    public Optional<BundleReceipt> readReceipt(UUID contentId, UUID bundleId) {
        String key = ObjectKeys.bundleObject(contentId, bundleId, ObjectKeys.BUNDLE_RECEIPT);
        if (store.head(bucket, key).isEmpty()) {
            return Optional.empty();
        }
        try (InputStream in = store.open(bucket, key)) {
            return Optional.of(JSON.readValue(new String(in.readAllBytes(),
                    StandardCharsets.UTF_8), BundleReceipt.class));
        } catch (IOException e) {
            throw new ObjectStoreException("could not read the receipt for "
                    + contentId + "/" + bundleId, e);
        }
    }

    private void requirePresent(UUID contentId, UUID bundleId, String name) {
        String key = ObjectKeys.bundleObject(contentId, bundleId, name);
        if (store.head(bucket, key).isEmpty()) {
            throw new ObjectStoreException(
                    "refusing to commit a receipt for " + contentId + "/" + bundleId
                            + ": " + name + " is not there. A receipt is a claim that the "
                            + "objects it describes exist, and this is the last moment "
                            + "anything can check it.");
        }
    }
}
