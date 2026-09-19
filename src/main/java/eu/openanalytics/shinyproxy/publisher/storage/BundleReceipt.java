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

import java.util.UUID;

/**
 * The record that makes a bundle complete, and the only thing that does.
 *
 * <p>Written last, after the archive, the manifest and the inventory. Its presence is the
 * definition of a finished upload: the plan says "Bundle bytes are immutable once a receipt
 * is committed" and "{@code receipt.json} is written last", so a bundle whose receipt is
 * absent is an upload that was abandoned, not a bundle that is missing a file.
 *
 * <p>Nothing here is taken from the store. The digests and byte counts are what this
 * platform computed over the bytes it wrote, for the reason {@link StoredObject} records:
 * an ETag is not a content hash.
 *
 * @param layoutVersion  the key layout this bundle was written under, so a future layout
 *                       can be told apart from this one without guessing from the keys
 * @param schemaVersion  the manifest schema version the manifest claims
 * @param contentId      the content this bundle belongs to
 * @param bundleId       this upload; names particular bytes and is never reused
 * @param archiveSha256  SHA-256 of the compressed archive as stored
 * @param archiveBytes   length of the compressed archive as counted while writing
 * @param manifestSha256 SHA-256 of {@code manifest.json} as stored
 * @param inventorySha256 SHA-256 of {@code inventory.json} as stored — the "inventory
 *                       digest" the plan requires, which is what lets a later reader tell
 *                       that the file list it is holding is the one that was validated
 */
public record BundleReceipt(int layoutVersion,
                            int schemaVersion,
                            UUID contentId,
                            UUID bundleId,
                            String archiveSha256,
                            long archiveBytes,
                            String manifestSha256,
                            String inventorySha256) {
}
