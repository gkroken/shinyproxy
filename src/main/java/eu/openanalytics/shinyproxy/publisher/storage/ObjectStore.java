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

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Optional;

/**
 * Durable object storage for bundles, build logs and rendered output.
 *
 * <p>The platform reads and writes through this; a build never does. Decision 8 and the
 * storage section of the plan both say so: a worker receives no bucket credentials and no
 * arbitrary object key, which is why this interface takes keys from {@link ObjectKeys}
 * rather than strings a caller composed.
 *
 * <p><b>A storage failure is a storage failure.</b> Every method throws
 * {@link ObjectStoreException} rather than returning a sentinel or falling back to the
 * filesystem. The plan is explicit that a MinIO outage "must be an explicit storage
 * failure" and that transient scratch is "never a filesystem durability fallback" — a
 * silent fallback would let the platform report a version as published while its bytes
 * exist only on one node's disk.
 */
public interface ObjectStore {

    /**
     * Writes a small object held in memory.
     *
     * <p>For {@code manifest.json}, {@code inventory.json}, {@code receipt.json} and
     * {@code descriptor.json}, which are small by construction. A bundle archive is not:
     * use {@link #putStreaming}.
     *
     * <p>The digest in the result is computed by this platform over the bytes it wrote,
     * never taken from the store's ETag. An ETag is MD5 only for single-part uploads and is
     * documented as unreliable as a content hash; the plan requires a server-calculated
     * SHA-256, and a checksum a publisher's bytes could influence is not a checksum.
     */
    StoredObject put(String bucket, String key, byte[] content, String contentType);

    /**
     * Writes an object from a stream, digesting as the bytes pass, never holding them whole.
     *
     * <p>This exists because the admin transport frozen at T1(e) requires it, in terms.
     * {@code spec/admin-transport-v1.json}, {@code bundle.upload}: "Streamed to object
     * storage under the configured limits and never buffered whole; Content-Length is a
     * claim, checked against the bytes actually read." With a 256 MiB compressed bundle
     * limit, a {@code byte[]} interface would put 256 MiB on the heap per concurrent
     * upload — and this project has already measured that shape costing a 924 MiB peak in a
     * much smaller setting (finding {@code 6987f01-F1}).
     *
     * <p><b>{@code declaredLength} is treated as a claim.</b> The bytes actually read are
     * counted, and a mismatch is an {@link ObjectStoreException}, not a silent truncation
     * or a short object.
     *
     * <p>Unlike {@link #put}, the digest is <em>not</em> also recorded as object metadata:
     * metadata travels in the request headers, which are sent before the body has been
     * read, so it cannot contain a digest of bytes that have not yet passed. The durable
     * record is {@code receipt.json}, which the plan already requires to carry the
     * compressed SHA-256 and to be written last.
     */
    StoredObject putStreaming(String bucket, String key, InputStream content,
                              long declaredLength, String contentType);

    /**
     * Writes an object only if the key does not already exist.
     *
     * <p>Used for log chunks, where "a single trusted log writer conditionally creates
     * chunks and rejects an attempt to replace different bytes at an existing sequence".
     * The condition is evaluated by the store, not by a read-then-write in this process:
     * two writers racing would both read absent and both write.
     *
     * @return the stored object, or empty if something was already at that key
     */
    Optional<StoredObject> putIfAbsent(String bucket, String key, byte[] content,
                                       String contentType);

    /** Metadata for an object, or empty if it is not there. */
    Optional<StoredObject> head(String bucket, String key);

    /**
     * Opens an object for reading. The caller closes it.
     *
     * @throws ObjectStoreException if the object does not exist
     */
    InputStream open(String bucket, String key);

    /**
     * Streams an object to {@code sink}, verifying its SHA-256 as the bytes pass.
     *
     * <p>The streaming counterpart of {@link #readVerified}, for objects too large to hold.
     *
     * <p><b>The caller must treat {@code sink} as poisoned until this returns.</b> A
     * mismatch is only knowable after the last byte, so by the time it throws, everything
     * has already been written. Write to a temporary location and promote it on success —
     * which is the same discipline the completion protocol applies to the artifacts
     * themselves.
     *
     * @throws ObjectStoreException if the object is absent or its digest does not match
     */
    StoredObject readVerifiedTo(String bucket, String key, String expectedSha256,
                                OutputStream sink);

    /**
     * Reads an object whole and verifies it against an expected SHA-256.
     *
     * <p>Separate from {@link #open} because the plan requires re-verification rather than
     * trust: "Copy/re-extraction by a worker verifies the recorded digest again." Bit rot,
     * a truncated transfer and a substituted object are all things a stored digest catches
     * only if something actually compares it.
     *
     * @throws ObjectStoreException if the object is absent or its digest does not match
     */
    byte[] readVerified(String bucket, String key, String expectedSha256);
}
