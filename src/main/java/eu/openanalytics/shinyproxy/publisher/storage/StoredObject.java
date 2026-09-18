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

/**
 * What the store actually holds at a key.
 *
 * @param bucket    the bucket it lives in
 * @param key       its key, as built by {@link ObjectKeys}
 * @param size      length in bytes, as counted by this platform
 * @param sha256    lower-case hex SHA-256, computed here over the bytes written or read,
 *                  never the store's ETag
 * @param etag      the store's own tag, carried for diagnosis only. It is deliberately NOT
 *                  a content hash: for a multipart upload it is a digest of part digests,
 *                  and AWS documents it as unsuitable for integrity checking. Recorded so
 *                  that a support question can be answered, never compared against
 *                  {@code sha256}.
 */
public record StoredObject(String bucket, String key, long size, String sha256, String etag) {
}
