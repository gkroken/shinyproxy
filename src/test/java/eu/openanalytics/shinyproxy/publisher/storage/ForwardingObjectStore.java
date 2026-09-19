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
import java.util.List;
import java.util.Optional;

/**
 * Delegates every {@link ObjectStore} call, so a test can override one of them.
 *
 * <p>In test sources because it exists to force a window open at an exact point. Racing
 * two threads and hoping would give a test that passes when the race does not happen,
 * which for a concurrency guard is the worst kind of green.
 */
abstract class ForwardingObjectStore implements ObjectStore {

    private final ObjectStore delegate;

    ForwardingObjectStore(ObjectStore delegate) {
        this.delegate = delegate;
    }

    @Override
    public StoredObject put(String bucket, String key, byte[] content, String contentType) {
        return delegate.put(bucket, key, content, contentType);
    }

    @Override
    public StoredObject putStreaming(String bucket, String key, InputStream content,
                                     long declaredLength, String contentType) {
        return delegate.putStreaming(bucket, key, content, declaredLength, contentType);
    }

    @Override
    public Optional<StoredObject> putStreamingIfAbsent(String bucket, String key,
                                                       InputStream content,
                                                       long declaredLength,
                                                       String contentType) {
        return delegate.putStreamingIfAbsent(bucket, key, content, declaredLength,
                contentType);
    }

    @Override
    public Optional<StoredObject> putIfAbsent(String bucket, String key, byte[] content,
                                              String contentType) {
        return delegate.putIfAbsent(bucket, key, content, contentType);
    }

    @Override
    public Optional<StoredObject> putIfMatch(String bucket, String key, byte[] content,
                                             String contentType, String expectedEtag) {
        return delegate.putIfMatch(bucket, key, content, contentType, expectedEtag);
    }

    @Override
    public List<StoredObject> list(String bucket, String prefix) {
        return delegate.list(bucket, prefix);
    }

    @Override
    public Optional<StoredObject> head(String bucket, String key) {
        return delegate.head(bucket, key);
    }

    @Override
    public InputStream open(String bucket, String key) {
        return delegate.open(bucket, key);
    }

    @Override
    public StoredObject readVerifiedTo(String bucket, String key, String expectedSha256,
                                       OutputStream sink) {
        return delegate.readVerifiedTo(bucket, key, expectedSha256, sink);
    }

    @Override
    public byte[] readVerified(String bucket, String key, String expectedSha256) {
        return delegate.readVerified(bucket, key, expectedSha256);
    }
}
