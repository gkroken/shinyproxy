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

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;

/**
 * {@link ObjectStore} over any S3-compatible store: AWS S3, MinIO, Ceph.
 *
 * <p><b>The digest is ours.</b> Every write and every verified read computes SHA-256 here,
 * over the bytes that actually moved. The store's ETag is recorded for diagnosis and never
 * compared: it is MD5 only for single-part uploads, is a digest-of-digests for multipart,
 * and differs between implementations. {@code readVerified} recomputes rather than trusting
 * what was recorded at write time, because a digest nothing re-checks detects nothing.
 */
public class S3ObjectStore implements ObjectStore {

    private final S3Client client;

    public S3ObjectStore(S3Client client) {
        this.client = client;
    }

    @Override
    public StoredObject put(String bucket, String key, byte[] content, String contentType) {
        return write(bucket, key, content, contentType, false)
                .orElseThrow(() -> new ObjectStoreException(
                        "unconditional put reported a conflict for " + bucket + "/" + key));
    }

    @Override
    public Optional<StoredObject> putIfAbsent(String bucket, String key, byte[] content,
                                              String contentType) {
        return write(bucket, key, content, contentType, true);
    }

    private Optional<StoredObject> write(String bucket, String key, byte[] content,
                                         String contentType, boolean onlyIfAbsent) {
        String sha256 = sha256(content);
        PutObjectRequest.Builder request = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .contentType(contentType)
                .contentLength((long) content.length)
                // Recorded on the object so the digest survives independently of our
                // database. A reader that has the object but not the row can still verify.
                .metadata(java.util.Map.of("skald-sha256", sha256));
        if (onlyIfAbsent) {
            // Evaluated by the store, atomically. A read-then-write here would let two
            // writers both observe absence and both write.
            request.ifNoneMatch("*");
        }
        try {
            PutObjectResponse response =
                    client.putObject(request.build(), RequestBody.fromBytes(content));
            return Optional.of(new StoredObject(bucket, key, content.length, sha256,
                    response.eTag()));
        } catch (S3Exception e) {
            if (onlyIfAbsent && e.statusCode() == 412) {
                // Precondition failed: something is already there. Not an error for a
                // caller that asked for create-only semantics.
                return Optional.empty();
            }
            throw new ObjectStoreException(
                    "could not write " + bucket + "/" + key + ": " + describe(e), e);
        } catch (RuntimeException e) {
            throw new ObjectStoreException(
                    "could not write " + bucket + "/" + key, e);
        }
    }

    @Override
    public Optional<StoredObject> head(String bucket, String key) {
        try {
            HeadObjectResponse response = client.headObject(
                    HeadObjectRequest.builder().bucket(bucket).key(key).build());
            return Optional.of(new StoredObject(bucket, key, response.contentLength(),
                    response.metadata().get("skald-sha256"), response.eTag()));
        } catch (NoSuchKeyException e) {
            return Optional.empty();
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                // HeadObject answers 404 with no body, so the SDK cannot always tell
                // NoSuchKey from NoSuchBucket. Absent is absent either way for this caller.
                return Optional.empty();
            }
            throw new ObjectStoreException(
                    "could not stat " + bucket + "/" + key + ": " + describe(e), e);
        } catch (RuntimeException e) {
            throw new ObjectStoreException("could not stat " + bucket + "/" + key, e);
        }
    }

    @Override
    public InputStream open(String bucket, String key) {
        try {
            return client.getObject(
                    GetObjectRequest.builder().bucket(bucket).key(key).build());
        } catch (NoSuchKeyException e) {
            throw new ObjectStoreException("no object at " + bucket + "/" + key, e);
        } catch (S3Exception e) {
            throw new ObjectStoreException(
                    "could not read " + bucket + "/" + key + ": " + describe(e), e);
        } catch (RuntimeException e) {
            throw new ObjectStoreException("could not read " + bucket + "/" + key, e);
        }
    }

    @Override
    public byte[] readVerified(String bucket, String key, String expectedSha256) {
        byte[] content;
        try (ResponseInputStream<GetObjectResponse> in =
                     (ResponseInputStream<GetObjectResponse>) open(bucket, key)) {
            content = in.readAllBytes();
        } catch (IOException e) {
            throw new ObjectStoreException("could not read " + bucket + "/" + key, e);
        }
        String actual = sha256(content);
        if (!actual.equals(expectedSha256)) {
            throw new ObjectStoreException(
                    "digest mismatch at " + bucket + "/" + key + ": expected "
                            + expectedSha256 + ", read " + actual + " over "
                            + content.length + " bytes");
        }
        return content;
    }

    /** Lower-case hex SHA-256, the one spelling the manifest schema's pattern accepts. */
    static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            // Every JVM is required to provide SHA-256.
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", e);
        }
    }

    /** The store's own words, which are what an operator needs to diagnose an outage. */
    private static String describe(S3Exception e) {
        return e.statusCode() + " "
                + (e.awsErrorDetails() == null ? "" : e.awsErrorDetails().errorCode());
    }
}