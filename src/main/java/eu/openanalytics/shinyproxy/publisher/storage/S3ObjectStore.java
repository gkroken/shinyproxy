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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
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
            return Optional.of(StoredObject.digested(bucket, key, content.length, sha256,
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
    public StoredObject putStreaming(String bucket, String key, InputStream content,
                                     long declaredLength, String contentType) {
        return writeStreaming(bucket, key, content, declaredLength, contentType, false)
                .orElseThrow(() -> new ObjectStoreException(
                        "unconditional streaming put reported a conflict for "
                                + bucket + "/" + key));
    }

    @Override
    public Optional<StoredObject> putStreamingIfAbsent(String bucket, String key,
                                                       InputStream content,
                                                       long declaredLength,
                                                       String contentType) {
        return writeStreaming(bucket, key, content, declaredLength, contentType, true);
    }

    private Optional<StoredObject> writeStreaming(String bucket, String key,
                                                  InputStream content, long declaredLength,
                                                  String contentType, boolean onlyIfAbsent) {
        MessageDigest digest = newDigest();
        CountingStream counted = new CountingStream(new DigestInputStream(content, digest));
        PutObjectRequest.Builder request = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .contentType(contentType)
                .contentLength(declaredLength);
        if (onlyIfAbsent) {
            request.ifNoneMatch("*");
        }
        PutObjectResponse response;
        try {
            // fromInputStream with an explicit length, so the SDK streams rather than
            // buffering to discover the size. No metadata digest here: headers are sent
            // before the body is read, so there is nothing to put in them yet.
            response = client.putObject(request.build(),
                    RequestBody.fromInputStream(counted, declaredLength));
        } catch (S3Exception e) {
            if (onlyIfAbsent && e.statusCode() == 412) {
                return Optional.empty();
            }
            throw new ObjectStoreException(
                    "could not write " + bucket + "/" + key + ": " + describe(e), e);
        } catch (RuntimeException e) {
            throw new ObjectStoreException("could not write " + bucket + "/" + key, e);
        }
        // "Content-Length is a claim, checked against the bytes actually read"
        // -- spec/admin-transport-v1.json, bundle.upload.
        //
        // The two directions are caught by two different mechanisms, and only one of them
        // is ours:
        //
        //   body SHORTER than declared: the SDK runs out of bytes and throws before
        //     returning, wrapped above as "could not write". Measured: an IllegalStateException
        //     from the SDK. A count check here would never execute, so there is not one --
        //     an unreachable branch reads as a control and is not one.
        //   body LONGER than declared: the SDK stops at exactly declaredLength and every
        //     count agrees, so nothing looks wrong. A publisher understating Content-Length
        //     would have stored a silently truncated bundle that every later check accepted.
        //     The only way to know is to ask the source whether it has more, which is what
        //     the read below does.
        //
        // declaredLengthIsAClaimThatIsChecked pins both directions, so if the SDK ever
        // stops throwing on a short body that test fails rather than the behaviour changing
        // quietly.
        int trailing;
        try {
            trailing = counted.read();
        } catch (IOException e) {
            throw new ObjectStoreException(
                    "could not check for trailing bytes after " + bucket + "/" + key, e);
        }
        if (trailing != -1) {
            throw new ObjectStoreException(
                    "declared length " + declaredLength + " for " + bucket + "/" + key
                            + " but the body has more bytes than that; the object as stored "
                            + "is truncated. An upload whose receipt is never committed is "
                            + "inert and is collected by the incomplete-upload rule.");
        }
        return Optional.of(StoredObject.digested(bucket, key, counted.count(), hex(digest),
                response.eTag()));
    }

    @Override
    public StoredObject readVerifiedTo(String bucket, String key, String expectedSha256,
                                       OutputStream sink) {
        MessageDigest digest = newDigest();
        long size = 0;
        try (InputStream in = open(bucket, key)) {
            byte[] buffer = new byte[64 * 1024];
            int n;
            while ((n = in.read(buffer)) != -1) {
                digest.update(buffer, 0, n);
                sink.write(buffer, 0, n);
                size += n;
            }
        } catch (IOException e) {
            throw new ObjectStoreException("could not read " + bucket + "/" + key, e);
        }
        String actual = hex(digest);
        if (!actual.equals(expectedSha256)) {
            // The sink already holds every byte. Its owner discards it; see the javadoc.
            throw new ObjectStoreException(
                    "digest mismatch at " + bucket + "/" + key + ": expected "
                            + expectedSha256 + ", read " + actual + " over " + size
                            + " bytes");
        }
        return StoredObject.digested(bucket, key, size, actual, null);
    }

    /** Counts what was actually read, which is the size recorded for the stored object. */
    private static final class CountingStream extends FilterInputStream {
        private long count;

        CountingStream(InputStream in) {
            super(in);
        }

        long count() {
            return count;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1) {
                count++;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) {
                count += n;
            }
            return n;
        }
    }

    @Override
    public Optional<StoredObject> head(String bucket, String key) {
        try {
            HeadObjectResponse response = client.headObject(
                    HeadObjectRequest.builder().bucket(bucket).key(key).build());
            // Absent for an object written by putStreaming: the digest could not be in
            // the headers, which are sent before the body is read.
            return Optional.of(new StoredObject(bucket, key, response.contentLength(),
                    Optional.ofNullable(response.metadata().get("skald-sha256")),
                    response.eTag()));
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
        return HexFormat.of().formatHex(newDigest().digest(content));
    }

    private static String hex(MessageDigest digest) {
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
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