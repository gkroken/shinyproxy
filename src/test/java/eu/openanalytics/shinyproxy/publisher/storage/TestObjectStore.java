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

import org.testcontainers.containers.GenericContainer;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

/**
 * A started MinIO with one bucket and the real {@link S3ObjectStore} over it, for tests
 * outside this package that need a log store (the build driver's).
 */
public final class TestObjectStore implements AutoCloseable {

    public final String bucket;
    public final ObjectStore store;
    private final GenericContainer<?> minio;
    private final S3Client client;

    public TestObjectStore(String bucket) {
        this.bucket = bucket;
        minio = MinioTestContainer.create("skald", "skaldskald");
        minio.start();
        client = S3Client.builder()
                .endpointOverride(java.net.URI.create("http://" + minio.getHost() + ":" + minio.getMappedPort(9000)))
                .region(Region.of("us-east-1"))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("skald", "skaldskald")))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .build();
        client.createBucket(CreateBucketRequest.builder().bucket(bucket).build());
        store = new S3ObjectStore(client);
    }

    @Override
    public void close() {
        client.close();
        minio.stop();
    }
}
