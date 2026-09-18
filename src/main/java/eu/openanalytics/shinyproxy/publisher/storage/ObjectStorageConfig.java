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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;

import java.net.URI;

/**
 * Builds the S3 client, and does so explicitly in the two places the defaults are wrong here.
 *
 * <p><b>The HTTP client is named, not discovered.</b> ContainerProxy already puts
 * {@code apache-client} and {@code netty-nio-client} on this classpath through its own SDK
 * dependencies, alongside the {@code url-connection-client} this project declares. The SDK
 * resolves an HTTP implementation by scanning the classpath when none is set, and with more
 * than one present that resolution is ambiguous. Naming it here is the fix;
 * {@code AwsSdkClasspathTest} keeps the versions aligned but cannot make discovery
 * deterministic.
 *
 * <p><b>Path-style addressing is the default here, unlike the SDK's.</b> Virtual-host style
 * puts the bucket in the hostname, which needs wildcard DNS; a self-hosted MinIO or Ceph
 * behind one hostname does not have it. Operators pointing at real AWS S3 can turn it off.
 *
 * <p>The whole thing is conditional on {@code skald.storage.endpoint}, so a deployment
 * without the publishing layer boots exactly as upstream does — the same shape
 * {@code DataSourceConfig} uses, and for the same reason.
 */
@Configuration
@ConditionalOnProperty(name = "skald.storage.endpoint")
public class ObjectStorageConfig {

    @Bean
    public S3Client skaldS3Client(
            @Value("${skald.storage.endpoint}") String endpoint,
            @Value("${skald.storage.region:us-east-1}") String region,
            @Value("${skald.storage.access-key}") String accessKey,
            @Value("${skald.storage.secret-key}") String secretKey,
            @Value("${skald.storage.path-style:true}") boolean pathStyle) {

        return S3Client.builder()
                .endpointOverride(URI.create(endpoint))
                // Region is required by the signer even where the store ignores it; MinIO
                // accepts any value, so this is a signing input rather than a location.
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey)))
                .httpClient(UrlConnectionHttpClient.create())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(pathStyle)
                        .build())
                .build();
    }

    @Bean
    public ObjectStore objectStore(S3Client skaldS3Client) {
        return new S3ObjectStore(skaldS3Client);
    }
}
