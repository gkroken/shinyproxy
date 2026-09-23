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
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

/**
 * The one MinIO the storage tests run against.
 *
 * <p><b>From quay.io</b>, as WORKPLAN-DEVSTACK.md records for the dev stack: Docker Hub's
 * minio image was not usable there.
 *
 * <p><b>Pinned by digest</b>, like postgres:16 in every other container test here, and for a
 * sharper reason: the load-bearing claim of the storage suites is that the STORE enforces
 * If-None-Match on PutObject, which is a comparatively recent MinIO feature. An unpinned
 * {@code :latest} could change that and either break the suites or, worse, quietly change what
 * {@code S3ObjectStoreTest.conditionalCreateRefusesTheSecondWriter} proves while still passing.
 * Measured against RELEASE.2025-09-07T16-13-09Z; the digest is what fixes it. Four test classes
 * used to spell this digest out each; one definition means a bump cannot leave one of them
 * testing a different server.
 *
 * <p><b>Its data directory is a tmpfs.</b> MinIO writes each object synchronously to its disk,
 * and on this project's development host (WSL2) that disk is a virtual one shared with the
 * build, so those writes stall for seconds at a time under load. Measured with 600 puts of
 * mixed sizes through {@code S3ObjectStore}, twice each, identical but for this setting:
 * data on the container's disk, 25 and 30 requests over one second, worst 18.2 s and 10.4 s;
 * on tmpfs, none over one second, worst 52 ms and 46 ms. Those stalls are what made the
 * storage tests' runtimes swing between 14 s and 180 s, and the requests that failed with
 * {@code 400 IncompleteBody} were among them (finding b66dcfd-F1). The disk's latency is not
 * what these tests test: the protocol's behaviour against a real S3 implementation is, and
 * a tmpfs gives them that without an unrelated source of timing failures. The dev stack's
 * MinIO keeps a real volume, because there persistence IS the point.
 */
final class MinioTestContainer {

    static final String IMAGE =
            "quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e"
                    + "708c1e2960462bd8936e";

    private MinioTestContainer() {
    }

    /** A MinIO with the given root credentials, not yet started. */
    static GenericContainer<?> create(String rootUser, String rootPassword) {
        return new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withCommand("server", "/data")
                .withTmpFs(Map.of("/data", "rw"))
                .withEnv("MINIO_ROOT_USER", rootUser)
                .withEnv("MINIO_ROOT_PASSWORD", rootPassword)
                .withExposedPorts(9000)
                .waitingFor(Wait.forHttp("/minio/health/live").forPort(9000));
    }
}
