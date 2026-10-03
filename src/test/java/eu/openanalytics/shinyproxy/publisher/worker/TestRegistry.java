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
package eu.openanalytics.shinyproxy.publisher.worker;

import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.RemoveContainerParam;
import org.mandas.docker.client.exceptions.DockerException;
import org.mandas.docker.client.messages.ContainerConfig;
import org.mandas.docker.client.messages.HostConfig;
import org.mandas.docker.client.messages.NetworkConfig;
import org.mandas.docker.client.messages.PortBinding;
import org.mandas.docker.client.messages.RegistryAuth;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The operator's side of a test build: a registry that requires the credential to read or
 * write, on an outer network the gateway joins, published on 127.0.0.1 to seed and check it,
 * with busybox seeded as base/busybox:1.
 */
final class TestRegistry implements AutoCloseable {

    /** registry:2, pinned. */
    static final String IMAGE = "registry@sha256:"
            + "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373";
    static final String SECRET_A = "skaldbktsecret";
    static final String SECRET_B = "x7q2";
    static final Credential CRED = new Credential("skald-launcher", SECRET_A + SECRET_B);

    final DockerClient docker;
    final int port;
    final String outer;
    final String name;

    TestRegistry(DockerClient docker, String prefix, int port) throws Exception {
        this.docker = docker;
        this.port = port;
        String run = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        this.outer = prefix + "-outer-" + run;
        this.name = prefix + "-registry-" + run;
        docker.createNetwork(NetworkConfig.builder().name(outer).build());
        String htpasswd = CRED.username() + ":" + new BCryptPasswordEncoder().encode(CRED.password()) + "\n";
        docker.createContainer(ContainerConfig.builder().image(IMAGE)
                .env("REGISTRY_AUTH=htpasswd", "REGISTRY_AUTH_HTPASSWD_REALM=skald",
                        "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd")
                .exposedPorts("5000/tcp")
                .hostConfig(HostConfig.builder().networkMode(outer)
                        .portBindings(Map.of("5000/tcp", List.of(PortBinding.of("127.0.0.1", port))))
                        .build()).build(), name);
        docker.copyToContainer(tar("auth/htpasswd", htpasswd), name, "/");
        docker.startContainer(name);
        String base = local("base/busybox:1");
        docker.tag(Images.HELPER, base);
        for (int i = 0; ; i++) {
            try {
                docker.push(base, auth());
                break;
            } catch (DockerException e) {
                if (i >= 20) {
                    throw e;
                }
                Thread.sleep(500);
            }
        }
        docker.removeImage(base);
    }

    RegistryAuth auth() {
        return RegistryAuth.builder().username(CRED.username()).password(CRED.password())
                .serverAddress("localhost:" + port).build();
    }

    /** The name the host uses for a repository reference. */
    String local(String reference) {
        return "localhost:" + port + "/" + reference;
    }

    /** The base image as the worker names it. */
    String base() {
        return name + ":5000/base/busybox:1";
    }

    @Override
    public void close() throws Exception {
        try {
            docker.removeContainer(name, RemoveContainerParam.forceKill(), RemoveContainerParam.removeVolumes());
        } finally {
            docker.removeNetwork(outer);
        }
    }

    static ByteArrayInputStream tar(String name, String body) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (TarArchiveOutputStream t = new TarArchiveOutputStream(out)) {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            TarArchiveEntry e = new TarArchiveEntry(name);
            e.setSize(bytes.length);
            e.setMode(0644);
            t.putArchiveEntry(e);
            t.write(bytes);
            t.closeArchiveEntry();
        }
        return new ByteArrayInputStream(out.toByteArray());
    }
}
