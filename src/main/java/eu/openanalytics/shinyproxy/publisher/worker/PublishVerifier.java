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

import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Claimed;
import eu.openanalytics.shinyproxy.publisher.build.BuildRunner;
import eu.openanalytics.shinyproxy.publisher.storage.BuildLogWriter;
import eu.openanalytics.shinyproxy.publisher.storage.LogFinal;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Step 5's verification, before anything may become a version (WORKPLAN-BUNDLES.md: "Verify
 * the pushed digest ... Publish a complete log descriptor"):
 * <ul>
 *   <li>the registry has a manifest at exactly the reported digest: a HEAD by digest to the
 *       registry's API, answered 200 with a Docker-Content-Digest equal to it. The
 *       reference the driver reported is {@code <registry>:5000/<repository>@sha256:<hex>};
 *       only the repository and digest are used, against {@code registryApi}, the registry
 *       as ShinyProxy reaches it.</li>
 *   <li>the attempt's log is finished: final.json exists, is complete, says BUILT, and was
 *       written by this attempt's lease generation. Its last sequence is the committed log
 *       cursor.</li>
 * </ul>
 * Anything else throws, and the runner fails the attempt (PUBLISHING -> FAILED). Basic
 * authentication with the build credential; a registry that wants bearer tokens is
 * refused by name, and per-repository scoping is T9's registry choice (94b4dae N3).
 */
public final class PublishVerifier implements BuildRunner.Publishing {

    private static final Pattern IMAGE = Pattern.compile(
            "[a-z0-9.-]+:5000/([a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)"
                    + "@(sha256:[0-9a-f]{64})");
    private static final String ACCEPT = String.join(", ",
            "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json");

    private final URI registryApi;
    private final Credential credential;
    private final BuildLogWriter logs;
    private final HttpClient http;

    public PublishVerifier(URI registryApi, Credential credential, BuildLogWriter logs) {
        this(registryApi, credential, logs, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    PublishVerifier(URI registryApi, Credential credential, BuildLogWriter logs, HttpClient http) {
        String api = registryApi.toString();
        if (!(api.startsWith("http://") || api.startsWith("https://")) || api.endsWith("/")) {
            throw new IllegalArgumentException("registry-api is http(s)://host[:port] with no trailing '/': " + api);
        }
        this.registryApi = registryApi;
        this.credential = credential;
        this.logs = logs;
        this.http = http;
    }

    @Override
    public long publish(Claimed build, String image) throws Exception {
        Matcher m = IMAGE.matcher(image);
        if (!m.matches()) {
            throw new IllegalStateException("not a pushed image by digest: " + image);
        }
        String repository = m.group(1);
        String digest = m.group(2);
        HttpResponse<Void> head = http.send(HttpRequest.newBuilder(
                        URI.create(registryApi + "/v2/" + repository + "/manifests/" + digest))
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .header("Accept", ACCEPT)
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (credential.username() + ":" + credential.password()).getBytes(StandardCharsets.UTF_8)))
                .timeout(Duration.ofSeconds(30))
                .build(), HttpResponse.BodyHandlers.discarding());
        if (head.statusCode() == 401 && head.headers().firstValue("WWW-Authenticate").orElse("").startsWith("Bearer")) {
            throw new IllegalStateException("the registry wants bearer tokens; only basic authentication is supported");
        }
        if (head.statusCode() != 200) {
            throw new IllegalStateException("the registry answered " + head.statusCode() + " for " + repository + "@"
                    + digest);
        }
        String served = head.headers().firstValue("Docker-Content-Digest").orElse("");
        if (!served.equals(digest)) {
            throw new IllegalStateException("the registry serves " + repository + " as " + served + ", not " + digest);
        }
        LogFinal fin = logs.readFinal(build.contentId(), build.buildId())
                .orElseThrow(() -> new IllegalStateException("the build log has no final.json"));
        if (!fin.complete() || !"BUILT".equals(fin.outcome()) || fin.generation() != build.lease().generation()) {
            throw new IllegalStateException("the build log is not this attempt's complete BUILT log: " + fin);
        }
        return fin.lastSequence();
    }
}
