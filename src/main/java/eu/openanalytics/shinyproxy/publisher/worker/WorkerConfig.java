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

import eu.openanalytics.shinyproxy.publisher.build.BuildCoordinator;
import eu.openanalytics.shinyproxy.publisher.build.BuildLoop;
import eu.openanalytics.shinyproxy.publisher.build.BuildRunner;
import eu.openanalytics.shinyproxy.publisher.build.CoordinatorSettings;
import eu.openanalytics.shinyproxy.publisher.bundle.ExtractionLimits;
import eu.openanalytics.shinyproxy.publisher.recipe.BaseCatalog;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Mirrors;
import eu.openanalytics.shinyproxy.publisher.storage.BuildLogWriter;
import eu.openanalytics.shinyproxy.publisher.storage.BundleWriter;
import eu.openanalytics.shinyproxy.publisher.storage.HeadTailLog;
import eu.openanalytics.shinyproxy.publisher.storage.ObjectStore;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The build worker, wired: when {@code skald.builds.worker.enabled=true}, a loop claims
 * queued attempts and builds each on its own rootless worker (T7, part 4c).
 *
 * <p><b>It refuses to start rather than fail every build.</b> Every condition a build would
 * otherwise meet only at run time is checked here, and all of them are reported at once:
 * a database and object storage are configured; the registry, its credential, the images,
 * the workspace and the mirrors are named; the published bases file loads against the
 * shipped catalog, and its registry is the one the gateway allows, {@code <registry>:5000}
 * (1ffdb20 review N1: the gateway's registry port, buildkitd.toml's plain-http entry and the
 * client's credential are all keyed on that); each mirror's host is one the gateway lets the
 * worker reach; the poll is at most renew_every / 2 (BuildDriver's bound); the four images
 * the launcher runs are present.
 */
@Configuration
@ConditionalOnProperty(name = "skald.builds.worker.enabled", havingValue = "true")
@ConfigurationProperties(prefix = "skald.builds.worker")
public class WorkerConfig {

    private String owner;
    private String workerImage;
    private String gatewayImage;
    private String registry;
    private String registryUsername;
    private String registryPassword;
    private List<String> outerNetworks = new ArrayList<>();
    private List<String> repos = new ArrayList<>();
    private List<String> privateMirrors = new ArrayList<>();
    private String cranMirror;
    private String pypiMirror;
    private String publishedBases;
    private String workspace;
    private String architecture = "amd64";
    /**
     * The workspace quota, MiB. 8 GiB: a cold R build holds the extracted base (about 1.5
     * GiB for rocker/r-ver), BuildKit's snapshots of each step and the compiled library;
     * the 4 GiB the probes used is enough for the fixture apps and too tight for a real
     * dependency tree. T5 F6 carry (3) left the production number to this track.
     */
    private int quotaMegabytes = 8192;
    private Duration poll = Duration.ofSeconds(1);
    private Duration settle = Duration.ofSeconds(30);
    private Duration idlePause = Duration.ofSeconds(2);
    private String bundleBucket = "skald-bundles";
    private String logBucket = "skald-logs";

    @Bean(destroyMethod = "close")
    public DockerClient skaldWorkerDocker() throws Exception {
        return new JerseyDockerClientBuilder().fromEnv().build();
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    public BuildLoop skaldBuildLoop(DockerClient skaldWorkerDocker, ObjectProvider<BuildCoordinator> coordinator,
                                    CoordinatorSettings settings, ObjectProvider<ObjectStore> store,
                                    ExtractionLimits limits) throws Exception {
        List<String> problems = problems(settings);
        if (coordinator.getIfAvailable() == null) {
            problems.add("a database (spring.datasource.url): builds are leased there");
        }
        if (store.getIfAvailable() == null) {
            problems.add("object storage (skald.storage.endpoint): bundles and logs live there");
        }
        BaseCatalog catalog = null;
        if (publishedBases != null && !publishedBases.isBlank()) {
            try (InputStream in = Files.newInputStream(Path.of(publishedBases))) {
                catalog = BaseCatalog.load(in);
                if (registry != null && !(registry + ":5000").equals(catalog.registry())) {
                    problems.add("the published bases name registry " + catalog.registry() + ", but the worker"
                            + " reaches " + registry + ":5000; publish them for that registry");
                }
            } catch (Exception e) {
                problems.add("published-bases " + publishedBases + ": " + e.getMessage());
            }
        }
        if (workerImage != null && gatewayImage != null) {
            for (String image : List.of(workerImage, gatewayImage, Images.HELPER, Images.SETUP)) {
                try {
                    skaldWorkerDocker.inspectImage(image);
                } catch (Exception e) {
                    problems.add("image " + image + " is not present: " + e.getMessage());
                }
            }
        }
        refuseIf(problems);

        Images images = Images.of(workerImage, gatewayImage);
        DockerWorkerLauncher launcher = new DockerWorkerLauncher(skaldWorkerDocker, WorkerProfile.load("runc-rootless"),
                images);
        BuildKitClient client = new BuildKitClient(skaldWorkerDocker, launcher, images);
        ObjectStore objects = store.getObject();
        Mirrors mirrors = new Mirrors(URI.create(cranMirror), URI.create(pypiMirror));
        BundleContextSource source = new BundleContextSource(new BundleWriter(objects, bundleBucket), objects,
                bundleBucket, limits, Path.of(workspace), catalog, mirrors, architecture);
        BuildKitDriver driver = new BuildKitDriver(skaldWorkerDocker, launcher, client, source,
                new BuildLogWriter(objects, logBucket),
                new BuildKitDriver.Config(Settings.defaults(), quotaMegabytes,
                        new Egress(outerNetworks, registry, repos, privateMirrors, List.of(), List.of()),
                        new Credential(registryUsername, registryPassword), poll, settle, HeadTailLog.Limits.defaults()));
        return new BuildLoop(new BuildRunner(coordinator.getObject(), settings), driver,
                owner != null && !owner.isBlank() ? owner : java.net.InetAddress.getLocalHost().getHostName(),
                idlePause);
    }

    /** Every refusal that needs no Docker, catalog or bean: the configuration itself. */
    List<String> problems(CoordinatorSettings settings) {
        List<String> problems = new ArrayList<>();
        for (var named : List.of(new String[] {"worker-image", workerImage}, new String[] {"gateway-image", gatewayImage},
                new String[] {"registry", registry}, new String[] {"registry-username", registryUsername},
                new String[] {"registry-password", registryPassword}, new String[] {"cran-mirror", cranMirror},
                new String[] {"pypi-mirror", pypiMirror}, new String[] {"published-bases", publishedBases},
                new String[] {"workspace", workspace})) {
            if (named[1] == null || named[1].isBlank()) {
                problems.add("skald.builds.worker." + named[0] + " is not set");
            }
        }
        if (poll.isNegative() || poll.isZero() || poll.compareTo(settings.renewEvery().dividedBy(2)) > 0) {
            problems.add("poll " + poll + " must be positive and at most renew_every / 2 ("
                    + settings.renewEvery().dividedBy(2) + "): the driver's stop bound");
        }
        if (workspace != null && !workspace.isBlank()) {
            Path w = Path.of(workspace);
            if (!Files.isDirectory(w) || !Files.isWritable(w)) {
                problems.add("workspace " + workspace + " is not a writable directory");
            }
        }
        Set<String> allowed = new HashSet<>(repos);
        allowed.addAll(privateMirrors);
        for (String mirror : new String[] {cranMirror, pypiMirror}) {
            if (mirror == null || mirror.isBlank()) {
                continue;
            }
            try {
                String host = URI.create(mirror).getHost();
                if (host == null || !allowed.contains(host)) {
                    problems.add("mirror " + mirror + ": its host is not in repos or private-mirrors, so the"
                            + " gateway would refuse every restore");
                }
                new Mirrors(URI.create(mirror), URI.create(mirror));
            } catch (IllegalArgumentException e) {
                problems.add("mirror " + mirror + ": " + e.getMessage());
            }
        }
        if (quotaMegabytes < 1024) {
            problems.add("quota-megabytes " + quotaMegabytes + " is below 1024: no base fits");
        }
        return problems;
    }

    static void refuseIf(List<String> problems) {
        if (!problems.isEmpty()) {
            throw new IllegalStateException("skald.builds.worker is enabled but cannot run builds:\n  - "
                    + String.join("\n  - ", problems));
        }
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public void setWorkerImage(String workerImage) {
        this.workerImage = workerImage;
    }

    public void setGatewayImage(String gatewayImage) {
        this.gatewayImage = gatewayImage;
    }

    public void setRegistry(String registry) {
        this.registry = registry;
    }

    public void setRegistryUsername(String registryUsername) {
        this.registryUsername = registryUsername;
    }

    public void setRegistryPassword(String registryPassword) {
        this.registryPassword = registryPassword;
    }

    public void setOuterNetworks(List<String> outerNetworks) {
        this.outerNetworks = outerNetworks == null ? new ArrayList<>() : outerNetworks;
    }

    public void setRepos(List<String> repos) {
        this.repos = repos == null ? new ArrayList<>() : repos;
    }

    public void setPrivateMirrors(List<String> privateMirrors) {
        this.privateMirrors = privateMirrors == null ? new ArrayList<>() : privateMirrors;
    }

    public void setCranMirror(String cranMirror) {
        this.cranMirror = cranMirror;
    }

    public void setPypiMirror(String pypiMirror) {
        this.pypiMirror = pypiMirror;
    }

    public void setPublishedBases(String publishedBases) {
        this.publishedBases = publishedBases;
    }

    public void setWorkspace(String workspace) {
        this.workspace = workspace;
    }

    public void setArchitecture(String architecture) {
        this.architecture = architecture;
    }

    public void setQuotaMegabytes(int quotaMegabytes) {
        this.quotaMegabytes = quotaMegabytes;
    }

    public void setPoll(Duration poll) {
        this.poll = poll;
    }

    public void setSettle(Duration settle) {
        this.settle = settle;
    }

    public void setIdlePause(Duration idlePause) {
        this.idlePause = idlePause;
    }

    public void setBundleBucket(String bundleBucket) {
        this.bundleBucket = bundleBucket;
    }

    public void setLogBucket(String logBucket) {
        this.logBucket = logBucket;
    }
}
