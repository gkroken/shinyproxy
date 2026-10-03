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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.openanalytics.shinyproxy.publisher.build.BuildLoop;
import eu.openanalytics.shinyproxy.publisher.build.CoordinatorSettings;
import eu.openanalytics.shinyproxy.publisher.bundle.ExtractionLimits;
import eu.openanalytics.shinyproxy.publisher.recipe.BaseCatalog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The worker refuses to start on anything a build would otherwise meet at run time. */
public class WorkerConfigTest {

    private static final CoordinatorSettings DEFAULTS = CoordinatorSettings.fromOverrides(Map.of());

    private static WorkerConfig valid(Path workspace) {
        WorkerConfig c = new WorkerConfig();
        c.setWorkerImage("skald-buildkit-worker:test");
        c.setGatewayImage("skald-egress-gateway:test");
        c.setRegistry("skald-registry");
        c.setRegistryUsername("skald");
        c.setRegistryPassword("secret");
        c.setRepos(List.of("pypi.org"));
        c.setPrivateMirrors(List.of("forge"));
        c.setCranMirror("http://forge:8080/repository/cran-public/");
        c.setPypiMirror("http://forge:8080/repository/pypi-public/simple/");
        c.setPublishedBases(workspace.resolve("published-bases.json").toString());
        c.setWorkspace(workspace.toString());
        return c;
    }

    @Test
    public void everythingUnsetIsReportedAtOnce() {
        List<String> p = new WorkerConfig().problems(DEFAULTS);
        for (String name : List.of("worker-image", "gateway-image", "registry", "registry-username",
                "registry-password", "cran-mirror", "pypi-mirror", "published-bases", "workspace")) {
            assertTrue(p.contains("skald.builds.worker." + name + " is not set"), name + " in " + p);
        }
    }

    @Test
    public void aValidConfigurationHasNoProblemsAndEachRefusalStandsAlone(@TempDir Path dir) {
        assertEquals(List.of(), valid(dir).problems(DEFAULTS));

        WorkerConfig slowPoll = valid(dir);
        slowPoll.setPoll(DEFAULTS.renewEvery().dividedBy(2).plusMillis(1));
        assertTrue(only(slowPoll).contains("renew_every / 2"), only(slowPoll));
        WorkerConfig zeroPoll = valid(dir);
        zeroPoll.setPoll(Duration.ZERO);
        assertTrue(only(zeroPoll).contains("must be positive"), only(zeroPoll));

        WorkerConfig unreachableMirror = valid(dir);
        unreachableMirror.setCranMirror("http://cran.example.org/");
        assertTrue(only(unreachableMirror).contains("not in repos or private-mirrors"), only(unreachableMirror));

        WorkerConfig badMirror = valid(dir);
        badMirror.setPypiMirror("http://forge:8080/simple");
        assertTrue(only(badMirror).contains("plain http(s) URL ending in '/'"), only(badMirror));

        WorkerConfig noWorkspace = valid(dir);
        noWorkspace.setWorkspace(dir.resolve("absent").toString());
        assertTrue(only(noWorkspace).contains("not a writable directory"), only(noWorkspace));

        WorkerConfig tinyQuota = valid(dir);
        tinyQuota.setQuotaMegabytes(512);
        assertTrue(only(tinyQuota).contains("below 1024"), only(tinyQuota));
    }

    private static String only(WorkerConfig c) {
        List<String> p = c.problems(DEFAULTS);
        assertEquals(1, p.size(), p.toString());
        return p.get(0);
    }

    private static ApplicationContextRunner context() {
        // The binder for @ConfigurationProperties, which the application gets from Boot's
        // auto-configuration.
        return new ApplicationContextRunner()
                .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations.of(
                        org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration.class))
                .withUserConfiguration(WorkerConfig.class)
                .withBean(CoordinatorSettings.class, () -> DEFAULTS)
                .withBean(ExtractionLimits.class, ExtractionLimits::defaults);
    }

    @Test
    public void disabledMeansNoWorkerAtAll() {
        context().run(ctx -> {
            assertFalse(ctx.containsBean("skaldBuildLoop"));
            assertTrue(ctx.getBeansOfType(BuildLoop.class).isEmpty());
        });
    }

    @Test
    public void enabledWithoutADatabaseOrStorageRefusesToStart(@TempDir Path dir) {
        context().withPropertyValues("skald.builds.worker.enabled=true").run(ctx -> {
            assertTrue(ctx.getStartupFailure() != null, "the context must not start");
            String all = String.valueOf(rootMessage(ctx.getStartupFailure()));
            assertTrue(all.contains("cannot run builds"), all);
            assertTrue(all.contains("a database (spring.datasource.url)"), all);
            assertTrue(all.contains("object storage (skald.storage.endpoint)"), all);
            assertTrue(all.contains("skald.builds.worker.registry is not set"), all);
        });
    }

    @Test
    public void publishedBasesForAnotherRegistryRefuseToStart(@TempDir Path dir) throws Exception {
        // 1ffdb20 review N1: the gateway allows <registry>:5000 only, so bases published under
        // another name would fail every build at its first pull.
        byte[] catalog;
        try (InputStream in = BaseCatalog.class.getClassLoader().getResourceAsStream(BaseCatalog.CATALOG_RESOURCE)) {
            catalog = in.readAllBytes();
        }
        ObjectNode published = new ObjectMapper().createObjectNode().put("layout_version", 1)
                .put("catalog_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(catalog)))
                .put("registry", "elsewhere:5000");
        published.putObject("bases");
        Path file = Files.writeString(dir.resolve("published-bases.json"), published.toString());
        context().withPropertyValues("skald.builds.worker.enabled=true", "skald.builds.worker.registry=skald-registry",
                "skald.builds.worker.published-bases=" + file).run(ctx -> {
            String all = String.valueOf(rootMessage(ctx.getStartupFailure()));
            assertTrue(all.contains("the published bases name registry elsewhere:5000, but the worker reaches"
                    + " skald-registry:5000"), all);
        });
    }

    private static String rootMessage(Throwable t) {
        StringBuilder b = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            b.append(c.getMessage()).append('\n');
        }
        return b.toString();
    }
}
