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
package eu.openanalytics.shinyproxy.publisher.registry;

import eu.openanalytics.containerproxy.ContainerProxyApplication;
import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.test.helpers.ShinyProxyClient;
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ADR-0008: a container started on version N keeps working, and stops cleanly, after N+1 is
 * activated and after a rollback.
 *
 * <p>Integration, with a real container, on purpose. Asserting that {@code getSpec()} returns
 * non-null for a superseded id would pass against a system that still breaks every running
 * app — the requirement is about containers, so the test holds one alive across both
 * transitions.
 *
 * <p>The second test documents which operations actually depend on the spec still resolving.
 * That mattered because the recorded reason for ADR-0008 was wrong: see the class comment on
 * {@link #stopNeedsOnlyTheDispatcherButTheUsersProxyListNeedsTheSpec}.
 */
public class VersionResolvabilityTest {

    private static final int PORT = 7588;
    private static final String IMAGE = "openanalytics/shinyproxy-integration-test-app:latest";

    /** The user in application-test-registry.yml, and therefore the content owner. */
    private static final String USER = "demo";

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static ConfigurableApplicationContext app;
    private static JdbcTemplate jdbc;
    private static ShinyProxySpecProvider specProvider;
    private static ShinyProxyClient client;

    @BeforeAll
    public static void beforeAll() {
        POSTGRES.start();

        SpringApplication application = new SpringApplication(ContainerProxyApplication.class);
        Properties properties = ContainerProxyApplication.getDefaultProperties();
        properties.put("spring.config.location", "src/test/resources/application-test-registry.yml");
        properties.put("server.port", PORT);
        properties.put("management.server.port", PORT % 1000 + 9000);
        properties.put("spring.datasource.url", POSTGRES.getJdbcUrl());
        properties.put("spring.datasource.username", POSTGRES.getUsername());
        properties.put("spring.datasource.password", POSTGRES.getPassword());
        properties.put("spring.flyway.schemas", "skald");
        properties.put("spring.flyway.default-schema", "skald");
        application.setDefaultProperties(properties);

        app = application.run();
        jdbc = app.getBean(JdbcTemplate.class);
        specProvider = app.getBean("shinyProxySpecProvider", ShinyProxySpecProvider.class);
        client = new ShinyProxyClient(USER, PORT);
    }

    @AfterAll
    public static void afterAll() {
        if (app != null) {
            app.stop();
            app.close();
        }
        POSTGRES.stop();
    }

    @BeforeEach
    public void beforeEach() {
        jdbc.update("DELETE FROM skald.content");
    }

    /**
     * The ADR-0008 requirement, end to end.
     */
    @Test
    public void aContainerSurvivesActivateAndRollbackAndStopsCleanly() {
        publish("rollme", 1);

        String proxyId = client.startProxy("rollme--v1");
        Assertions.assertNotNull(proxyId, "the v1 container did not start");
        client.testProxyReachable(proxyId);

        // --- activate v2 while the v1 container is alive -------------------------------
        publish("rollme", 2);

        Assertions.assertEquals(List.of("rollme--v2"), registryIds(),
            "only the active version should be listed");
        Assertions.assertNotNull(specProvider.getSpec("rollme--v1"),
            "ADR-0008: a superseded version must stay resolvable while its containers live");

        Assertions.assertTrue(proxyIds().contains(proxyId),
            "the running proxy disappeared from the user's own list after activation");
        client.testProxyReachable(proxyId);

        // --- roll back to v1 ------------------------------------------------------------
        activate("rollme", 1);

        Assertions.assertEquals(List.of("rollme--v1"), registryIds(),
            "rollback should put v1 back in the listing");
        Assertions.assertNotNull(specProvider.getSpec("rollme--v2"),
            "the rolled-back-from version must still resolve too");

        Assertions.assertTrue(proxyIds().contains(proxyId),
            "the running proxy disappeared from the user's own list after rollback");
        client.testProxyReachable(proxyId);

        // --- and it still stops ---------------------------------------------------------
        Assertions.assertDoesNotThrow(() -> client.stopProxy(proxyId),
            "a container that outlived an activate and a rollback failed to stop");
        Assertions.assertFalse(proxyIds().contains(proxyId), "the proxy did not actually stop");
    }

    /**
     * Establishes which operations really depend on a live proxy's spec still resolving.
     *
     * <p>ADR-0008, CLAUDE.md, WORKPLAN.md and WORKPLAN-REGISTRY.md all recorded the reason as
     * "{@code ProxyService.java:536} re-resolves {@code getSpec(proxy.getSpecId())} when
     * <em>stopping</em> a proxy". That is not what line 536 is: it sits in
     * {@code startOrResumeProxy}. {@code ProxyService.stopProxy} (line 346) never calls
     * {@code getSpec} at all — it needs only {@code getDispatcher(specId)}, which
     * {@code LazyProxyDispatcherService} already answers for any id.
     *
     * <p>So the decision is right and its stated mechanism was wrong. This test pins what is
     * actually true, so the next person to touch version lifecycle reads behaviour rather
     * than the old story: <b>stop survives an unresolvable spec; the user's proxy list does
     * not</b>, because {@code ProxyService.getUserProxies():231} filters through
     * {@code canAccess(auth, specId)}, which resolves the spec and denies when it is null.
     *
     * <p>The practical consequence is a constraint on task 7: deleting a content row cascades
     * to its versions, so the write path must refuse to delete a version that still has live
     * proxies, or their owners lose sight of them.
     */
    @Test
    public void stopNeedsOnlyTheDispatcherButTheUsersProxyListNeedsTheSpec() {
        publish("vanishing", 1);

        String proxyId = client.startProxy("vanishing--v1");
        Assertions.assertNotNull(proxyId);
        Assertions.assertTrue(proxyIds().contains(proxyId), "precondition: the proxy is listed");

        // Make the spec unresolvable out from under the running container. ON DELETE CASCADE
        // takes the versions with it, which is exactly what a content delete would do.
        jdbc.update("DELETE FROM skald.content WHERE slug = 'vanishing'");
        Assertions.assertNull(specProvider.getSpec("vanishing--v1"),
            "precondition: the spec no longer resolves");

        Assertions.assertFalse(proxyIds().contains(proxyId),
            "getUserProxies filters on canAccess, which needs the spec — if this now passes, "
                + "upstream changed and the task 7 delete constraint can be relaxed");

        // The other half of the claim: stop it while the spec is STILL unresolvable. Doing
        // this after restoring the row would exercise the ordinary path and prove nothing.
        Assertions.assertDoesNotThrow(() -> client.stopProxy(proxyId),
            "stopProxy needs only getDispatcher(specId), which LazyProxyDispatcherService "
                + "answers for any id — if this throws, stop does depend on the spec after all");

        // Restoring the row makes the proxy visible again IF it is still running, so this is
        // how we tell a real stop from a proxy that merely became invisible.
        publish("vanishing", 1);
        Assertions.assertNotNull(specProvider.getSpec("vanishing--v1"),
            "precondition: the spec resolves again");
        Assertions.assertFalse(proxyIds().contains(proxyId),
            "the proxy is still running — the stop with an unresolvable spec did not take effect");
    }

    // ------------------------------------------------------------------- fixtures

    private static List<String> registryIds() {
        return specProvider.getSpecs().stream()
            .map(ProxySpec::getId)
            .filter(id -> !id.equals("boot-spec"))
            .toList();
    }

    private static Set<String> proxyIds() {
        return client.getProxies().stream()
            .map(p -> p.getString("id"))
            .collect(Collectors.toSet());
    }

    /** Adds a version and makes it active, creating the content item on first use. */
    private static void publish(String slug, int version) {
        jdbc.update("""
            INSERT INTO skald.content (slug, owner, type) VALUES (?, ?, 'shiny')
            ON CONFLICT (slug) DO NOTHING
            """, slug, USER);
        jdbc.update("""
            INSERT INTO skald.content_version (content_id, version, image, created_by)
            SELECT id, ?, ?, ? FROM skald.content WHERE slug = ?
            ON CONFLICT (content_id, version) DO NOTHING
            """, version, IMAGE, USER, slug);
        activate(slug, version);
    }

    private static void activate(String slug, int version) {
        jdbc.update("""
            UPDATE skald.content c SET active_version_id = v.id
            FROM skald.content_version v
            WHERE v.content_id = c.id AND v.version = ? AND c.slug = ?
            """, version, slug);
    }


}
