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
import eu.openanalytics.containerproxy.service.ProxyAccessControlService;
import eu.openanalytics.containerproxy.test.helpers.ShinyProxyClient;
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
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
    private static ProxyAccessControlService accessControl;

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
        accessControl = app.getBean(ProxyAccessControlService.class);
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
        // v2 is now superseded AND has no container of its own, so it must stop resolving:
        // that is what keeps activation able to retire a version. v1, which the live container
        // is on, is active again here and covered by the assertions above.
        Assertions.assertNull(specProvider.getSpec("rollme--v2"),
            "a superseded version with nothing running on it must not stay resolvable");

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

    /**
     * The hole this condition was added to close, at the level a user would exploit it.
     *
     * <p>Before {@code findSpec} required a live container, a superseded version was absent from
     * the index but still fully startable from {@code /app/<slug>--v<n>} or the proxy API —
     * confirmed against the running dev stack, where v1 started a real container while v2 was
     * active. That made activation control discovery but not execution, so publishing a fix
     * never retired the version it fixed.
     */
    @Test
    public void aSupersededVersionWithNothingRunningCannotBeStarted() throws IOException {
        publish("retired", 1);
        publish("retired", 2);

        Assertions.assertEquals(List.of("retired--v2"), registryIds(), "precondition: v2 is active");
        Assertions.assertTrue(proxyIds().isEmpty(), "precondition: nothing is running");

        int status = startStatus("retired--v1");
        Assertions.assertTrue(status >= 400,
            "a retired version was startable (HTTP " + status + "); activation must retire code, "
                + "not just hide it from the index");
        Assertions.assertTrue(proxyIds().isEmpty(), "a container was started on a retired version");

        // The active version is of course still startable.
        Assertions.assertEquals(201, startStatus("retired--v2"),
            "the active version must still start");
        proxyIds().forEach(client::stopProxy);
    }

    /**
     * WORKPLAN-REGISTRY.md decision 4: "Superseded versions carry the same ACL as the content
     * item, not a snapshot." Never tested until now, and only testable with a container alive —
     * a superseded version with nothing running no longer resolves at all, so there would be
     * nothing to evaluate an ACL against.
     *
     * <p>The point is that an old version is not a way to keep access someone has lost. A
     * snapshotted ACL would mean revoking a grant leaves the revoked user able to reach
     * whichever version they were granted on.
     */
    @Test
    public void aSupersededVersionUsesTheContentsCurrentAclNotASnapshot() {
        publish("acl-ver", 1);
        grantTo("acl-ver", "bob");

        String proxyId = client.startProxy("acl-ver--v1");
        Assertions.assertNotNull(proxyId, "precondition: a container is alive on v1");
        try {
            publish("acl-ver", 2);
            ProxySpec superseded = specProvider.getSpec("acl-ver--v1");
            Assertions.assertNotNull(superseded, "precondition: v1 resolves, its container lives");

            Assertions.assertTrue(accessControl.canAccess(user("bob"), superseded),
                "precondition: bob was granted access to the content");

            jdbc.update("DELETE FROM skald.content_acl WHERE principal = 'bob'");

            Assertions.assertFalse(
                accessControl.canAccess(user("bob"), specProvider.getSpec("acl-ver--v1")),
                "a superseded version kept a revoked grant — the ACL was snapshotted, so an old "
                    + "version would be a way to retain access after it is taken away");
        } finally {
            client.stopProxy(proxyId);
        }
    }

    private static Authentication user(String name) {
        return new UsernamePasswordAuthenticationToken(name, "n/a", List.of(new SimpleGrantedAuthority("users")));
    }

    private static void grantTo(String slug, String principal) {
        jdbc.update("""
            INSERT INTO skald.content_acl (content_id, principal_type, principal)
            SELECT id, 'user', ? FROM skald.content WHERE slug = ?
            """, principal, slug);
    }

    private static int startStatus(String specId) throws IOException {
        Request request = new Request.Builder()
            .post(RequestBody.create("{}", MediaType.get("application/json; charset=utf-8")))
            .url(client.getBaseUrl() + "/api/proxy/" + specId)
            .build();
        try (Response response = client.newCall(request).execute()) {
            return response.code();
        }
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
