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
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

/**
 * The deny cases for registry content, decided by ContainerProxy's real evaluator rather than
 * by reading the projection.
 *
 * <p>These go through {@code ProxyAccessControlService.canAccess}, which is what
 * {@code ProxyService.getUserSpecs()} filters the index with and what {@code UISecurityConfig}
 * gates {@code /app/{specId}/**} on — not through {@code AccessControlEvaluationService}
 * directly. The difference matters: {@code canAccess} consults a per-session cache whenever a
 * request context exists, and {@link #anAclRevocationDoesNotReachASessionThatIsAlreadyUsingTheApp}
 * below is what that costs.
 */
public class ContentAccessControlTest {

    private static final int PORT = 7587;

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static ConfigurableApplicationContext app;
    private static JdbcTemplate jdbc;
    private static ShinyProxySpecProvider specProvider;
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
        // content_path rows deliberately SURVIVE a content delete -- that is the reservation
        // that stops a retired URL pointing at different content later. A test resetting the
        // world has to clear them explicitly; a test that means to exercise the reservation
        // must not.
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.content_path");
    }

    @AfterEach
    public void afterEach() {
        RequestContextHolder.resetRequestAttributes();
    }

    // ---------------------------------------------------------------- allow

    @Test
    public void theOwnerCanAccessTheirOwnContent() {
        publish("report", "alice");

        Assertions.assertTrue(canAccess(user("alice"), specIdOf("report")));
    }

    @Test
    public void aUserNamedInTheAclCanAccess() {
        publish("report", "alice");
        grant("report", "user", "bob");

        Assertions.assertTrue(canAccess(user("bob"), specIdOf("report")));
    }

    @Test
    public void aMemberOfAGrantedGroupCanAccess() {
        publish("report", "alice");
        grant("report", "group", "viewers");

        Assertions.assertTrue(canAccess(user("bob", "viewers"), specIdOf("report")));
    }

    /** viewer and editor differ in what may be changed, not in who may open the content. */
    @Test
    public void anEditorGrantCanOpenTheContentToo() {
        publish("report", "alice");
        jdbc.update("""
            INSERT INTO skald.content_acl (content_id, principal_type, principal, permission)
            VALUES (?, 'user', 'bob', 'editor')
            """, contentId("report"));

        Assertions.assertTrue(canAccess(user("bob"), specIdOf("report")));
    }

    @Test
    public void allAuthenticatedGrantsAnyLoggedInUser() {
        publish("open-report", "alice", "all_authenticated");

        Assertions.assertTrue(canAccess(user("bob"), specIdOf("open-report")));
        Assertions.assertTrue(canAccess(user("carol", "some-unrelated-group"), specIdOf("open-report")));
    }

    // ----------------------------------------------------------------- deny

    @Test
    public void aUserWithNoGrantIsDenied() {
        publish("report", "alice");

        Assertions.assertFalse(canAccess(user("bob"), specIdOf("report")));
    }

    @Test
    public void aUserInTheWrongGroupIsDenied() {
        publish("report", "alice");
        grant("report", "group", "publishers");

        Assertions.assertFalse(canAccess(user("bob", "viewers"), specIdOf("report")));
    }

    @Test
    public void revokingAnAclDeniesOnTheNextEvaluation() {
        publish("report", "alice");
        grant("report", "user", "bob");
        Assertions.assertTrue(canAccess(user("bob"), specIdOf("report")), "precondition: bob was granted");

        jdbc.update("DELETE FROM skald.content_acl WHERE principal = 'bob'");

        Assertions.assertFalse(canAccess(user("bob"), specIdOf("report")),
            "a revoked ACL must not survive in the memoised ProxySpec");
    }

    @Test
    public void anonymousIsDeniedAclOnlyContent() {
        publish("report", "alice");
        grant("report", "group", "viewers");

        Assertions.assertFalse(canAccess(anonymous(), specIdOf("report")));
    }

    /**
     * Proves the finding that {@code visibility = 'anonymous'} rests on, rather than asserting
     * it: ContainerProxy's {@code AccessControlEvaluationService.checkAccess} rejects an
     * {@code AnonymousAuthenticationToken} outright whenever the authentication backend has
     * authorization, <em>before</em> users, groups or the expression are consulted. So even
     * the most permissive AccessControl Skald could project — the one
     * {@code all_authenticated} uses — does not let an unauthenticated visitor through.
     *
     * <p>If this test ever starts failing, anonymous content became implementable through
     * projection alone and {@code AccessControlProjector} should be revisited.
     */
    @Test
    public void anonymousIsDeniedEvenByTheMostPermissiveProjection() {
        publish("open-report", "alice", "all_authenticated");

        Assertions.assertTrue(canAccess(user("bob"), specIdOf("open-report")),
            "precondition: all_authenticated grants an authenticated user");
        Assertions.assertFalse(canAccess(anonymous(), specIdOf("open-report")),
            "anonymous access cannot be granted by an AccessControl; see AccessControlProjector");
    }

    @Test
    public void anonymousVisibilityDeniesEveryoneRatherThanDowngrading() {
        publish("public-thing", "alice", "anonymous");

        Assertions.assertFalse(canAccess(anonymous(), specIdOf("public-thing")));
        Assertions.assertFalse(canAccess(user("alice"), specIdOf("public-thing")),
            "an unservable visibility mode must not silently become owner-only");
        Assertions.assertFalse(canAccess(user("bob"), specIdOf("public-thing")),
            "an unservable visibility mode must not silently become all_authenticated");
    }

    /**
     * Review finding F1, at the level where it did damage.
     *
     * <p>Spec ids used to be derived from the publisher's slug, so deleting content and
     * re-creating it under the same name handed the new content the old one's spec id. Because
     * {@code ProxyAccessControlService} memoises decisions per {@code (sessionId, specId)} with
     * no way to invalidate them, a user whose grant was gone kept access to whatever occupied
     * the id next — reproduced live, where a revoked user opened the app and started a
     * container while a fresh session was correctly refused.
     *
     * <p>Ids now come from the content UUID, so new content cannot collide with a cached
     * decision. This drives a real {@code RequestContextHolder} so the cache is genuinely in
     * play; without that, {@code canAccess} skips it entirely.
     *
     * <p><b>What this does and does not prove.</b> It is a structural guard, not the
     * behavioural proof: with UUID-derived ids the two spec ids differ by construction, so the
     * assertion cannot fail unless id allocation regresses to being derived from something a
     * publisher controls — which is exactly the regression worth catching, and what it is here
     * for. The behavioural proof that ids are never reused is
     * {@code ContentAdminControllerTest.aRecreatedContentItemNeverInheritsTheOldSpecId}, which
     * fails precisely under a mutation that makes {@code specId()} reuse ids. Path reservation
     * closes the same hole a second time, independently, by making it impossible to re-create
     * content at a retired name at all.
     */
    @Test
    public void newContentCannotInheritACachedDecisionFromDeletedContent() {
        UUID first = publish("first-report", "alice");
        grant("first-report", "user", "bob");
        String firstSpecId = specIdOf("first-report");

        withRequestContext(() -> {
            Assertions.assertTrue(canAccess(user("bob"), firstSpecId),
                "precondition: bob is granted, and this caches the decision for his session");

            // The content is deleted and different content is published. Bob is granted nothing.
            jdbc.update("DELETE FROM skald.content WHERE id = ?", first);
            publish("second-report", "alice");
            String secondSpecId = specIdOf("second-report");

            Assertions.assertNotEquals(firstSpecId, secondSpecId,
                "precondition: the new content must not have been handed the retired id");
            Assertions.assertFalse(canAccess(user("bob"), secondSpecId),
                "bob reached content he was never granted, in the same session that had a "
                    + "cached decision for the deleted content");
        });
    }

    // ------------------------------------------------- the per-session cache

    /**
     * Characterisation test, <b>not</b> an endorsement: this pins behaviour we intend to fix.
     *
     * <p>{@code ProxyAccessControlService} memoises the answer per
     * {@code (sessionId, specId)} with {@code expireAfterAccess(60, TimeUnit.MINUTES)} and
     * exposes no way to invalidate it, on the comment "this never changes during the lifetime
     * of a session". That holds for YAML ACLs and breaks for published content: a revocation
     * does not reach a session that already has a cached answer, and because the expiry is
     * {@code expireAfterAccess} rather than {@code expireAfterWrite}, continued use keeps
     * refreshing it.
     *
     * <p>Every other deny test above runs with no request context, where {@code canAccess}
     * bypasses the cache entirely — which is precisely why none of them catches this, and why
     * it is worth one test that drives the cache on purpose.
     *
     * <p>The fix needs a change inside ContainerProxy and therefore an ADR-0001 decision; the
     * write path that would make it a live bug does not exist until task 7. See
     * {@code docs/UPSTREAM_CHANGES.md}.
     */
    @Test
    public void anAclRevocationDoesNotReachASessionThatIsAlreadyUsingTheApp() {
        publish("report", "alice");
        grant("report", "user", "bob");

        withRequestContext(() -> {
            Assertions.assertTrue(canAccess(user("bob"), specIdOf("report")),
                "precondition: bob was granted, within a session");

            jdbc.update("DELETE FROM skald.content_acl WHERE principal = 'bob'");

            Assertions.assertFalse(
                spec(specIdOf("report")).getAccessControl().hasUserAccess()
                    && Arrays.asList(spec(specIdOf("report")).getAccessControl().getUsers()).contains("bob"),
                "precondition: the projection itself no longer grants bob");

            Assertions.assertTrue(canAccess(user("bob"), specIdOf("report")),
                "KNOWN LIMITATION: if this starts failing, the per-session authorization cache "
                    + "became invalidatable and this test should become a real deny assertion");
        });

        // ...and the same revocation is honoured immediately for a session that has not yet
        // asked, which is why the hole is invisible to a smoke test that logs in fresh.
        Assertions.assertFalse(canAccess(user("bob"), specIdOf("report")));
    }

    // ------------------------------------------------------------- fixtures

    private static boolean canAccess(Authentication auth, String specId) {
        ProxySpec proxySpec = spec(specId);
        Assertions.assertNotNull(proxySpec, "spec '" + specId + "' does not exist");
        return accessControl.canAccess(auth, proxySpec);
    }

    /** Goes through the (sessionId, specId) cache the way a real request would. */
    private static boolean canAccessBySpecId(Authentication auth, String specId) {
        return accessControl.canAccess(auth, specId);
    }

    /** Always re-resolved: an ACL change produces a new ProxySpec instance by design. */
    private static ProxySpec spec(String specId) {
        return specProvider.getSpec(specId);
    }

    private static Authentication user(String name, String... groups) {
        return new UsernamePasswordAuthenticationToken(name, "n/a",
            Arrays.stream(groups).map(SimpleGrantedAuthority::new).toList());
    }

    private static Authentication anonymous() {
        return new AnonymousAuthenticationToken("key", "anonymousUser",
            List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
    }

    /** Gives the body a stable session id, so ProxyAccessControlService uses its cache. */
    private static void withRequestContext(Runnable body) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            body.run();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private static UUID publish(String path, String owner) {
        return publish(path, owner, "acl_only");
    }

    private static UUID publish(String path, String owner, String visibility) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type, visibility) "
            + "VALUES (?, ?, ?, 'shiny', ?)", id, path, owner, visibility);
        jdbc.update("INSERT INTO skald.content_path (path, path_key, content_id) VALUES (?, ?, ?)",
            path, path, id);
        jdbc.update("INSERT INTO skald.content_version (content_id, version, image, created_by) "
            + "VALUES (?, 1, ?, ?)", id, "registry:5000/" + path + ":1", owner);
        jdbc.update("""
            UPDATE skald.content c SET active_version_id = v.id
            FROM skald.content_version v
            WHERE v.content_id = c.id AND v.version = 1 AND c.id = ?
            """, id);
        return id;
    }

    /** The spec id of version 1 of the content published at this path. */
    private static String specIdOf(String path) {
        return ContentSpecRepository.specId(contentId(path), 1);
    }

    private static UUID contentId(String path) {
        return jdbc.queryForObject("SELECT content_id FROM skald.content_path WHERE path_key = ?",
            (rs, i) -> (UUID) rs.getObject("content_id"), path);
    }

    private static void grant(String path, String principalType, String principal) {
        jdbc.update("INSERT INTO skald.content_acl (content_id, principal_type, principal) "
            + "VALUES (?, ?, ?)", contentId(path), principalType, principal);
    }

}
