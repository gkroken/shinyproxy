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
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * Proves that content in the registry becomes a startable spec without a restart, and that
 * configured YAML specs stay authoritative.
 *
 * <p>Runs against a real PostgreSQL through Testcontainers rather than an in-memory stand-in:
 * the schema uses {@code jsonb}, {@code gen_random_uuid()}, partial CHECK constraints and a
 * circular foreign key, none of which an H2 compatibility mode would exercise honestly.
 */
public class MergedSpecProviderTest {

    private static final int PORT = 7586;

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static ConfigurableApplicationContext app;
    private static JdbcTemplate jdbc;
    private static ShinyProxySpecProvider specProvider;

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

    @Test
    public void theMergedProviderIsInstalled() {
        Assertions.assertInstanceOf(MergedSpecProvider.class, specProvider,
            "SpecProviderOverrideRegistrar did not retarget the bean");
    }

    @Test
    public void flywayAppliedTheSchema() {
        Integer applied = jdbc.queryForObject(
            "SELECT count(*) FROM skald.flyway_schema_history WHERE success", Integer.class);
        Assertions.assertNotNull(applied);
        Assertions.assertTrue(applied >= 1, "no successful Flyway migrations");
    }

    @Test
    public void contentAddedToTheRegistryBecomesASpecWithNoRestart() {
        Assertions.assertTrue(specProvider.getSpecs().stream().noneMatch(x -> x.getId().startsWith("c")),
            "precondition: no registry spec exists before the row does");

        publish("my-app", "alice", 1, "registry:5000/my-app:1");

        ProxySpec spec = specProvider.getSpec(spec("my-app", 1));
        Assertions.assertNotNull(spec, "registry content did not become a resolvable spec");
        // getOriginalValue, not getValueOrNull: a SpelField only has a resolved value after
        // ProxyService runs firstResolve/finalResolve at proxy-start time, and reading it
        // before that throws.
        Assertions.assertEquals("registry:5000/my-app:1",
            spec.getContainerSpecs().get(0).getImage().getOriginalValue());

        // It must also be listed, which is what drives the index and getUserSpecs().
        Assertions.assertTrue(idsOf(specProvider.getSpecs()).contains(spec("my-app", 1)));

        // The spec extension ShinyProxy dereferences without a null check must be present,
        // or every page rendering this spec NPEs.
        Assertions.assertDoesNotThrow(() -> specProvider.getShinyForceFullReload(spec));
        Assertions.assertDoesNotThrow(() -> specProvider.getHideNavbarOnMainPageLink(spec));
    }

    /**
     * The generic guard against a whole class of bug.
     *
     * <p>{@code ProxySpec.getSpecExtension()} returns null when an extension is absent, and
     * several ShinyProxy call sites dereference it without checking — so a registry spec
     * missing one does not degrade, it throws while rendering the index or starting a proxy.
     * Enumerating the known extensions in a test would only catch the ones already known.
     * Comparing against a configured spec catches the next one upstream adds, at build time.
     */
    @Test
    public void registrySpecsCarryEveryExtensionAConfiguredSpecCarries() {
        publish("my-app", "alice", 1, "registry:5000/my-app:1");

        ProxySpec configured = specProvider.getSpec("boot-spec");
        ProxySpec fromRegistry = specProvider.getSpec(spec("my-app", 1));

        Assertions.assertTrue(
            fromRegistry.getSpecExtensions().keySet().containsAll(configured.getSpecExtensions().keySet()),
            "registry specs are missing spec extensions that configured specs have: "
                + configured.getSpecExtensions().keySet().stream()
                    .filter(k -> !fromRegistry.getSpecExtensions().containsKey(k)).toList());
    }

    /**
     * ShinyProxy keys view-model maps by {@code ProxySpec} <em>object</em>:
     * {@code IndexController} builds them from one {@code getUserSpecs()} call and
     * {@code BaseController.prepareMap} puts the results of a second call in the model, so the
     * template looks the first up by the second. {@code ProxySpec.equals} delegates to
     * {@code AccessControl}, which has no {@code equals} and compares by identity — so a
     * provider that rebuilds specs per call makes the index page 500 on a null-to-boolean
     * conversion. Instance stability is a correctness requirement, and this is its guard.
     */
    @Test
    public void repeatedLookupsReturnTheSameInstanceUntilTheContentChanges() {
        publish("my-app", "alice", 1, "registry:5000/my-app:1");

        ProxySpec first = specProvider.getSpec(spec("my-app", 1));
        Assertions.assertSame(first, specProvider.getSpec(spec("my-app", 1)),
            "unchanged content must resolve to the same ProxySpec instance");
        Assertions.assertSame(first,
            specProvider.getSpecs().stream().filter(s -> s.getId().equals(spec("my-app", 1))).findFirst().orElseThrow(),
            "getSpecs() and getSpec() must agree on the instance");

        // ...but a change to the row must produce a new one, or edits would never take effect.
        jdbc.update("UPDATE skald.content SET visibility = 'all_authenticated' WHERE id = ?", contentId("my-app"));
        Assertions.assertNotSame(first, specProvider.getSpec(spec("my-app", 1)),
            "changed content must be rebuilt");
    }

    /**
     * ADR-0008 is conditional, and this covers the half that has no containers.
     *
     * <p>The previous version of this test asserted that a superseded version stays resolvable
     * "while its containers live" — with nothing running. That assertion never matched its own
     * stated intent, and it was encoding a real hole: any permitted user could start any
     * historical version forever from a bookmarked {@code /app/<slug>--v<n>} URL, so publishing
     * a fix never retired the version it fixed. {@code VersionResolvabilityTest} covers the
     * other half, with a container actually alive.
     */
    @Test
    public void aSupersededVersionWithNothingRunningIsNeitherListedNorResolvable() {
        publish("rollme", "alice", 1, "registry:5000/rollme:1");
        publish("rollme", "alice", 2, "registry:5000/rollme:2");

        List<String> listed = idsOf(specProvider.getSpecs());
        Assertions.assertTrue(listed.contains(spec("rollme", 2)), "the active version should be listed");
        Assertions.assertFalse(listed.contains(spec("rollme", 1)), "a superseded version must not be listed");

        Assertions.assertNotNull(specProvider.getSpec(spec("rollme", 2)),
            "the active version must resolve");
        Assertions.assertNull(specProvider.getSpec(spec("rollme", 1)),
            "a superseded version with no running container must not resolve, or activation "
                + "would never retire anything");

        // ...and rolling back makes it resolvable again, because it is active again.
        jdbc.update("""
            UPDATE skald.content c SET active_version_id = v.id
            FROM skald.content_version v
            WHERE v.content_id = c.id AND v.version = 1 AND c.id = ?
            """, contentId("rollme"));
        Assertions.assertNotNull(specProvider.getSpec(spec("rollme", 1)));
        Assertions.assertNull(specProvider.getSpec(spec("rollme", 2)));
    }

    /**
     * Configured specs are authoritative, and registry content can no longer even express a
     * claim on one.
     *
     * <p>Decision 3 used to be enforced by comparing a publisher-chosen slug against the
     * configured spec ids, and review finding F4 showed that check was incomplete: it compared
     * the bare slug, so publishing {@code probe} produced the spec id {@code probe--v1} and
     * captured an admin's configured {@code probe--v1} — two success responses followed by
     * content that never resolved, and a per-request error in the log.
     *
     * <p>Spec ids now derive from the content UUID, so the namespaces are disjoint by
     * construction rather than by a check that has to be kept complete. This asserts the
     * structural property, which is the thing worth defending.
     */
    @Test
    public void registrySpecIdsCannotCollideWithConfiguredOnes() {
        publish("boot-spec", "mallory", 1, "registry:5000/evil:1");

        // A publisher naming their content after a configured spec changes nothing: the id is
        // not derived from the name.
        Assertions.assertNotNull(specProvider.getSpec("boot-spec"),
            "the configured spec must still be the one at its own id");
        Assertions.assertEquals("Present at startup",
            specProvider.getSpec("boot-spec").getDisplayName(),
            "the configured spec was shadowed by registry content");

        Assertions.assertTrue(
            idsOf(specProvider.getSpecs()).stream().filter(id -> !id.equals("boot-spec"))
                .allMatch(id -> id.matches("^c[0-9a-f]{32}--v[0-9]+$")),
            "every registry spec id must be UUID-derived, so that no publisher-supplied text "
                + "can ever produce a configured spec's id");
    }

    @Test
    public void malformedAndUnknownSpecIdsResolveToNull() {
        publish("my-app", "alice", 1, "registry:5000/my-app:1");

        Assertions.assertNull(specProvider.getSpec("my-app"));
        Assertions.assertNull(specProvider.getSpec(spec("my-app", 2)));
        Assertions.assertNull(specProvider.getSpec("c" + "0".repeat(32) + "--v0"));
        Assertions.assertNull(specProvider.getSpec("nope--v1"));
        Assertions.assertNull(specProvider.getSpec("' OR 1=1 --v1"));
        Assertions.assertNull(specProvider.getSpec(null));
    }

    /**
     * Risk 4 in WORKPLAN-REGISTRY.md: {@code ShinyProxySpecProvider} caches the whole
     * max-instances map per session for 60 minutes, on the stated assumption that it "never
     * changes during the lifetime of a session". Publishing breaks that assumption, and the
     * failure is not cosmetic — {@code BaseController.validateMaxInstances} unboxes the
     * {@code Integer} this returns, so a missing entry is a 500 on every attempt to open the
     * new content, for the rest of that session.
     *
     * <p>The request and security contexts are set up by hand because the cache is only
     * consulted when there is a session id to key on; without them the parent recomputes every
     * time and this test would pass with the override removed.
     */
    @Test
    public void contentPublishedAfterASessionCachedItsMaxInstancesIsStillResolvable() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("demo", "n/a", List.of()));

        try {
            // Warm the per-session cache while the registry is empty, exactly as opening the
            // index page would.
            Map<String, Integer> beforePublishing = specProvider.getMaxInstances();
            Assertions.assertTrue(beforePublishing.containsKey("boot-spec"),
                "precondition: the configured spec is in the cached map");
            Assertions.assertFalse(beforePublishing.keySet().stream().anyMatch(k -> k.startsWith("c")),
                "precondition: the content does not exist yet");

            publish("late", "alice", 1, "registry:5000/late:1");

            ProxySpec spec = specProvider.getSpec(spec("late", 1));
            Assertions.assertNotNull(spec, "precondition: the content became a spec");

            Assertions.assertNotNull(specProvider.getMaxInstancesForSpec(spec),
                "content published mid-session has no max-instances entry, so "
                    + "BaseController.validateMaxInstances would throw on unboxing null");
            Assertions.assertEquals(1, specProvider.getMaxInstancesForSpec(spec),
                "registry content should fall back to proxy.default-max-instances");

            // The configured specs must survive the overlay unchanged.
            Assertions.assertEquals(beforePublishing.get("boot-spec"),
                specProvider.getMaxInstances().get("boot-spec"));
        } finally {
            SecurityContextHolder.clearContext();
            RequestContextHolder.resetRequestAttributes();
        }
    }

    /**
     * Creates content (if needed), adds a version, and makes it the active one.
     *
     * <p>Keyed by path, but the spec id comes from the generated content UUID, so tests ask
     * {@link #spec} for it rather than spelling one out. That is the point of the identity
     * split: nothing derivable from a name is durable.
     */
    private static UUID publish(String path, String owner, int version, String image) {
        UUID existing = contentId(path);
        UUID id = (existing != null) ? existing : UUID.randomUUID();
        if (existing == null) {
            jdbc.update("INSERT INTO skald.content (id, title, owner, type) VALUES (?, ?, ?, 'shiny')",
                id, path, owner);
            jdbc.update("INSERT INTO skald.content_path (path, path_key, content_id) VALUES (?, ?, ?)",
                path, path, id);
        }
        jdbc.update("""
            INSERT INTO skald.content_version (content_id, version, image, created_by)
            VALUES (?, ?, ?, ?)
            """, id, version, image, owner);
        jdbc.update("""
            UPDATE skald.content c SET active_version_id = v.id
            FROM skald.content_version v
            WHERE v.content_id = c.id AND v.version = ? AND c.id = ?
            """, version, id);
        return id;
    }

    private static UUID contentId(String path) {
        List<UUID> found = jdbc.query(
            "SELECT content_id FROM skald.content_path WHERE path_key = ?",
            (rs, i) -> (UUID) rs.getObject("content_id"), path);
        return found.isEmpty() ? null : found.get(0);
    }

    /** The spec id of a version of the content published at this path. */
    private static String spec(String path, int version) {
        return ContentSpecRepository.specId(contentId(path), version);
    }

    private static List<String> idsOf(List<ProxySpec> specs) {
        return specs.stream().map(ProxySpec::getId).toList();
    }

}
