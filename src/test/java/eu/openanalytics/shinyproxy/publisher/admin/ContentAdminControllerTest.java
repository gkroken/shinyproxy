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
package eu.openanalytics.shinyproxy.publisher.admin;

import eu.openanalytics.containerproxy.ContainerProxyApplication;
import eu.openanalytics.containerproxy.test.helpers.ShinyProxyClient;
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
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
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * The admin write path (spine #1 task 7), driven over real HTTP.
 *
 * <p>Weighted towards refusals. Every one of them encodes a decision an earlier task paid to
 * establish, and a write path that accepts what it should refuse is how those decisions get
 * quietly undone: a non-admin caller, a slug that shadows a configured spec, a visibility mode
 * the platform cannot serve, a delete that would strand a running container, and a
 * cross-site-shaped form POST.
 */
public class ContentAdminControllerTest {

    private static final int PORT = 7589;
    private static final String IMAGE = "openanalytics/shinyproxy-integration-test-app:latest";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static ConfigurableApplicationContext app;
    private static JdbcTemplate jdbc;
    private static ShinyProxySpecProvider specProvider;
    private static ShinyProxyClient admin;
    private static ShinyProxyClient plain;
    private static OkHttpClient anonymous;
    private static String baseUrl;

    @BeforeAll
    public static void beforeAll() {
        POSTGRES.start();

        SpringApplication application = new SpringApplication(ContainerProxyApplication.class);
        Properties properties = ContainerProxyApplication.getDefaultProperties();
        properties.put("spring.config.location", "src/test/resources/application-test-admin.yml");
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

        admin = new ShinyProxyClient("adminuser", PORT);
        plain = new ShinyProxyClient("plainuser", PORT);
        baseUrl = admin.getBaseUrl();
        anonymous = new OkHttpClient.Builder()
            .followRedirects(false)
            .callTimeout(30, TimeUnit.SECONDS)
            .build();
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
        jdbc.update("DELETE FROM skald.audit_event");
    }

    // ------------------------------------------------------------------- lifecycle

    @Test
    public void createPublishesContentThatIsImmediatelyResolvable() throws IOException {
        Assertions.assertNull(specProvider.getSpec("report--v1"), "precondition");

        try (Response created = post(admin, "/admin/content",
            """
            {"slug":"report","owner":"alice","type":"shiny"}
            """)) {
            Assertions.assertEquals(201, created.code(), body(created));
        }
        try (Response version = post(admin, "/admin/content/report/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(201, version.code(), body(version));
        }

        // No restart: the spec exists the moment the row does.
        Assertions.assertNotNull(specProvider.getSpec("report--v1"),
            "content created over HTTP did not become a resolvable spec");
    }

    @Test
    public void activateMovesTheActiveVersionAndRollbackMovesItBack() throws IOException {
        createContent("rollme");
        addVersion("rollme");
        addVersion("rollme");

        Assertions.assertEquals(List.of("rollme--v2"), registryIds(),
            "adding a version should activate it by default");

        try (Response rollback = put(admin, "/admin/content/rollme/active-version",
            """
            {"version":1}
            """)) {
            Assertions.assertEquals(200, rollback.code(), body(rollback));
        }
        Assertions.assertEquals(List.of("rollme--v1"), registryIds(), "rollback did not take effect");
        Assertions.assertNotNull(specProvider.getSpec("rollme--v1"), "the active version resolves");
        Assertions.assertNull(specProvider.getSpec("rollme--v2"),
            "with nothing running on it, the rolled-back-from version must stop resolving — "
                + "otherwise rollback would not actually retire v2");
    }

    @Test
    public void deleteRemovesTheContentAndItsSpecs() throws IOException {
        createContent("goner");
        addVersion("goner");
        Assertions.assertNotNull(specProvider.getSpec("goner--v1"), "precondition");

        try (Response deleted = delete(admin, "/admin/content/goner")) {
            Assertions.assertEquals(200, deleted.code(), body(deleted));
        }
        Assertions.assertNull(specProvider.getSpec("goner--v1"));
    }

    @Test
    public void everyMutationIsAudited() throws IOException {
        createContent("audited");
        addVersion("audited");
        try (Response ignored = delete(admin, "/admin/content/audited")) {
            Assertions.assertEquals(200, ignored.code());
        }

        List<String> actions = jdbc.queryForList(
            "SELECT action FROM skald.audit_event WHERE subject_id = 'audited' ORDER BY id",
            String.class);
        Assertions.assertEquals(
            List.of("content.create", "content.version.add", "content.activate", "content.delete"),
            actions);

        String actor = jdbc.queryForObject(
            "SELECT actor FROM skald.audit_event WHERE subject_id = 'audited' LIMIT 1", String.class);
        Assertions.assertEquals("adminuser", actor, "the audit trail must name who did it");
    }

    // ------------------------------------------------------------- authorization

    /**
     * The endpoint adds no security configuration of its own — it sits under {@code /admin},
     * which {@code UISecurityConfig} already gates. This is the test that the inheritance is
     * real rather than assumed.
     */
    @Test
    public void anAuthenticatedNonAdminIsRefusedEveryEndpoint() throws IOException {
        createContent("existing");

        try (Response r = get(plain, "/admin/content")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could LIST registry content");
        }
        try (Response r = post(plain, "/admin/content",
            "{\"slug\":\"sneaky\",\"owner\":\"plainuser\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could CREATE content");
        }
        try (Response r = post(plain, "/admin/content/existing/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could add a VERSION");
        }
        try (Response r = put(plain, "/admin/content/existing/active-version", "{\"version\":1}")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could ACTIVATE a version");
        }
        try (Response r = delete(plain, "/admin/content/existing")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could DELETE content");
        }

        Assertions.assertTrue(slugs().contains("existing"),
            "the refused calls must not have changed anything");
        Assertions.assertFalse(slugs().contains("sneaky"));
    }

    @Test
    public void anUnauthenticatedCallerIsNotServed() throws IOException {
        Request request = new Request.Builder().get().url(baseUrl + "/admin/content").build();
        try (Response r = anonymous.newCall(request).execute()) {
            Assertions.assertNotEquals(200, r.code(),
                "the registry was readable without authenticating");
        }
    }

    /**
     * The CSRF defence. ShinyProxy only protects {@code POST /login}
     * ({@code WebSecurityConfig:136}), so an admin's browser on a hostile page could otherwise
     * be made to submit a form here. Refusing every content type a form can produce makes that
     * impossible without a CORS preflight this application never grants.
     *
     * <p>Note for anyone mutation-testing this: removing {@code consumes} from the controller
     * does <em>not</em> make this test fail, and that is not a gap in the test. The property has
     * two independent guards — see the controller's class comment — and this asserts the
     * property, not one mechanism. Making it fail takes removing both, for example by binding
     * the body with {@code @ModelAttribute} instead of {@code @RequestBody}.
     */
    @Test
    public void aFormEncodedPostIsRefusedBeforeItReachesAHandler() throws IOException {
        RequestBody form = RequestBody.create(
            "slug=sneaky&owner=adminuser&type=shiny",
            MediaType.get("application/x-www-form-urlencoded"));
        Request request = new Request.Builder().post(form).url(baseUrl + "/admin/content").build();

        try (Response r = admin.newCall(request).execute()) {
            Assertions.assertEquals(415, r.code(),
                "a form-encoded POST was accepted — the cross-site-request defence is gone");
        }
        Assertions.assertFalse(slugs().contains("sneaky"));
    }

    // ------------------------------------------------------------------- refusals

    @Test
    public void anonymousVisibilityIsRefusedOnWrite() throws IOException {
        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"public-thing\",\"owner\":\"alice\",\"type\":\"shiny\",\"visibility\":\"anonymous\"}")) {
            Assertions.assertEquals(400, r.code());
            Assertions.assertTrue(body(r).contains("anonymous"), "the reason should name the mode");
        }
        Assertions.assertFalse(slugs().contains("public-thing"));
    }

    @Test
    public void aSlugThatShadowsAConfiguredSpecIsRefused() throws IOException {
        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"boot-spec\",\"owner\":\"alice\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(),
                "registry content was allowed to shadow a configured spec id");
        }
        Assertions.assertFalse(slugs().contains("boot-spec"));
    }

    @Test
    public void duplicateSlugsAndBadInputAreRefused() throws IOException {
        createContent("taken");

        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"taken\",\"owner\":\"alice\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), "duplicate slug");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"Not A Slug\",\"owner\":\"alice\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(400, r.code(), "slug format");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"weird\",\"owner\":\"alice\",\"type\":\"cobol\"}")) {
            Assertions.assertEquals(400, r.code(), "unknown type");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"ownerless\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(400, r.code(), "missing owner");
        }
        try (Response r = put(admin, "/admin/content/taken/active-version", "{\"version\":99}")) {
            Assertions.assertEquals(404, r.code(), "activating a version that does not exist");
        }
    }

    /**
     * Task 6's constraint, with a real container. {@code content_version} is
     * {@code ON DELETE CASCADE} from {@code content}, so deleting this would make the running
     * proxy's spec unresolvable — and a proxy whose spec does not resolve disappears from its
     * own owner's list.
     */
    @Test
    public void deletingContentWithARunningAppIsRefused() throws IOException {
        createContent("busy");
        addVersion("busy");

        String proxyId = admin.startProxy("busy--v1");
        Assertions.assertNotNull(proxyId, "precondition: the container started");
        try {
            try (Response r = delete(admin, "/admin/content/busy")) {
                Assertions.assertEquals(409, r.code(),
                    "content with a running app was deleted, stranding the container");
                Assertions.assertTrue(body(r).contains("busy--v1"),
                    "the refusal should name what is still running");
            }
            Assertions.assertTrue(slugs().contains("busy"), "the content should still be there");
        } finally {
            admin.stopProxy(proxyId);
        }

        // ...and once nothing is running, the same delete succeeds.
        try (Response r = delete(admin, "/admin/content/busy")) {
            Assertions.assertEquals(200, r.code(), body(r));
        }
    }

    // ------------------------------------------------------------------- fixtures

    private static void createContent(String slug) throws IOException {
        try (Response r = post(admin, "/admin/content",
            "{\"slug\":\"" + slug + "\",\"owner\":\"adminuser\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }
    }

    private static void addVersion(String slug) throws IOException {
        try (Response r = post(admin, "/admin/content/" + slug + "/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }
    }

    private static List<String> slugs() {
        return jdbc.queryForList("SELECT slug FROM skald.content ORDER BY slug", String.class);
    }

    private static List<String> registryIds() {
        return specProvider.getSpecs().stream()
            .map(s -> s.getId())
            .filter(id -> !id.equals("boot-spec"))
            .toList();
    }

    private static Response get(ShinyProxyClient client, String path) throws IOException {
        return client.newCall(new Request.Builder().get().url(baseUrl + path).build()).execute();
    }

    private static Response post(ShinyProxyClient client, String path, String json) throws IOException {
        return client.newCall(new Request.Builder()
            .post(RequestBody.create(json, JSON)).url(baseUrl + path).build()).execute();
    }

    private static Response put(ShinyProxyClient client, String path, String json) throws IOException {
        return client.newCall(new Request.Builder()
            .put(RequestBody.create(json, JSON)).url(baseUrl + path).build()).execute();
    }

    private static Response delete(ShinyProxyClient client, String path) throws IOException {
        return client.newCall(new Request.Builder().delete().url(baseUrl + path).build()).execute();
    }

    private static String body(Response response) throws IOException {
        return (response.peekBody(8192)).string();
    }

}
