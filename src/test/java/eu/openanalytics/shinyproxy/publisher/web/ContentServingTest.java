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
package eu.openanalytics.shinyproxy.publisher.web;

import eu.openanalytics.containerproxy.ContainerProxyApplication;
import eu.openanalytics.containerproxy.service.ProxyService;
import eu.openanalytics.containerproxy.test.helpers.ShinyProxyClient;
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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code /c/<path>} — serving published content at the publisher's own URL.
 *
 * <p>Weighted towards the answers rather than the happy path, because every one of them is a
 * promise made to a link that someone else is holding: a renamed path still resolves, a
 * deleted one says so rather than going quiet, a shared link survives signing in, and a URL
 * someone was never given does not confirm it exists.
 *
 * <p>Note what a unit test cannot reach here and where it is covered instead: the post-login
 * hand-off runs through Keycloak and a rendered page, so {@code dev/smoke.sh} drives the real
 * browser flow. This class asserts the half it can — that the destination is remembered.
 */
public class ContentServingTest {

    private static final int PORT = 7591;
    private static final String IMAGE = "openanalytics/shinyproxy-integration-test-app:latest";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final Pattern ID = Pattern.compile("\"id\":\"([0-9a-f-]{36})\"");

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static ConfigurableApplicationContext app;
    private static JdbcTemplate jdbc;
    private static ProxyService proxyService;
    private static ShinyProxyClient owner;
    private static ShinyProxyClient stranger;
    private static OkHttpClient signedOut;
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
        proxyService = app.getBean(ProxyService.class);

        owner = new ShinyProxyClient("adminuser", PORT);
        stranger = new ShinyProxyClient("plainuser", PORT);
        baseUrl = owner.getBaseUrl();
        signedOut = new OkHttpClient.Builder()
            .followRedirects(false)
            .callTimeout(60, TimeUnit.SECONDS)
            .build();
    }

    @AfterAll
    public static void afterAll() {
        if (app != null) {
            proxyService.getAllProxies().forEach(p -> proxyService.stopProxy(null, p, true).run());
            app.stop();
            app.close();
        }
        POSTGRES.stop();
    }

    @BeforeEach
    public void beforeEach() {
        proxyService.getAllProxies().forEach(p -> proxyService.stopProxy(null, p, true).run());
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.content_path");
    }

    // ------------------------------------------------------------------ not found

    @Test
    public void anAddressNobodyPublishedIsNotFound() throws IOException {
        assertStatus(404, owner, "/c/nothing-here/");
    }

    /**
     * Publishing {@code etl/fetchFromA} and {@code etl/fetchFromB} does not put anything at
     * {@code /c/etl/}, and nothing can be published there either — a document at {@code etl}
     * would own {@code etl/fetchFromA} as one of its own pages. Spine #4 replaces this 404
     * with a generated index of what the viewer may see beneath it; until then, trimming the
     * URL back is a dead end and should say so honestly.
     */
    @Test
    public void anIntermediateLevelIsNotFoundRatherThanAnEmptyPage() throws IOException {
        publish("etl/fetchFromA");
        publish("etl/fetchFromB");

        assertStatus(404, owner, "/c/etl/");
        assertStatus(404, owner, "/c/etl");
    }

    @Test
    public void contentWithNoActiveVersionIsNotFound() throws IOException {
        createOnly("claimed-but-empty");
        assertStatus(404, owner, "/c/claimed-but-empty/");
    }

    // ------------------------------------------------------------------ serving

    @Test
    public void contentIsServedAtThePublishersOwnAddress() throws IOException {
        publish("finance/report");

        try (Response r = get(owner, "/c/finance/report/")) {
            Assertions.assertEquals(200, r.code(), "the published address did not serve the app");
        }
    }

    /**
     * The regression that only a second request reveals.
     * {@code UserAndAppNameAndInstanceNameProxyIndex} matches a running proxy on its
     * {@code AppInstanceKey} runtime value, so a proxy started without one is never found
     * again: every later request tried to start another container and the second one failed on
     * {@code max-instances}. First request 200, second 500 — invisible to any test that asks
     * once.
     */
    @Test
    public void aSecondRequestReusesTheRunningContainer() throws IOException {
        publish("reused");

        assertStatus(200, owner, "/c/reused/");
        assertStatus(200, owner, "/c/reused/");
        assertStatus(200, owner, "/c/reused/");

        Assertions.assertEquals(1, proxyService.getAllProxies().size(),
            "each request started its own container instead of reusing the first");
    }

    @Test
    public void aRequestWithoutTheTrailingSlashIsRedirectedToIt() throws IOException {
        publish("slashless");

        try (Response r = getWithoutFollowing("adminuser", "/c/slashless")) {
            Assertions.assertTrue(r.isRedirect(), "expected a redirect, got " + r.code());
            Assertions.assertTrue(r.header("Location").endsWith("/c/slashless/"),
                "relative links inside the app resolve one level too high without it; got "
                    + r.header("Location"));
        }
    }

    /** Activating a new version must not move the address — that is the whole point of it. */
    @Test
    public void publishingANewVersionDoesNotChangeTheAddress() throws IOException {
        String id = publish("stable-url");
        addVersion(id);

        assertStatus(200, owner, "/c/stable-url/");
    }

    // ------------------------------------------------------------------ refusals

    /**
     * ADR-0011 rule 5. 403 would confirm that something exists at an address a stranger
     * guessed or was forwarded, and the index already hides content a user may not see, so 403
     * here would contradict it.
     */
    @Test
    public void aStrangerGetsNotFoundRatherThanForbidden() throws IOException {
        publish("private-thing");

        try (Response r = get(stranger, "/c/private-thing/")) {
            Assertions.assertEquals(404, r.code(),
                "a stranger must not be able to tell this address is in use");
            Assertions.assertNotEquals(403, r.code(), "403 confirms the content exists");
        }
    }

    /**
     * The status has to be right for a browser too, and that is not automatic: forwarding to
     * {@code /error} with {@code ERROR_STATUS_CODE} set — which is what upstream's app
     * controllers do — leaves the response at 200. Measured before the fix: 404 to a
     * wildcard {@code Accept}, 200 to {@code text/html}.
     */
    @Test
    public void refusalsCarryTheirStatusForBrowsersNotOnlyForApiClients() throws IOException {
        publish("private-thing");

        try (Response r = get(stranger, "/c/private-thing/", "text/html")) {
            Assertions.assertEquals(404, r.code(),
                "a browser was told 'not found' with a success status");
        }
        try (Response r = get(owner, "/c/nothing-here/", "text/html")) {
            Assertions.assertEquals(404, r.code());
        }
    }

    // ------------------------------------------------------------------ rename and delete

    @Test
    public void aRenamedAddressRedirectsAndKeepsTheSubPath() throws IOException {
        String id = publish("old-name");
        rename(id, "new-name");

        try (Response r = getWithoutFollowing("adminuser", "/c/old-name/chapter2.html")) {
            Assertions.assertEquals(301, r.code(), "a shared deep link stopped working");
            Assertions.assertTrue(r.header("Location").endsWith("/c/new-name/chapter2.html"),
                "the redirect dropped the sub-path, so the link lands on the front page "
                    + "instead of the page that was shared; got " + r.header("Location"));
        }
    }

    /**
     * Gone, not missing. The difference is the promise that nobody else will ever answer here
     * — a 404 invites "try again later", and a redirect to whoever takes the address next is
     * the bug this whole design exists to prevent.
     */
    @Test
    public void aDeletedAddressIsGoneAndStaysReserved() throws IOException {
        String id = publish("deleted-thing");
        rename(id, "renamed-then-deleted");
        delete(id);

        assertStatus(410, owner, "/c/renamed-then-deleted/");
        assertStatus(410, owner, "/c/deleted-thing/");

        try (Response r = post(owner, "/admin/content",
            "{\"path\":\"deleted-thing\",\"title\":\"x\",\"owner\":\"adminuser\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), "a retired address was handed to new content");
        }
    }

    /**
     * The retired address must not answer to someone the content is not shared with.
     *
     * <p>Found by an independent review after this class was already green. The rename
     * redirect ran before any authorization, so a stranger who correctly got 404 at the
     * current address was handed that address by the old one — and so was a signed-out
     * caller. It never exposed the content body, but it is precisely the existence
     * disclosure rule 5 exists to prevent, and a redirect is a statement about content the
     * caller may not know exists.
     */
    @Test
    public void aRetiredAddressIsAuthorizedBeforeItRedirects() throws IOException {
        String id = publish("owner-only");
        rename(id, "owner-only-moved");

        assertStatus(404, stranger, "/c/owner-only-moved/");
        try (Response r = getWithoutFollowing("plainuser", "/c/owner-only/")) {
            Assertions.assertEquals(404, r.code(),
                "the retired address told a stranger where the content went; Location was "
                    + r.header("Location"));
        }

        Request anonymous = new Request.Builder().get().url(baseUrl + "/c/owner-only/").build();
        try (Response r = signedOut.newCall(anonymous).execute()) {
            Assertions.assertTrue(r.header("Location") == null
                    || !r.header("Location").contains("owner-only-moved"),
                "a signed-out caller was told the new address: " + r.header("Location"));
        }

        // Still works for someone who may actually see it.
        try (Response r = getWithoutFollowing("adminuser", "/c/owner-only/")) {
            Assertions.assertEquals(301, r.code(), "the owner lost their redirect");
        }
    }

    /**
     * The sub-path belongs to the content, so it has to arrive exactly as it was sent.
     * {@code URI.create(uri).getPath()} decoded it: {@code chapter%20one.html} became a real
     * space, {@code a%23b} a fragment delimiter, and {@code a%3Fb} a real {@code ?} — so
     * everything after it was silently reinterpreted as a query string. Asserted on the
     * redirect, where the outgoing value is directly observable.
     */
    @Test
    public void anEncodedSubPathIsNotDecodedOnTheWayThrough() throws IOException {
        String id = publish("encoded");
        rename(id, "encoded-moved");

        for (String encoded : new String[]{"chapter%20one.html", "a%3Fb", "a%23b", "caf%C3%A9.png"}) {
            try (Response r = getWithoutFollowing("adminuser", "/c/encoded/" + encoded)) {
                Assertions.assertEquals(301, r.code(), encoded);
                Assertions.assertEquals(baseUrl + "/c/encoded-moved/" + encoded, r.header("Location"),
                    "the sub-path was re-encoded or decoded in transit");
            }
        }
    }

    /** A shared link with state in it is the main thing these URLs are for. */
    @Test
    public void redirectsKeepTheQueryString() throws IOException {
        String id = publish("querykeeper");

        try (Response r = getWithoutFollowing("adminuser", "/c/querykeeper?tab=2&x=1")) {
            Assertions.assertTrue(r.isRedirect(), "expected the add-a-slash redirect");
            Assertions.assertEquals(baseUrl + "/c/querykeeper/?tab=2&x=1", r.header("Location"),
                "the trailing-slash redirect dropped the query");
        }

        rename(id, "querykeeper-moved");
        try (Response r = getWithoutFollowing("adminuser", "/c/querykeeper/?tab=2")) {
            Assertions.assertEquals(301, r.code());
            Assertions.assertEquals(baseUrl + "/c/querykeeper-moved/?tab=2", r.header("Location"),
                "the rename redirect dropped the query");
        }
    }

    // ------------------------------------------------------------------ signing in

    /**
     * ADR-0011 rule 5's other half. Spring's saved request is not enough on its own:
     * {@code UISecurityConfig} only restores a destination that {@code AppRequestInfo} can
     * parse, which means {@code /app*} and nothing else, so a signed-out visitor following a
     * shared {@code /c/} link would land on the index. The controller therefore sets the same
     * session attribute upstream's own handler sets.
     *
     * <p>Asserted here as far as a test client can: the redirect goes to the login page and
     * the destination is remembered. {@code dev/smoke.sh} drives the rest through Keycloak.
     */
    @Test
    public void aSignedOutVisitorIsSentToLoginAndTheDestinationIsRemembered() throws IOException {
        publish("shared/link");

        Request request = new Request.Builder()
            .get().url(baseUrl + "/c/shared/link/?tab=2").build();

        try (Response r = signedOut.newCall(request).execute()) {
            Assertions.assertTrue(r.isRedirect(), "expected a redirect to sign in, got " + r.code());
            Assertions.assertTrue(r.header("Location").contains("/login"),
                "expected the login page, got " + r.header("Location"));
            Assertions.assertNotNull(r.header("Set-Cookie"),
                "a session is needed to remember where the visitor was going");
        }
    }

    // ------------------------------------------------------------------- fixtures

    private static String publish(String path) throws IOException {
        String id = createOnly(path);
        addVersion(id);
        return id;
    }

    private static String createOnly(String path) throws IOException {
        try (Response r = post(owner, "/admin/content",
            "{\"path\":\"" + path + "\",\"title\":\"" + path + "\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
            Matcher matcher = ID.matcher(body(r));
            Assertions.assertTrue(matcher.find(), "no id in " + body(r));
            return matcher.group(1);
        }
    }

    private static void addVersion(String id) throws IOException {
        try (Response r = post(owner, "/admin/content/" + id + "/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }
    }

    private static void rename(String id, String path) throws IOException {
        try (Response r = put(owner, "/admin/content/" + id + "/path",
            "{\"path\":\"" + path + "\"}")) {
            Assertions.assertEquals(200, r.code(), body(r));
        }
    }

    private static void delete(String id) throws IOException {
        Request request = new Request.Builder().delete().url(baseUrl + "/admin/content/" + id).build();
        try (Response r = owner.newCall(request).execute()) {
            Assertions.assertEquals(200, r.code(), body(r));
        }
    }

    private static void assertStatus(int expected, ShinyProxyClient client, String path)
        throws IOException {
        try (Response r = get(client, path)) {
            Assertions.assertEquals(expected, r.code(), path + " -> " + body(r));
        }
    }

    private static Response get(ShinyProxyClient client, String path) throws IOException {
        return get(client, path, "*/*");
    }

    private static Response get(ShinyProxyClient client, String path, String accept)
        throws IOException {
        return client.newCall(new Request.Builder()
            .get().header("Accept", accept).url(baseUrl + path).build()).execute();
    }

    /**
     * {@code ShinyProxyClient} follows redirects, which is right for every other call here and
     * useless for asserting on one: a 301 to a page the test app does not serve comes back as
     * the container's own 404, and a 302 to add a trailing slash comes back as 200. This client
     * carries the same basic-auth credentials and stops at the redirect.
     */
    private static Response getWithoutFollowing(String user, String path) throws IOException {
        String credentials = Base64.getEncoder()
            .encodeToString((user + ":" + user).getBytes(StandardCharsets.UTF_8));
        return signedOut.newCall(new Request.Builder()
            .get().header("Authorization", "Basic " + credentials)
            .url(baseUrl + path).build()).execute();
    }

    private static Response post(ShinyProxyClient client, String path, String json)
        throws IOException {
        return client.newCall(new Request.Builder()
            .post(RequestBody.create(json, JSON)).url(baseUrl + path).build()).execute();
    }

    private static Response put(ShinyProxyClient client, String path, String json)
        throws IOException {
        return client.newCall(new Request.Builder()
            .put(RequestBody.create(json, JSON)).url(baseUrl + path).build()).execute();
    }

    private static String body(Response response) throws IOException {
        return response.peekBody(8192).string();
    }

}
