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
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
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
 * {@code /c/<path>} behind a servlet context path.
 *
 * <p>A whole test class for one property, because the defect it exists for is invisible
 * without it and was: {@code redirectToLogin} fed {@code getRequestURI()} — which already
 * contains the context path — into {@code fromCurrentContextPath()}, which adds it again. With
 * a context of {@code /skald}, a signed-out visitor following a shared link was sent back to
 * {@code /skald/skald/c/...} after signing in and got a 404. The dev stack and every other
 * test run at the root, so 133 tests and 47 live checks all passed over it.
 *
 * <p>Found by an independent review, and the reason it is worth its own boot: a property that
 * nothing exercises is a property that is wrong.
 */
public class ContentContextPathTest {

    private static final int PORT = 7593;
    private static final String CONTEXT = "/skald";
    private static final String IMAGE = "openanalytics/shinyproxy-integration-test-app:latest";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final Pattern ID = Pattern.compile("\"id\":\"([0-9a-f-]{36})\"");

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static ConfigurableApplicationContext app;
    private static JdbcTemplate jdbc;
    private static OkHttpClient client;
    private static String baseUrl;

    @BeforeAll
    public static void beforeAll() {
        POSTGRES.start();

        SpringApplication application = new SpringApplication(ContainerProxyApplication.class);
        Properties properties = ContainerProxyApplication.getDefaultProperties();
        properties.put("spring.config.location", "src/test/resources/application-test-contextpath.yml");
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
        baseUrl = "http://localhost:" + PORT + CONTEXT;
        client = new OkHttpClient.Builder()
            .followRedirects(false)
            .callTimeout(60, TimeUnit.SECONDS)
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

    /**
     * The destination remembered for after sign-in must carry the context path exactly once.
     *
     * <p>Asserted on the stored session attribute's effect rather than on the attribute
     * itself: what matters is that the URL a visitor is sent back to actually resolves.
     */
    @Test
    public void theRememberedDestinationCarriesTheContextPathExactlyOnce() throws IOException {
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.content_path");
        publish("shared/link");

        Request request = new Request.Builder()
            .get().url(baseUrl + "/c/shared/link/?tab=2").build();

        String sessionCookie;
        try (Response r = client.newCall(request).execute()) {
            Assertions.assertTrue(r.isRedirect(), "expected a redirect to sign in, got " + r.code());
            sessionCookie = r.header("Set-Cookie");
            Assertions.assertNotNull(sessionCookie, "no session to remember the destination in");
        }

        // /auth-success renders the stored destination into the page it returns.
        Request success = new Request.Builder().get().url(baseUrl + "/auth-success")
            .header("Cookie", sessionCookie.split(";")[0])
            .header("Authorization", basic("adminuser"))
            .build();

        try (Response r = client.newCall(success).execute()) {
            String body = r.peekBody(65536).string().replace("\\/", "/");
            Assertions.assertFalse(body.contains(CONTEXT + CONTEXT),
                "the context path was added twice, so signing in lands on a 404: " + CONTEXT
                    + CONTEXT + " appears in the auth-success page");
            Assertions.assertTrue(body.contains(CONTEXT + "/c/shared/link/?tab=2"),
                "the destination was not remembered at all; page said: "
                    + body.replaceAll("(?s).*?(window\\.location[^;]*).*", "$1"));
        }
    }

    /** Sanity: the route works at all behind a context path. */
    @Test
    public void contentIsServedBeneathTheContextPath() throws IOException {
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.content_path");
        publish("ctx/app");

        Request request = new Request.Builder().get().url(baseUrl + "/c/ctx/app")
            .header("Authorization", basic("adminuser")).build();
        try (Response r = client.newCall(request).execute()) {
            Assertions.assertTrue(r.isRedirect(), "expected the add-a-slash redirect, got " + r.code());
            Assertions.assertEquals(baseUrl + "/c/ctx/app/", r.header("Location"),
                "the trailing-slash redirect mangled the context path");
        }
    }

    // ------------------------------------------------------------------- fixtures

    private static String basic(String user) {
        return "Basic " + Base64.getEncoder()
            .encodeToString((user + ":" + user).getBytes(StandardCharsets.UTF_8));
    }

    private static void publish(String path) throws IOException {
        String id;
        try (Response r = post("/admin/content",
            "{\"path\":\"" + path + "\",\"title\":\"" + path + "\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), r.peekBody(4096).string());
            Matcher matcher = ID.matcher(r.peekBody(4096).string());
            Assertions.assertTrue(matcher.find());
            id = matcher.group(1);
        }
        try (Response r = post("/admin/content/" + id + "/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(201, r.code(), r.peekBody(4096).string());
        }
    }

    private static Response post(String path, String json) throws IOException {
        return client.newCall(new Request.Builder()
            .post(RequestBody.create(json, JSON))
            .header("Authorization", basic("adminuser"))
            .url(baseUrl + path).build()).execute();
    }

}
