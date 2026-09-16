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
import eu.openanalytics.shinyproxy.publisher.registry.ContentPath;
import eu.openanalytics.shinyproxy.publisher.registry.ContentSpecRepository;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
        // content_path rows deliberately SURVIVE a content delete -- that is the reservation
        // that stops a retired URL pointing at different content later. A test resetting the
        // world has to clear them explicitly; a test that means to exercise the reservation
        // must not.
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.content_path");
        jdbc.update("DELETE FROM skald.audit_event");
    }

    // ------------------------------------------------------------------- lifecycle

    @Test
    public void createPublishesContentThatIsImmediatelyResolvable() throws IOException {
        String id = createContent("report");
        addVersion(id);

        // No restart: the spec exists the moment the row does.
        Assertions.assertNotNull(specProvider.getSpec(specIdOf(id, 1)),
            "content created over HTTP did not become a resolvable spec");
    }

    @Test
    public void activateMovesTheActiveVersionAndRollbackMovesItBack() throws IOException {
        String id = createContent("rollme");
        addVersion(id);
        addVersion(id);

        Assertions.assertEquals(List.of(specIdOf(id, 2)), registryIds(),
            "adding a version should activate it by default");

        try (Response rollback = put(admin, "/admin/content/" + id + "/active-version",
            """
            {"version":1}
            """)) {
            Assertions.assertEquals(200, rollback.code(), body(rollback));
        }
        Assertions.assertEquals(List.of(specIdOf(id, 1)), registryIds(), "rollback did not take effect");
        Assertions.assertNotNull(specProvider.getSpec(specIdOf(id, 1)), "the active version resolves");
        Assertions.assertNull(specProvider.getSpec(specIdOf(id, 2)),
            "with nothing running on it, the rolled-back-from version must stop resolving — "
                + "otherwise rollback would not actually retire v2");
    }

    @Test
    public void deleteRemovesTheContentAndItsSpecs() throws IOException {
        String id = createContent("goner");
        addVersion(id);
        Assertions.assertNotNull(specProvider.getSpec(specIdOf(id, 1)), "precondition");

        try (Response deleted = delete(admin, "/admin/content/" + id)) {
            Assertions.assertEquals(200, deleted.code(), body(deleted));
        }
        Assertions.assertNull(specProvider.getSpec(specIdOf(id, 1)));
    }

    @Test
    public void everyMutationIsAudited() throws IOException {
        String id = createContent("audited");
        addVersion(id);
        try (Response ignored = delete(admin, "/admin/content/" + id)) {
            Assertions.assertEquals(200, ignored.code());
        }

        // Subject is the content UUID, never the path: the path is mutable, so identifying by
        // it would orphan every row written before a rename.
        List<String> actions = jdbc.queryForList(
            "SELECT action FROM skald.audit_event WHERE subject_id = ? ORDER BY id",
            String.class, id);
        Assertions.assertEquals(
            List.of("content.create", "content.version.add", "content.activate", "content.delete"),
            actions);

        String actor = jdbc.queryForObject(
            "SELECT actor FROM skald.audit_event WHERE subject_id = ? LIMIT 1", String.class, id);
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
        String id = createContent("existing");

        try (Response r = get(plain, "/admin/content")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could LIST registry content");
        }
        try (Response r = post(plain, "/admin/content",
            "{\"path\":\"sneaky\",\"title\":\"sneaky\",\"owner\":\"plainuser\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could CREATE content");
        }
        try (Response r = post(plain, "/admin/content/" + id + "/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could add a VERSION");
        }
        try (Response r = put(plain, "/admin/content/" + id + "/active-version", "{\"version\":1}")) {
            Assertions.assertEquals(403, r.code(), "a non-admin could ACTIVATE a version");
        }
        try (Response r = delete(plain, "/admin/content/" + id)) {
            Assertions.assertEquals(403, r.code(), "a non-admin could DELETE content");
        }

        Assertions.assertTrue(paths().contains("existing"),
            "the refused calls must not have changed anything");
        Assertions.assertFalse(paths().contains("sneaky"));
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
            "path=sneaky&title=x&owner=adminuser&type=shiny",
            MediaType.get("application/x-www-form-urlencoded"));
        Request request = new Request.Builder().post(form).url(baseUrl + "/admin/content").build();

        try (Response r = admin.newCall(request).execute()) {
            Assertions.assertEquals(415, r.code(),
                "a form-encoded POST was accepted — the cross-site-request defence is gone");
        }
        Assertions.assertFalse(paths().contains("sneaky"));
    }

    // ------------------------------------------------------------------- refusals

    @Test
    public void anonymousVisibilityIsRefusedOnWrite() throws IOException {
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"public-thing\",\"title\":\"Public\",\"owner\":\"alice\",\"type\":\"shiny\",\"visibility\":\"anonymous\"}")) {
            Assertions.assertEquals(400, r.code());
            Assertions.assertTrue(body(r).contains("anonymous"), "the reason should name the mode");
        }
        Assertions.assertFalse(paths().contains("public-thing"));
    }

    /**
     * Review finding F4, closed by construction rather than by a check.
     *
     * <p>The old rule compared a publisher's slug against the configured spec ids, and was
     * incomplete: it compared the bare slug, so publishing {@code probe} produced the spec id
     * {@code probe--v1} and captured an admin's configured {@code probe--v1}. Paths and spec
     * ids are now separate namespaces — the id comes from the content UUID — so a publisher
     * naming their content after a configured spec is simply harmless, and there is nothing
     * left to check.
     */
    @Test
    public void aPathNamedAfterAConfiguredSpecIsHarmless() throws IOException {
        String id = createContent("boot-spec");
        addVersion(id);

        Assertions.assertNotNull(specProvider.getSpec("boot-spec"),
            "the configured spec must still be at its own id");
        Assertions.assertEquals("Present at startup",
            specProvider.getSpec("boot-spec").getDisplayName(),
            "the configured spec was shadowed by registry content");
        Assertions.assertNotNull(specProvider.getSpec(specIdOf(id, 1)),
            "the registry content works too, under its own id");
        Assertions.assertTrue(specIdOf(id, 1).startsWith("c"),
            "registry ids must be UUID-derived and so cannot collide with a configured id");
    }

    @Test
    public void duplicateSlugsAndBadInputAreRefused() throws IOException {
        String id = createContent("taken");

        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"taken\",\"title\":\"taken\",\"owner\":\"alice\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), "duplicate path");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"Not A Path!\",\"title\":\"x\",\"owner\":\"alice\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(400, r.code(), "path format");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"weird\",\"title\":\"weird\",\"owner\":\"alice\",\"type\":\"cobol\"}")) {
            Assertions.assertEquals(400, r.code(), "unknown type");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"ownerless\",\"title\":\"x\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(400, r.code(), "missing owner");
        }
        try (Response r = put(admin, "/admin/content/" + id + "/active-version", "{\"version\":99}")) {
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
        String id = createContent("busy");
        addVersion(id);

        String proxyId = admin.startProxy(specIdOf(id, 1));
        Assertions.assertNotNull(proxyId, "precondition: the container started");
        try {
            try (Response r = delete(admin, "/admin/content/" + id)) {
                Assertions.assertEquals(409, r.code(),
                    "content with a running app was deleted, stranding the container");
                Assertions.assertTrue(body(r).contains(specIdOf(id, 1)),
                    "the refusal should name what is still running");
            }
            Assertions.assertTrue(paths().contains("busy"), "the content should still be there");
        } finally {
            admin.stopProxy(proxyId);
        }

        // ...and once nothing is running, the same delete succeeds.
        try (Response r = delete(admin, "/admin/content/" + id)) {
            Assertions.assertEquals(200, r.code(), body(r));
        }
    }

    // ------------------------------------------------------------ paths (review F1)

    /**
     * The identity half of review finding F1.
     *
     * <p>Spec ids used to come from the publisher's slug, so deleting content and re-creating
     * it handed the new content the old one's id — and ContainerProxy memoises authorization
     * per {@code (sessionId, specId)} with no way to invalidate it, so a user whose grant had
     * been removed kept access to whatever next occupied the id. Ids now come from the content
     * UUID and are never reused. {@code ContentAccessControlTest} covers the authorization
     * consequence; this covers the property it rests on.
     */
    @Test
    public void aRecreatedContentItemNeverInheritsTheOldSpecId() throws IOException {
        String first = createContent("probe-one");
        addVersion(first);
        String firstSpecId = specIdOf(first, 1);

        try (Response r = delete(admin, "/admin/content/" + first)) {
            Assertions.assertEquals(200, r.code(), body(r));
        }

        String second = createContent("probe-two");
        addVersion(second);

        Assertions.assertNotEquals(firstSpecId, specIdOf(second, 1),
            "a new content item was handed a retired spec id");
        Assertions.assertNull(specProvider.getSpec(firstSpecId),
            "the retired spec id still resolves");
    }

    /** A retired path stays reserved, so nobody can inherit its audience or its links. */
    @Test
    public void aPathIsReservedOnceUsedAndStaysReservedAfterDeletion() throws IOException {
        String id = createContent("finance/quarterly");
        try (Response r = delete(admin, "/admin/content/" + id)) {
            Assertions.assertEquals(200, r.code(), body(r));
        }

        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"finance/quarterly\",\"title\":\"Mine now\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(),
                "a retired path was handed to different content, which would inherit every "
                    + "stale link pointing at it");
        }

        // ...and it answers Gone rather than Not Found, which is the promise that nothing else
        // will ever answer there.
        try (Response r = get(admin, "/admin/content/by-path?path=finance/quarterly")) {
            Assertions.assertEquals(410, r.code(), body(r));
        }
    }

    @Test
    public void renamingKeepsTheOldPathResolvableAndTheSpecIdUnchanged() throws IOException {
        String id = createContent("old-name");
        addVersion(id);
        String specBefore = specIdOf(id, 1);

        try (Response r = put(admin, "/admin/content/" + id + "/path",
            "{\"path\":\"new-name\"}")) {
            Assertions.assertEquals(200, r.code(), body(r));
        }

        // The spec id is UUID-derived, so a rename cannot orphan a running container.
        Assertions.assertEquals(specBefore, specIdOf(id, 1));
        Assertions.assertNotNull(specProvider.getSpec(specBefore));

        try (Response r = get(admin, "/admin/content/by-path?path=new-name")) {
            Assertions.assertEquals(200, r.code(), body(r));
            Assertions.assertTrue(body(r).contains("\"pathIsCurrent\":true"), body(r));
        }
        // The old name still resolves, so a rename does not silently break existing scripts --
        // the non-browser equivalent of the 301 a bookmark would get.
        try (Response r = get(admin, "/admin/content/by-path?path=old-name")) {
            Assertions.assertEquals(200, r.code(), body(r));
            Assertions.assertTrue(body(r).contains("\"pathIsCurrent\":false"), body(r));
            Assertions.assertTrue(body(r).contains(id), body(r));
        }
        // And nobody else may take it.
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"old-name\",\"title\":\"x\",\"owner\":\"adminuser\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), body(r));
        }
    }

    /**
     * Content owns its whole subtree, so one path may not sit inside another: a request for
     * {@code /c/team/reports} would otherwise be satisfiable two ways and the resolver would
     * have no basis to choose. Refused at publish time, in both directions.
     */
    @Test
    public void nestedPathsAreRefusedInBothDirections() throws IOException {
        createContent("team/reports");

        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"team\",\"title\":\"x\",\"owner\":\"adminuser\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), "a parent of an existing path was accepted");
        }
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"team/reports/q1\",\"title\":\"x\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), "a child of an existing path was accepted");
        }
        // A sibling is fine -- it is not in anyone's subtree.
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"team-reports\",\"title\":\"x\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }
    }

    @Test
    public void pathsAreMatchedCaseInsensitivelyButStoredAsWritten() throws IOException {
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"Finance/QuarterlyReport\",\"title\":\"Q\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }
        Assertions.assertTrue(paths().contains("Finance/QuarterlyReport"),
            "the publisher's capitalisation should be preserved for display, got " + paths());

        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"finance/quarterlyreport\",\"title\":\"x\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(409, r.code(), "case must not be enough to make a path distinct");
        }
        try (Response r = get(admin, "/admin/content/by-path?path=FINANCE/QUARTERLYREPORT")) {
            Assertions.assertEquals(200, r.code(), "lookup must be case-insensitive");
        }
    }

    @Test
    public void malformedPathsAreRefused() throws IOException {
        for (String path : List.of("a/b/c/d", "/leading", "trailing/", "UPPER CASE",
                "-starts-with-hyphen", "has_underscore", "rapporté", "a//b")) {
            try (Response r = post(admin, "/admin/content",
                "{\"path\":\"" + path + "\",\"title\":\"x\",\"owner\":\"adminuser\","
                    + "\"type\":\"shiny\"}")) {
                Assertions.assertEquals(400, r.code(), "path '" + path + "' should be refused");
            }
        }
        Assertions.assertTrue(paths().isEmpty(), "a refused path must not have been stored");
    }

    // ------------------------------------------------- robustness (review F2, F3)

    /**
     * F2: {@code audit()} hand-rolled its JSON and escaped only quote and backslash, so any
     * control character produced invalid JSON, failed the {@code ?::jsonb} cast, and rolled the
     * whole mutation back with an unrecoverable-error body. Fields reaching it are not all
     * validated — {@code owner} and {@code image} are only checked for being non-blank, and the
     * trim they get leaves embedded newlines intact.
     */
    @Test
    public void controlCharactersInAuditedFieldsDoNotBreakTheWrite() throws IOException {
        String ctrlId;
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"ctrl\",\"title\":\"ctrl\",\"owner\":\"al\\nice\",\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
            ctrlId = idOf(body(r));
        }
        try (Response r = post(admin, "/admin/content/" + ctrlId + "/versions",
            "{\"image\":\"img\\nbad\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }

        Assertions.assertTrue(paths().contains("ctrl"), "the mutation was rolled back");
        Assertions.assertEquals("al\nice", jdbc.queryForObject(
            "SELECT detail_json->>'owner' FROM skald.audit_event WHERE action = 'content.create'",
            String.class), "the audit detail must survive round-tripping through jsonb");
        Assertions.assertEquals("img\nbad", jdbc.queryForObject(
            "SELECT detail_json->>'image' FROM skald.audit_event WHERE action = 'content.version.add'",
            String.class));
    }

    /**
     * F3: create and addVersion were check-then-insert, so concurrent callers got 500s from the
     * unique constraint instead of the 409 the API documents. Integrity was never at risk; the
     * contract was.
     */
    @Test
    public void concurrentCreatesOfOneSlugYieldOneCreatedAndTheRestConflict() throws Exception {
        int callers = 6;
        List<Integer> codes = inParallel(callers, () -> {
            try (Response r = post(admin, "/admin/content",
                "{\"path\":\"racy\",\"title\":\"racy\",\"owner\":\"adminuser\",\"type\":\"shiny\"}")) {
                return r.code();
            }
        });

        Assertions.assertEquals(1, codes.stream().filter(c -> c == 201).count(),
            "exactly one caller should create it, got " + codes);
        Assertions.assertEquals(callers - 1, codes.stream().filter(c -> c == 409).count(),
            "every loser should get 409, got " + codes);
        Assertions.assertEquals(1, paths().stream().filter("racy"::equals).count());
    }

    @Test
    public void concurrentVersionAddsAllSucceedWithDistinctVersions() throws Exception {
        String id = createContent("versioned");

        int callers = 6;
        List<Integer> codes = inParallel(callers, () -> {
            try (Response r = post(admin, "/admin/content/" + id + "/versions",
                "{\"image\":\"" + IMAGE + "\"}")) {
                return r.code();
            }
        });

        Assertions.assertTrue(codes.stream().allMatch(c -> c == 201 || c == 409),
            "version allocation produced something other than 201/409: " + codes);
        Assertions.assertEquals(codes.stream().filter(c -> c == 201).count(),
            (long) jdbc.queryForObject("""
                SELECT count(DISTINCT version) FROM skald.content_version WHERE content_id = ?::uuid
                """, Integer.class, id),
            "every success must have allocated a distinct version");
    }

    /**
     * B1: nesting is a relationship between two rows, so no constraint expresses it and the
     * check that enforces it is read-then-write. Before {@code claimPath} took an advisory lock
     * on the path's first segment, four parallel creates of {@code race}, {@code race/a},
     * {@code race/b} and {@code race/a/deep} <em>all</em> returned 201 and all four rows
     * survived — which is exactly the state {@code /c/<path>} resolution has no basis to
     * answer. Found by driving the live stack, not by this suite.
     *
     * <p>The assertion is on the invariant, not on a count: siblings like {@code race/a} and
     * {@code race/b} may legitimately both win, so several outcomes are correct and the only
     * thing that must hold is that no two surviving paths nest.
     */
    @Test
    public void concurrentlyClaimedPathsNeverNestInsideOneAnother() throws Exception {
        List<String> wanted = List.of("race", "race/a", "race/b", "race/a/deep");

        List<Integer> codes = inParallel(wanted.stream().map(path -> (Callable<Integer>) () -> {
            try (Response r = post(admin, "/admin/content",
                "{\"path\":\"" + path + "\",\"title\":\"x\",\"owner\":\"adminuser\","
                    + "\"type\":\"shiny\"}")) {
                return r.code();
            }
        }).toList());

        Assertions.assertTrue(codes.stream().allMatch(c -> c == 201 || c == 409),
            "claiming a path produced something other than 201/409: " + codes);

        List<String> stored = paths().stream()
            .filter(p -> p.equals("race") || p.startsWith("race/"))
            .toList();
        Assertions.assertFalse(stored.isEmpty(), "at least one caller should have won");
        Assertions.assertEquals(codes.stream().filter(c -> c == 201).count(), stored.size(),
            "every 201 should have left exactly one row, got " + stored + " for " + codes);

        for (String a : stored) {
            for (String b : stored) {
                Assertions.assertFalse(ContentPath.conflicts(a, b),
                    "'" + a + "' and '" + b + "' nest inside one another, so a request below "
                        + "the shorter one is satisfiable two ways: " + stored);
            }
        }
    }

    private static List<Integer> inParallel(int callers, Callable<Integer> call) throws Exception {
        return inParallel(Collections.nCopies(callers, call));
    }

    private static List<Integer> inParallel(List<Callable<Integer>> calls) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(calls.size());
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Integer>> futures = new ArrayList<>();
            for (Callable<Integer> call : calls) {
                futures.add(pool.submit(() -> {
                    go.await();
                    return call.call();
                }));
            }
            go.countDown();
            List<Integer> codes = new ArrayList<>();
            for (Future<Integer> f : futures) {
                codes.add(f.get(60, TimeUnit.SECONDS));
            }
            return codes;
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------------- fixtures

    /** Creates content at a path and returns its id, which is what mutating endpoints take. */
    private static String createContent(String path) throws IOException {
        try (Response r = post(admin, "/admin/content",
            "{\"path\":\"" + path + "\",\"title\":\"" + path + "\",\"owner\":\"adminuser\","
                + "\"type\":\"shiny\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
            return idOf(body(r));
        }
    }

    private static void addVersion(String contentId) throws IOException {
        try (Response r = post(admin, "/admin/content/" + contentId + "/versions",
            "{\"image\":\"" + IMAGE + "\"}")) {
            Assertions.assertEquals(201, r.code(), body(r));
        }
    }

    private static String idOf(String responseBody) {
        Matcher m = Pattern.compile("\"id\"\\s*:\\s*\"([0-9a-f-]{36})\"").matcher(responseBody);
        Assertions.assertTrue(m.find(), "no content id in response: " + responseBody);
        return m.group(1);
    }

    private static String specIdOf(String contentId, int version) {
        return ContentSpecRepository.specId(UUID.fromString(contentId), version);
    }

    /** The live paths currently in the registry. */
    private static List<String> paths() {
        return jdbc.queryForList("""
            SELECT path FROM skald.content_path WHERE is_current AND content_id IS NOT NULL
            ORDER BY path
            """, String.class);
    }

    /** Registry spec ids only; the configured boot-spec is not one. */
    private static List<String> registryIds() {
        return specProvider.getSpecs().stream()
            .map(spec -> spec.getId())
            .filter(id -> id.startsWith("c"))
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
