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
package eu.openanalytics.shinyproxy.publisher.build;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Admission against real PostgreSQL with V1+V2 applied (WORKPLAN-BUNDLES.md T6 part 2).
 *
 * <p>The sequential cases pin each rule; the concurrent ones are the reason admission is a
 * locked transaction rather than a few queries: a check-then-insert that is right in every
 * single-threaded test can still queue two builds or overfill the queue under load.
 */
public class BuildAdmissionTest {

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static JdbcTemplate jdbc;

    @BeforeAll
    public static void beforeAll() {
        POSTGRES.start();
        Flyway.configure()
            .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
            .schemas("skald").defaultSchema("skald").locations("classpath:db/migration")
            .load().migrate();
        DriverManagerDataSource source = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbc = new JdbcTemplate(source);
    }

    @AfterAll
    public static void afterAll() {
        POSTGRES.stop();
    }

    @BeforeEach
    public void clean() {
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.audit_event");
    }

    private static UUID content() {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type) VALUES (?, 't', 'alice', 'shiny')", id);
        return id;
    }

    private static UUID bundle(UUID content, String state) {
        UUID id = UUID.randomUUID();
        boolean done = state.equals("VALIDATED") || state.equals("REJECTED");
        jdbc.update("INSERT INTO skald.bundle (id, content_id, created_by, state, upload_deadline,"
            + " finished_at, object_key, object_sha256, object_bytes, manifest_sha256,"
            + " inventory_files, inventory_bytes, rejection_rule) VALUES (?, ?, 'alice', ?,"
            + " now() + interval '1 hour', CASE WHEN ? THEN now() END, ?, ?, 10, ?, 1, 10,"
            + " CASE WHEN ? = 'REJECTED' THEN 'MANIFEST_MISSING' END)",
            id, content, state, done, "bundles/" + id, "a".repeat(64), "b".repeat(64), state);
        return id;
    }

    private static BuildAdmission admission(int queue, int perPublisher) {
        return new BuildAdmission(jdbc, new AdmissionLimits(queue, perPublisher));
    }

    private static BuildAdmission.Inputs inputs(UUID bundle) {
        return new BuildAdmission.Inputs(bundle, Map.of("recipe", "r-shiny-renv"));
    }

    private static String state(UUID build) {
        return jdbc.queryForObject("SELECT state FROM skald.build WHERE id = ?", String.class, build);
    }

    private static AdmissionRefusal.Reason refusal(Runnable call) {
        return assertThrows(AdmissionRefusal.class, call::run).reason();
    }

    // ------------------------------------------------------------------ idempotency

    @Test
    public void aRetriedRequestReturnsTheSameAttempt() {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(10, 3);
        BuildAdmission.Admitted first = admit.request(c, "alice", "k1", inputs(b));
        BuildAdmission.Admitted again = admit.request(c, "alice", "k1",
            new BuildAdmission.Inputs(b, Map.of("recipe", "r-shiny-renv")));
        assertTrue(first.created());
        assertFalse(again.created());
        assertEquals(first.buildId(), again.buildId());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM skald.build", Integer.class));
    }

    @Test
    public void theSameKeyForDifferentInputsIsRefused() {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        UUID b2 = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(10, 3);
        admit.request(c, "alice", "k1", inputs(b));
        assertEquals(AdmissionRefusal.Reason.KEY_REUSED_WITH_DIFFERENT_INPUTS,
            refusal(() -> admit.request(c, "alice", "k1", inputs(b2))));
        assertEquals(AdmissionRefusal.Reason.KEY_REUSED_WITH_DIFFERENT_INPUTS,
            refusal(() -> admit.request(c, "alice", "k1",
                new BuildAdmission.Inputs(b, Map.of("recipe", "something-else")))));
    }

    @Test
    public void aRetryIsAnsweredEvenWhenTheLimitsWouldNowRefuse() {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(1, 1);
        BuildAdmission.Admitted first = admit.request(c, "alice", "k1", inputs(b));
        UUID other = content();
        assertEquals(AdmissionRefusal.Reason.PUBLISHER_LIMIT,
            refusal(() -> admit.request(other, "alice", "k2", inputs(bundle(other, "VALIDATED")))));
        // The retry arrives once the attempt is RUNNING: the publisher is at the limit and
        // nothing of hers is QUEUED to free a slot, so only checking the key FIRST answers it.
        // (While the attempt was still QUEUED, the supersede credit let a retry through even
        // with the key checked last -- a mutant moving the check survived that version.)
        jdbc.update("UPDATE skald.build SET state = 'RUNNING', lease_owner = 'n',"
            + " lease_expires_at = now() + interval '1 minute', lease_generation = 1 WHERE id = ?",
            first.buildId());
        assertEquals(first.buildId(), admit.request(c, "alice", "k1", inputs(b)).buildId());
    }

    @Test
    public void aMalformedKeyIsRefusedBeforeTheDatabase() {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(10, 3);
        for (String key : new String[] {null, "", "has space", "x".repeat(201), "\u00e9"}) {
            assertEquals(AdmissionRefusal.Reason.KEY_INVALID,
                refusal(() -> admit.request(c, "alice", key, inputs(b))), String.valueOf(key));
        }
    }

    // ------------------------------------------------------------------ the bundle

    @Test
    public void onlyAValidatedBundleOfThisContentItemIsBuilt() {
        UUID c = content();
        UUID other = content();
        BuildAdmission admit = admission(10, 3);
        assertEquals(AdmissionRefusal.Reason.BUNDLE_NOT_FOUND,
            refusal(() -> admit.request(c, "alice", "k1", inputs(bundle(other, "VALIDATED")))));
        assertEquals(AdmissionRefusal.Reason.BUNDLE_NOT_FOUND,
            refusal(() -> admit.request(c, "alice", "k2", inputs(UUID.randomUUID()))));
        for (String state : new String[] {"UPLOADING", "VALIDATING", "REJECTED"}) {
            assertEquals(AdmissionRefusal.Reason.BUNDLE_NOT_VALIDATED,
                refusal(() -> admit.request(c, "alice", "k-" + state, inputs(bundle(c, state)))), state);
        }
        assertEquals(AdmissionRefusal.Reason.CONTENT_NOT_FOUND,
            refusal(() -> admit.request(UUID.randomUUID(), "alice", "k3", inputs(bundle(c, "VALIDATED")))));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.build", Integer.class));
    }

    // ------------------------------------------------------------------ supersede

    @Test
    public void aNewRequestSupersedesTheQueuedOneButNotARunningOne() {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(10, 3);
        UUID first = admit.request(c, "alice", "k1", inputs(b)).buildId();
        BuildAdmission.Admitted second = admit.request(c, "alice", "k2", inputs(b));
        assertEquals(first, second.superseded());
        assertEquals("CANCELLED", state(first));
        assertEquals(second.buildId(), jdbc.queryForObject(
            "SELECT superseded_by FROM skald.build WHERE id = ?", UUID.class, first));
        assertEquals("QUEUED", state(second.buildId()));

        // A RUNNING attempt is left alone; the new request simply queues.
        jdbc.update("UPDATE skald.build SET state = 'RUNNING', lease_owner = 'n',"
            + " lease_expires_at = now() + interval '1 minute', lease_generation = 1 WHERE id = ?",
            second.buildId());
        BuildAdmission.Admitted third = admit.request(c, "alice", "k3", inputs(b));
        assertNull(third.superseded());
        assertEquals("RUNNING", state(second.buildId()));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM skald.audit_event"
            + " WHERE action = 'build.superseded'", Integer.class));
    }

    // ------------------------------------------------------------------ limits

    @Test
    public void thePublisherLimitCountsUnfinishedBuildsAndFreesTheOneBeingSuperseded() {
        BuildAdmission admit = admission(10, 2);
        UUID a = content();
        UUID b = content();
        UUID c = content();
        admit.request(a, "alice", "k1", inputs(bundle(a, "VALIDATED")));
        admit.request(b, "alice", "k2", inputs(bundle(b, "VALIDATED")));
        assertEquals(AdmissionRefusal.Reason.PUBLISHER_LIMIT,
            refusal(() -> admit.request(c, "alice", "k3", inputs(bundle(c, "VALIDATED")))));
        // Superseding her OWN queued build on a does not grow her count.
        admit.request(a, "alice", "k4", inputs(bundle(a, "VALIDATED")));
        // Another publisher is counted separately.
        admit.request(c, "bob", "k5", inputs(bundle(c, "VALIDATED")));
    }

    @Test
    public void theSupersedeCreditIsOnlyForTheSupersedersOwnBuild() {
        // 5c39c0b-F1: bob, at his limit, must not get alice's queued build as HIS credit by
        // superseding it -- or he holds limit+1 unfinished builds, one more per shared item.
        BuildAdmission admit = admission(10, 1);
        UUID shared = content();
        UUID bobs = content();
        UUID alices = admit.request(shared, "alice", "a1", inputs(bundle(shared, "VALIDATED"))).buildId();
        admit.request(bobs, "bob", "b1", inputs(bundle(bobs, "VALIDATED")));
        assertEquals(AdmissionRefusal.Reason.PUBLISHER_LIMIT,
            refusal(() -> admit.request(shared, "bob", "b2", inputs(bundle(shared, "VALIDATED")))));
        assertEquals("QUEUED", state(alices), "the refused request still superseded alice's build");
        assertNull(jdbc.queryForObject("SELECT superseded_by FROM skald.build WHERE id = ?",
            UUID.class, alices));
        // The control: alice, in the same position, supersedes her own.
        BuildAdmission.Admitted hers = admit.request(shared, "alice", "a2",
            inputs(bundle(shared, "VALIDATED")));
        assertEquals(alices, hers.superseded());
    }

    @Test
    public void theQueueCapacityIsGlobalAndASupersedeDoesNotConsumeIt() {
        BuildAdmission admit = admission(2, 10);
        UUID a = content();
        UUID b = content();
        UUID c = content();
        admit.request(a, "alice", "k1", inputs(bundle(a, "VALIDATED")));
        admit.request(b, "bob", "k2", inputs(bundle(b, "VALIDATED")));
        assertEquals(AdmissionRefusal.Reason.QUEUE_FULL,
            refusal(() -> admit.request(c, "carol", "k3", inputs(bundle(c, "VALIDATED")))));
        admit.request(a, "alice", "k4", inputs(bundle(a, "VALIDATED")));
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE state = 'QUEUED'",
            Integer.class));
    }

    @Test
    public void limitsAreConfiguredStrictlyAndNeverRemoved() {
        assertEquals(new AdmissionLimits(20, 5),
            AdmissionLimits.fromOverrides(Map.of("queue-capacity", "20", "per_publisher_active", "5")));
        assertEquals(AdmissionLimits.DEFAULTS, AdmissionLimits.fromOverrides(Map.of()));
        assertThrows(IllegalArgumentException.class,
            () -> AdmissionLimits.fromOverrides(Map.of("queue_capacty", "20")), "a typo");
        assertThrows(IllegalArgumentException.class,
            () -> AdmissionLimits.fromOverrides(Map.of("queue_capacity", "0")), "removed");
        assertThrows(IllegalArgumentException.class,
            () -> AdmissionLimits.fromOverrides(Map.of("per_publisher_active", "-1")));
        assertThrows(IllegalArgumentException.class,
            () -> AdmissionLimits.fromOverrides(Map.of("queue_capacity", "lots")));
    }

    // ------------------------------------------------------------------ concurrency

    private static <T> List<Future<T>> race(int threads, java.util.function.IntFunction<Callable<T>> job)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<T>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Callable<T> call = job.apply(i);
            futures.add(pool.submit(() -> {
                start.await();
                return call.call();
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(120, java.util.concurrent.TimeUnit.SECONDS));
        return futures;
    }

    @Test
    public void concurrentRequestsForOneContentItemLeaveExactlyOneQueued() throws Exception {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(100, 100);
        List<Future<BuildAdmission.Admitted>> results =
            race(16, i -> () -> admit.request(c, "user" + i, "k" + i, inputs(b)));
        for (Future<BuildAdmission.Admitted> f : results) {
            assertTrue(f.get().created(), "every distinct request is admitted, none crashes");
        }
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE content_id = ?"
            + " AND state = 'QUEUED'", Integer.class, c));
        assertEquals(15, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE content_id = ?"
            + " AND state = 'CANCELLED' AND superseded_by IS NOT NULL", Integer.class, c));
    }

    @Test
    public void concurrentRequestsNeverOverfillTheQueue() throws Exception {
        BuildAdmission admit = admission(5, 100);
        List<UUID[]> items = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            UUID c = content();
            items.add(new UUID[] {c, bundle(c, "VALIDATED")});
        }
        List<Future<Object>> results = race(16, i -> () -> {
            try {
                return admit.request(items.get(i)[0], "user" + i, "k", inputs(items.get(i)[1]));
            } catch (AdmissionRefusal refused) {
                return refused.reason();
            }
        });
        int admitted = 0;
        int full = 0;
        for (Future<Object> f : results) {
            Object r = f.get();
            if (r instanceof BuildAdmission.Admitted) {
                admitted++;
            } else {
                assertEquals(AdmissionRefusal.Reason.QUEUE_FULL, r);
                full++;
            }
        }
        assertEquals(5, admitted);
        assertEquals(11, full);
        assertEquals(5, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE state = 'QUEUED'",
            Integer.class));
    }

    @Test
    public void concurrentRetriesOfOneRequestMakeOneAttempt() throws Exception {
        UUID c = content();
        UUID b = bundle(c, "VALIDATED");
        BuildAdmission admit = admission(10, 3);
        Set<UUID> ids = ConcurrentHashMap.newKeySet();
        for (Future<BuildAdmission.Admitted> f : race(8, i -> () -> admit.request(c, "alice", "same", inputs(b)))) {
            ids.add(f.get().buildId());
        }
        assertEquals(1, ids.size());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM skald.build", Integer.class));
    }

    @Test
    public void theFingerprintIgnoresKeyOrderAndNothingElse() {
        BuildAdmission admit = admission(10, 3);
        UUID b = UUID.randomUUID();
        java.util.LinkedHashMap<String, String> ab = new java.util.LinkedHashMap<>();
        ab.put("a", "1");
        ab.put("b", "2");
        java.util.LinkedHashMap<String, String> ba = new java.util.LinkedHashMap<>();
        ba.put("b", "2");
        ba.put("a", "1");
        assertEquals(admit.fingerprint(new BuildAdmission.Inputs(b, ab)),
            admit.fingerprint(new BuildAdmission.Inputs(b, ba)));
        assertNotEquals(admit.fingerprint(new BuildAdmission.Inputs(b, ab)),
            admit.fingerprint(new BuildAdmission.Inputs(UUID.randomUUID(), ab)));
        assertNotEquals(admit.fingerprint(new BuildAdmission.Inputs(b, ab)),
            admit.fingerprint(new BuildAdmission.Inputs(b, Map.of("a", "1", "b", "3"))));
    }
}
