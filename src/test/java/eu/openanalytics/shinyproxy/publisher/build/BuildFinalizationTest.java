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

import eu.openanalytics.shinyproxy.publisher.registry.VersionAllocator;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A build's success and its version, as one transaction (WORKPLAN-BUNDLES.md T6 step 5,
 * decision 4; the T6 Pass line: "no failed build produces a version, exactly one version per
 * success, no accidental activation"), and its race with the legacy direct-image endpoint
 * through the shared allocator.
 */
public class BuildFinalizationTest {

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static JdbcTemplate jdbc;
    private static final String DIGEST = "registry:5000/c@sha256:" + "c".repeat(64);
    private static final CoordinatorSettings MANY = new CoordinatorSettings(
        Duration.ofSeconds(60), Duration.ofSeconds(20), Duration.ofMinutes(20), 50);

    @BeforeAll
    public static void beforeAll() {
        POSTGRES.start();
        Flyway.configure()
            .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
            .schemas("skald").defaultSchema("skald").locations("classpath:db/migration")
            .load().migrate();
        jdbc = new JdbcTemplate(new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
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
        UUID c = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type) VALUES (?, 't', 'alice', 'shiny')", c);
        return c;
    }

    private static UUID validatedBundle(UUID c) {
        UUID b = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.bundle (id, content_id, created_by, state, upload_deadline,"
            + " finished_at, object_key, object_sha256, object_bytes, manifest_sha256,"
            + " inventory_files, inventory_bytes) VALUES (?, ?, 'alice', 'VALIDATED',"
            + " now() + interval '1 hour', now(), ?, ?, 10, ?, 1, 10)",
            b, c, "bundles/" + b, "a".repeat(64), "b".repeat(64));
        return b;
    }

    /** Admits, claims and builds an attempt of {@code c}; returns its lease, PUBLISHING. */
    private static Lease publishing(BuildCoordinator coordinator, UUID c) {
        new BuildAdmission(jdbc, new AdmissionLimits(100, 100)).request(c, "alice",
            "k-" + UUID.randomUUID(), new BuildAdmission.Inputs(validatedBundle(c), Map.of()));
        Lease lease = coordinator.claim("n-" + UUID.randomUUID()).orElseThrow().lease();
        coordinator.toPublishing(lease, DIGEST);
        coordinator.markLogComplete(lease, 42);
        return lease;
    }

    private static String state(UUID build) {
        return jdbc.queryForObject("SELECT state FROM skald.build WHERE id = ?", String.class, build);
    }

    private static int versions(UUID c) {
        return jdbc.queryForObject("SELECT count(*) FROM skald.content_version WHERE content_id = ?",
            Integer.class, c);
    }

    @Test
    public void aSuccessAllocatesTheNextVersionLinksItAndActivatesNothing() {
        UUID c = content();
        new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource())).execute(s ->
            new VersionAllocator(jdbc).allocate(c, "legacy-image", null, "admin", null));
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        Lease lease = publishing(coordinator, c);

        VersionAllocator.Allocated v = coordinator.succeed(lease, "{\"runtime\": \"r-4.4\"}");
        assertEquals(2, v.version());
        assertEquals("SUCCEEDED", state(lease.buildId()));
        Map<String, Object> row = jdbc.queryForMap("SELECT build_id, image, spec_json::text AS spec,"
            + " created_by FROM skald.content_version WHERE id = ?", v.id());
        assertEquals(lease.buildId(), row.get("build_id"));
        assertEquals(DIGEST, row.get("image"));
        assertEquals("alice", row.get("created_by"), "the version records who requested the build");
        assertTrue(String.valueOf(row.get("spec")).contains("r-4.4"));
        assertNull(jdbc.queryForObject("SELECT active_version_id FROM skald.content WHERE id = ?",
            UUID.class, c), "a success activated a version");
    }

    @Test
    public void aSuccessHappensExactlyOnce() {
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        Lease lease = publishing(coordinator, c);
        coordinator.succeed(lease, null);
        assertThrows(Fenced.class, () -> coordinator.succeed(lease, null));
        assertEquals(1, versions(c));
    }

    @Test
    public void noSuccessWithoutACompleteLog() {
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        new BuildAdmission(jdbc, new AdmissionLimits(100, 100)).request(c, "alice", "k",
            new BuildAdmission.Inputs(validatedBundle(c), Map.of()));
        Lease lease = coordinator.claim("n").orElseThrow().lease();
        coordinator.toPublishing(lease, DIGEST);
        assertThrows(Fenced.class, () -> coordinator.succeed(lease, null));
        assertEquals("PUBLISHING", state(lease.buildId()));
        assertEquals(0, versions(c));
    }

    @Test
    public void aFencedAttemptAllocatesNothing() {
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        Lease reaped = publishing(coordinator, c);
        jdbc.update("UPDATE skald.build SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
            reaped.buildId());
        coordinator.reap();
        assertThrows(Fenced.class, () -> coordinator.succeed(reaped, null), "success after reaping");
        assertEquals("INTERRUPTED", state(reaped.buildId()));

        Lease late = publishing(coordinator, c);
        jdbc.update("UPDATE skald.build SET deadline_at = now() - interval '1 second' WHERE id = ?",
            late.buildId());
        assertThrows(Fenced.class, () -> coordinator.succeed(late, null),
            "a success after the deadline; it must be TIMED_OUT, never a late SUCCEEDED");

        Lease wrong = publishing(coordinator, c);
        assertThrows(Fenced.class, () -> coordinator.succeed(
            new Lease(wrong.buildId(), wrong.generation() + 1, wrong.owner()), null));
        assertEquals(0, versions(c), "a failed or fenced attempt produced a version");
    }

    @Test
    public void aCrashInsideTheSuccessTransactionLeavesNoHalfVersion() {
        // The plan: "Crash after push but before the transaction leaves an orphan image, never a
        // half-version." The last write of the success transaction (its audit row) is made to
        // fail; the version insert and the state change before it must roll back with it.
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        Lease lease = publishing(coordinator, c);
        jdbc.execute("CREATE FUNCTION skald.crash_on_success() RETURNS trigger LANGUAGE plpgsql AS"
            + " $$ BEGIN IF NEW.action = 'build.succeeded' THEN RAISE EXCEPTION 'simulated crash'; END IF;"
            + " RETURN NEW; END $$");
        jdbc.execute("CREATE TRIGGER crash_on_success BEFORE INSERT ON skald.audit_event"
            + " FOR EACH ROW EXECUTE FUNCTION skald.crash_on_success()");
        try {
            assertThrows(RuntimeException.class, () -> coordinator.succeed(lease, null));
        } finally {
            jdbc.execute("DROP TRIGGER crash_on_success ON skald.audit_event");
            jdbc.execute("DROP FUNCTION skald.crash_on_success()");
        }
        assertEquals(0, versions(c), "a half-version survived the crash");
        assertEquals("PUBLISHING", state(lease.buildId()));
        // And it can still finish exactly once afterwards.
        assertEquals(1, coordinator.succeed(lease, null).version());
    }

    @Test
    public void aContentItemDeletedBeforeTheSuccessGetsNoVersion() {
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        Lease lease = publishing(coordinator, c);
        jdbc.update("DELETE FROM skald.content WHERE id = ?", c);
        assertThrows(Fenced.class, () -> coordinator.succeed(lease, null));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.content_version", Integer.class));
    }

    @Test
    public void versionNumbersFollowSuccessNotStart() throws Exception {
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        Lease first = publishing(coordinator, c);
        Thread.sleep(5);
        Lease second = publishing(coordinator, c);
        assertEquals(1, coordinator.succeed(second, null).version());
        assertEquals(2, coordinator.succeed(first, null).version());
    }

    @Test
    public void concurrentSuccessesAndLegacyAddsGetDistinctContiguousVersions() throws Exception {
        UUID c = content();
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        List<Lease> leases = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            leases.add(publishing(coordinator, c));
        }
        TransactionTemplate tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
        List<Callable<Integer>> jobs = new ArrayList<>();
        for (Lease lease : leases) {
            jobs.add(() -> coordinator.succeed(lease, null).version());
        }
        for (int i = 0; i < 8; i++) {
            jobs.add(() -> tx.execute(s -> new VersionAllocator(jdbc)
                .allocate(c, "legacy-image", null, "admin", null).orElseThrow().version()));
        }
        ExecutorService pool = Executors.newFixedThreadPool(jobs.size());
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> results = new ArrayList<>();
        for (Callable<Integer> job : jobs) {
            results.add(pool.submit(() -> {
                go.await();
                return job.call();
            }));
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        java.util.TreeSet<Integer> got = new java.util.TreeSet<>();
        for (Future<Integer> f : results) {
            got.add(f.get());
        }
        assertEquals(14, got.size(), "two allocations got one number");
        assertEquals(1, got.first());
        assertEquals(14, got.last());
        for (Lease lease : leases) {
            assertEquals("SUCCEEDED", state(lease.buildId()));
            assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM skald.content_version"
                + " WHERE build_id = ?", Integer.class, lease.buildId()));
        }
        // a00a190 review N3, the half the schema cannot hold: a version links only to a
        // SUCCEEDED build.
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.content_version v"
            + " JOIN skald.build b ON b.id = v.build_id WHERE b.state <> 'SUCCEEDED'", Integer.class));
    }
}
