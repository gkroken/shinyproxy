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

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The coordinator and runner against real PostgreSQL, with FAKE drivers (WORKPLAN-BUNDLES.md
 * T6: "Use a fake driver for deterministic crash/concurrency tests only here").
 *
 * <p>A crash is modelled the way it looks to the database: a claim with no further writes and
 * no renewals. Time passing is modelled by moving lease_expires_at or deadline_at into the
 * past, so no test waits a minute and none depends on scheduling luck -- except the two that
 * exercise the real heartbeat, which use a 2 s lease.
 */
public class BuildCoordinatorTest {

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static JdbcTemplate jdbc;
    private static final String DIGEST = "registry:5000/c@sha256:" + "c".repeat(64);
    private static final CoordinatorSettings ONE = CoordinatorSettings.DEFAULTS;

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

    /** A content item with a VALIDATED bundle, and an admitted (QUEUED) build of it. */
    private static UUID queued(String actor) {
        UUID c = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type) VALUES (?, 't', 'alice', 'shiny')", c);
        UUID b = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.bundle (id, content_id, created_by, state, upload_deadline,"
            + " finished_at, object_key, object_sha256, object_bytes, manifest_sha256,"
            + " inventory_files, inventory_bytes) VALUES (?, ?, 'alice', 'VALIDATED',"
            + " now() + interval '1 hour', now(), ?, ?, 10, ?, 1, 10)",
            b, c, "bundles/" + b, "a".repeat(64), "b".repeat(64));
        return new BuildAdmission(jdbc, new AdmissionLimits(100, 100))
            .request(c, actor, "k-" + UUID.randomUUID(), new BuildAdmission.Inputs(b, Map.of("r", "1")))
            .buildId();
    }

    private static String state(UUID build) {
        return jdbc.queryForObject("SELECT state FROM skald.build WHERE id = ?", String.class, build);
    }

    private static UUID contentOf(UUID build) {
        return jdbc.queryForObject("SELECT content_id FROM skald.build WHERE id = ?", UUID.class, build);
    }

    private static void expireLease(UUID build) {
        jdbc.update("UPDATE skald.build SET lease_expires_at = now() - interval '1 second' WHERE id = ?", build);
    }

    // ------------------------------------------------------------------ claim

    @Test
    public void aClaimTakesTheOldestQueuedAttemptAndLeasesIt() throws Exception {
        UUID first = queued("alice");
        Thread.sleep(5);
        UUID second = queued("bob");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        BuildDriver.Claimed claimed = coordinator.claim("node-1").orElseThrow();
        assertEquals(first, claimed.buildId());
        assertEquals(1, claimed.lease().generation());
        assertEquals("RUNNING", state(first));
        assertEquals("QUEUED", state(second));
        Map<String, Object> row = jdbc.queryForMap("SELECT lease_owner,"
            + " extract(epoch FROM lease_expires_at - now()) AS lease_left,"
            + " extract(epoch FROM deadline_at - now()) AS deadline_left, started_at FROM skald.build"
            + " WHERE id = ?", first);
        assertEquals("node-1", row.get("lease_owner"));
        double leaseLeft = ((Number) row.get("lease_left")).doubleValue();
        double deadlineLeft = ((Number) row.get("deadline_left")).doubleValue();
        assertTrue(leaseLeft > 50 && leaseLeft <= 60, "lease " + leaseLeft);
        assertTrue(deadlineLeft > 1190 && deadlineLeft <= 1200, "deadline " + deadlineLeft);
        assertEquals(Map.of("r", "1"), claimed.recipe());
    }

    @Test
    public void noMoreThanMaxRunningAttemptsRunAtOnce() {
        UUID a = queued("alice");
        queued("bob");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        Lease lease = coordinator.claim("node-1").orElseThrow().lease();
        assertTrue(coordinator.claim("node-2").isEmpty(), "a second attempt ran beside the first");
        coordinator.fail(lease, "STEP_FAILED", "x");
        assertEquals("FAILED", state(a));
        assertTrue(coordinator.claim("node-2").isPresent(), "the slot was not freed");
    }

    @Test
    public void concurrentClaimersNeverExceedTheRunningLimit() throws Exception {
        for (int i = 0; i < 6; i++) {
            queued("user" + i);
        }
        for (int limit : new int[] {1, 3}) {
            jdbc.update("UPDATE skald.build SET state = 'QUEUED', lease_owner = NULL,"
                + " lease_expires_at = NULL, started_at = NULL, deadline_at = NULL");
            BuildCoordinator coordinator = new BuildCoordinator(jdbc, new CoordinatorSettings(
                Duration.ofSeconds(60), Duration.ofSeconds(20), Duration.ofMinutes(20), limit));
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Optional<BuildDriver.Claimed>>> claims = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                String owner = "node-" + t;
                claims.add(pool.submit(() -> {
                    go.await();
                    return coordinator.claim(owner);
                }));
            }
            go.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
            int got = 0;
            for (Future<Optional<BuildDriver.Claimed>> f : claims) {
                got += f.get().isPresent() ? 1 : 0;
            }
            assertEquals(limit, got, "claims under a limit of " + limit);
            assertEquals(limit, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE state = 'RUNNING'",
                Integer.class));
        }
    }

    // ------------------------------------------------------------------ fencing

    @Test
    public void aWorkerWhoseLeaseWasReapedIsFencedEverywhere() {
        UUID build = queued("alice");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        Lease lease = coordinator.claim("node-1").orElseThrow().lease();
        expireLease(build);
        assertEquals(1, coordinator.reap());
        assertEquals("INTERRUPTED", state(build));

        assertFalse(coordinator.renew(lease));
        assertThrows(Fenced.class, () -> coordinator.toPublishing(lease, DIGEST));
        assertThrows(Fenced.class, () -> coordinator.fail(lease, "X", "late"));
        assertEquals("INTERRUPTED", state(build), "a stale worker changed a terminal attempt");
    }

    @Test
    public void anExpiredButUnreapedLeaseIsAlreadyFenced() {
        UUID build = queued("alice");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        Lease lease = coordinator.claim("node-1").orElseThrow().lease();
        expireLease(build);
        assertFalse(coordinator.renew(lease), "an expired lease was renewed back to life");
        assertThrows(Fenced.class, () -> coordinator.toPublishing(lease, DIGEST));
        assertEquals("RUNNING", state(build));
    }

    @Test
    public void theWrongGenerationOrOwnerIsFenced() {
        UUID build = queued("alice");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        Lease lease = coordinator.claim("node-1").orElseThrow().lease();
        assertThrows(Fenced.class, () -> coordinator.toPublishing(
            new Lease(build, lease.generation() + 1, "node-1"), DIGEST));
        assertThrows(Fenced.class, () -> coordinator.toPublishing(
            new Lease(build, lease.generation(), "node-2"), DIGEST));
        assertFalse(coordinator.renew(new Lease(build, lease.generation() - 1, "node-1")));
        coordinator.toPublishing(lease, DIGEST);
        assertEquals("PUBLISHING", state(build));
        assertThrows(Fenced.class, () -> coordinator.toPublishing(lease, DIGEST),
            "RUNNING -> PUBLISHING applied twice");
    }

    // ------------------------------------------------------------------ reap

    @Test
    public void reapingInterruptsExpiredLeasesTimesOutDeadlinesAndRetriesNothing() {
        UUID expired = queued("alice");
        UUID late = queued("bob");
        UUID healthy = queued("carol");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, new CoordinatorSettings(
            Duration.ofSeconds(60), Duration.ofSeconds(20), Duration.ofMinutes(20), 3));
        coordinator.claim("n1");
        coordinator.claim("n2");
        coordinator.claim("n3");
        expireLease(expired);
        jdbc.update("UPDATE skald.build SET deadline_at = now() - interval '1 second' WHERE id = ?", late);
        int builds = jdbc.queryForObject("SELECT count(*) FROM skald.build", Integer.class);

        assertEquals(2, coordinator.reap());
        assertEquals("INTERRUPTED", state(expired));
        assertEquals("LEASE_EXPIRED", jdbc.queryForObject(
            "SELECT error_code FROM skald.build WHERE id = ?", String.class, expired));
        assertEquals("TIMED_OUT", state(late));
        assertEquals("RUNNING", state(healthy));
        assertEquals(builds, jdbc.queryForObject("SELECT count(*) FROM skald.build", Integer.class),
            "reaping created a retry; retries are a user's new attempt (decision 4)");
        assertEquals(0, coordinator.reap(), "reaping is not idempotent");
    }

    // ------------------------------------------------------------------ cancel

    @Test
    public void cancellationFollowsTheMachineInEveryState() {
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, new CoordinatorSettings(
            Duration.ofSeconds(60), Duration.ofSeconds(20), Duration.ofMinutes(20), 3));
        UUID queuedBuild = queued("alice");
        assertEquals(BuildCoordinator.CancelOutcome.CANCELLED,
            coordinator.cancel(contentOf(queuedBuild), queuedBuild, "alice"));
        assertEquals("CANCELLED", state(queuedBuild));

        UUID running = queued("alice");
        Lease lease = coordinator.claim("n1").orElseThrow().lease();
        assertThrows(Fenced.class, () -> coordinator.confirmCancelled(lease),
            "a stop that nobody requested was recorded as a cancellation");
        assertFalse(coordinator.cancelRequested(lease));
        assertEquals(BuildCoordinator.CancelOutcome.REQUESTED,
            coordinator.cancel(contentOf(running), running, "alice"));
        assertEquals("RUNNING", state(running), "cancelled before the worker confirmed it stopped");
        assertTrue(coordinator.cancelRequested(lease));
        coordinator.confirmCancelled(lease);
        assertEquals("CANCELLED", state(running));

        UUID publishing = queued("alice");
        Lease p = coordinator.claim("n2").orElseThrow().lease();
        coordinator.toPublishing(p, DIGEST);
        assertEquals(BuildCoordinator.CancelOutcome.REFUSED_PUBLISHING,
            coordinator.cancel(contentOf(publishing), publishing, "alice"));
        assertEquals("PUBLISHING", state(publishing));

        assertEquals(BuildCoordinator.CancelOutcome.ALREADY_FINISHED,
            coordinator.cancel(contentOf(running), running, "alice"));
        assertEquals(BuildCoordinator.CancelOutcome.NOT_FOUND,
            coordinator.cancel(contentOf(queued("bob")), running, "bob"),
            "a build was cancelled through another content item");
    }

    // ------------------------------------------------------------------ the runner, with fake drivers

    @Test
    public void theRunnerWritesEachOutcomeOnce() {
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        BuildRunner runner = new BuildRunner(coordinator, ONE);
        assertEquals(BuildRunner.Result.IDLE, runner.runOnce("n1", (b, stop) -> {
            throw new AssertionError("ran with nothing queued");
        }));

        UUID built = queued("alice");
        assertEquals(BuildRunner.Result.PUBLISHING, runner.runOnce("n1", (b, stop) -> new BuildDriver.Built(DIGEST)));
        assertEquals("PUBLISHING", state(built));
        assertEquals(DIGEST, jdbc.queryForObject("SELECT output_image FROM skald.build WHERE id = ?", String.class, built));
        coordinator.fail(new Lease(built, 1, "n1"), "TEST_DONE", "free the slot");

        UUID failed = queued("alice");
        assertEquals(BuildRunner.Result.FAILED, runner.runOnce("n1",
            (b, stop) -> new BuildDriver.Failed("STEP_FAILED", "R CMD INSTALL")));
        assertEquals("STEP_FAILED", jdbc.queryForObject("SELECT error_code FROM skald.build WHERE id = ?", String.class, failed));

        UUID threw = queued("alice");
        assertEquals(BuildRunner.Result.FAILED, runner.runOnce("n1", (b, stop) -> {
            throw new IllegalStateException("driver bug");
        }));
        assertEquals("DRIVER_ERROR", jdbc.queryForObject("SELECT error_code FROM skald.build WHERE id = ?", String.class, threw));
    }

    @Test
    public void anInterruptedDriverWritesNothingAndTheInterruptStays() {
        // The process is stopping (BuildLoop.stop interrupts the loop's thread). The driver has
        // stopped its worker and rethrown; that is not a failure of the attempt, so nothing is
        // written, and the lease expires into INTERRUPTED through the reaper.
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        BuildRunner runner = new BuildRunner(coordinator, ONE);
        UUID build = queued("alice");
        try {
            assertEquals(BuildRunner.Result.INTERRUPTED, runner.runOnce("n1", (b, stop) -> {
                throw new InterruptedException("stopping");
            }));
            assertTrue(Thread.currentThread().isInterrupted(), "the interrupt is kept for the caller");
        } finally {
            Thread.interrupted();
        }
        assertEquals("RUNNING", state(build), "nothing written: no FAILED, no DRIVER_ERROR");
        assertEquals(null, jdbc.queryForObject("SELECT error_code FROM skald.build WHERE id = ?", String.class, build));
        coordinator.fail(new Lease(build, 1, "n1"), "TEST_DONE", "free the slot");
    }

    @Test
    public void aCancelDuringTheRunStopsTheWorkerThenCancels() throws Exception {
        // The cancel flag reaches the driver through the heartbeat's renewal (at most one
        // renew_every later), so a short renewal interval keeps this test short.
        CoordinatorSettings fast = new CoordinatorSettings(Duration.ofSeconds(2), Duration.ofSeconds(1),
            Duration.ofMinutes(20), 1);
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, fast);
        BuildRunner runner = new BuildRunner(coordinator, fast);
        UUID build = queued("alice");
        CountDownLatch running = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<BuildRunner.Result> result = pool.submit(() -> runner.runOnce("n1", (b, stop) -> {
            running.countDown();
            for (int i = 0; i < 300 && !stop.getAsBoolean(); i++) {
                Thread.sleep(100);
            }
            return stop.getAsBoolean() ? new BuildDriver.Stopped() : new BuildDriver.Built(DIGEST);
        }));
        assertTrue(running.await(30, TimeUnit.SECONDS));
        assertEquals(BuildCoordinator.CancelOutcome.REQUESTED, coordinator.cancel(contentOf(build), build, "alice"));
        assertEquals(BuildRunner.Result.CANCELLED, result.get(60, TimeUnit.SECONDS));
        assertEquals("CANCELLED", state(build));
        pool.shutdown();
    }

    @Test
    public void aWorkerThatLosesItsLeaseMidRunWritesNothing() throws Exception {
        // The real heartbeat, with a 2 s lease renewed every 1 s. Another coordinator's reaper
        // takes the attempt while the driver works; the next renewal fails, the driver is told
        // to stop, and what it then returns -- an image -- must not be written.
        CoordinatorSettings fast = new CoordinatorSettings(Duration.ofSeconds(2), Duration.ofSeconds(1),
            Duration.ofMinutes(20), 1);
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, fast);
        BuildRunner runner = new BuildRunner(coordinator, fast);
        UUID build = queued("alice");
        CountDownLatch running = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<BuildRunner.Result> result = pool.submit(() -> runner.runOnce("n1", (b, stop) -> {
            running.countDown();
            for (int i = 0; i < 300 && !stop.getAsBoolean(); i++) {
                Thread.sleep(100);
            }
            return new BuildDriver.Built(DIGEST);
        }));
        assertTrue(running.await(30, TimeUnit.SECONDS));
        expireLease(build);
        new BuildCoordinator(jdbc, fast).reap();
        assertEquals(BuildRunner.Result.FENCED, result.get(60, TimeUnit.SECONDS));
        assertEquals("INTERRUPTED", state(build));
        assertEquals(null, jdbc.queryForObject("SELECT output_image FROM skald.build WHERE id = ?", String.class, build));
        pool.shutdown();
    }

    @Test
    public void aHealthyLongBuildKeepsItsLeaseThroughTheHeartbeat() throws Exception {
        CoordinatorSettings fast = new CoordinatorSettings(Duration.ofSeconds(2), Duration.ofSeconds(1),
            Duration.ofMinutes(20), 1);
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, fast);
        UUID build = queued("alice");
        // Runs for 5 s, longer than two whole leases, with a reaper sweeping all along.
        ExecutorService reaper = Executors.newSingleThreadExecutor();
        Future<Integer> reaped = reaper.submit(() -> {
            int n = 0;
            for (int i = 0; i < 25; i++) {
                n += coordinator.reap();
                Thread.sleep(200);
            }
            return n;
        });
        BuildRunner.Result result = new BuildRunner(coordinator, fast).runOnce("n1", (b, stop) -> {
            Thread.sleep(5000);
            return new BuildDriver.Built(DIGEST);
        });
        assertEquals(BuildRunner.Result.PUBLISHING, result);
        assertEquals(0, reaped.get());
        assertEquals("PUBLISHING", state(build));
        reaper.shutdown();
    }

    /** A DataSource that refuses connections while {@code failing} is set: a database blip. */
    private static final class FlakyDataSource extends org.springframework.jdbc.datasource.DelegatingDataSource {
        volatile boolean failing;

        FlakyDataSource(javax.sql.DataSource target) {
            super(target);
        }

        @Override
        public java.sql.Connection getConnection() throws java.sql.SQLException {
            if (failing) {
                throw new java.sql.SQLException("simulated: the database is unreachable");
            }
            return super.getConnection();
        }
    }

    private static final CoordinatorSettings THREE_SECONDS = new CoordinatorSettings(
        Duration.ofSeconds(3), Duration.ofSeconds(1), Duration.ofMinutes(20), 1);

    @Test
    public void aRenewalThatThrowsOnceDoesNotKillTheHeartbeat() throws Exception {
        // 071ef50-F1, the transient half: one renewal fails with a database error (not a
        // refusal). The heartbeat must survive it, renew on the next tick, and the build finish.
        FlakyDataSource flaky = new FlakyDataSource(jdbc.getDataSource());
        BuildCoordinator coordinator = new BuildCoordinator(new JdbcTemplate(flaky), THREE_SECONDS);
        UUID build = queued("alice");
        java.util.concurrent.atomic.AtomicBoolean sawStop = new java.util.concurrent.atomic.AtomicBoolean();
        ExecutorService blip = Executors.newSingleThreadExecutor();
        blip.submit(() -> {
            Thread.sleep(700);
            flaky.failing = true;      // covers the renewal at ~1 s
            Thread.sleep(700);
            flaky.failing = false;
            return null;
        });
        BuildRunner.Result result = new BuildRunner(coordinator, THREE_SECONDS).runOnce("n1", (b, stop) -> {
            for (int i = 0; i < 50; i++) {
                if (stop.getAsBoolean()) {
                    sawStop.set(true);
                    return new BuildDriver.Stopped();
                }
                Thread.sleep(100);
            }
            return new BuildDriver.Built(DIGEST);
        });
        assertFalse(sawStop.get(), "one failed renewal stopped a healthy build");
        assertEquals(BuildRunner.Result.PUBLISHING, result);
        assertEquals("PUBLISHING", state(build));
        blip.shutdown();
    }

    @Test
    public void aWorkerThatCannotRenewIsStoppedBeforeItsLeaseCouldExpire() throws Exception {
        // 071ef50-F1, the reviewer's shape: the runner's database goes away for good just after
        // the claim. Its renewals all THROW. The driver must be told to stop before the lease
        // could expire -- otherwise a healthy coordinator reaps it, claims the next build, and
        // two workers run under max_running = 1 while the first still runs untrusted code.
        FlakyDataSource flaky = new FlakyDataSource(jdbc.getDataSource());
        BuildCoordinator runnersView = new BuildCoordinator(new JdbcTemplate(flaky), THREE_SECONDS);
        UUID build = queued("alice");
        queued("bob");
        long[] stoppedAfterMs = {-1};
        long start = System.nanoTime();
        ExecutorService outage = Executors.newSingleThreadExecutor();
        outage.submit(() -> {
            Thread.sleep(500);
            flaky.failing = true;
            return null;
        });
        BuildRunner.Result result = new BuildRunner(runnersView, THREE_SECONDS).runOnce("n1", (b, stop) -> {
            for (int i = 0; i < 100; i++) {
                if (stop.getAsBoolean()) {
                    stoppedAfterMs[0] = (System.nanoTime() - start) / 1_000_000;
                    return new BuildDriver.Built(DIGEST);
                }
                Thread.sleep(50);
            }
            return new BuildDriver.Built(DIGEST);
        });
        assertEquals(BuildRunner.Result.FENCED, result);
        assertTrue(stoppedAfterMs[0] >= 0, "the driver was never told to stop");
        assertTrue(stoppedAfterMs[0] < 2900, "told to stop only after " + stoppedAfterMs[0]
            + " ms, when the 3 s lease could already have been reaped");
        // The rest of the world, on a healthy connection, reaps it once the lease expires.
        Thread.sleep(Math.max(0, 3200 - (System.nanoTime() - start) / 1_000_000));
        BuildCoordinator healthy = new BuildCoordinator(jdbc, THREE_SECONDS);
        healthy.reap();
        assertEquals("INTERRUPTED", state(build));
        assertTrue(healthy.claim("n2").isPresent());
        outage.shutdown();
    }

    /** A DataSource whose connections, while {@code hanging}, take six seconds to arrive. */
    private static final class HangingDataSource extends org.springframework.jdbc.datasource.DelegatingDataSource {
        volatile boolean hanging;

        HangingDataSource(javax.sql.DataSource target) {
            super(target);
        }

        @Override
        public java.sql.Connection getConnection() throws java.sql.SQLException {
            if (hanging) {
                try {
                    Thread.sleep(6000);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
            return super.getConnection();
        }
    }

    @Test
    public void aWorkerWhoseRenewalHangsIsStoppedBeforeItsLeaseCouldExpire() throws Exception {
        // 071ef50-F1 in its hanging form (59f1bc3 review): a renewal that neither returns nor
        // throws -- a connection that takes 6 s to arrive -- must not delay the stop signal.
        // Lease 3 s, renew 1 s: the driver has to hear "stop" before 3 s, while renew() is
        // still stuck.
        HangingDataSource hanging = new HangingDataSource(jdbc.getDataSource());
        BuildCoordinator runnersView = new BuildCoordinator(new JdbcTemplate(hanging), THREE_SECONDS);
        UUID build = queued("alice");
        long[] stoppedAfterMs = {-1};
        long start = System.nanoTime();
        ExecutorService window = Executors.newSingleThreadExecutor();
        window.submit(() -> {
            Thread.sleep(700);
            hanging.hanging = true;     // the ~1 s renewal waits 6 s for its connection
            Thread.sleep(900);
            hanging.hanging = false;
            return null;
        });
        BuildRunner.Result result = new BuildRunner(runnersView, THREE_SECONDS).runOnce("n1", (b, stop) -> {
            for (int i = 0; i < 200; i++) {
                if (stop.getAsBoolean()) {
                    stoppedAfterMs[0] = (System.nanoTime() - start) / 1_000_000;
                    return new BuildDriver.Built(DIGEST);
                }
                Thread.sleep(50);
            }
            return new BuildDriver.Built(DIGEST);
        });
        assertTrue(stoppedAfterMs[0] >= 0, "the driver was never told to stop");
        assertTrue(stoppedAfterMs[0] < 2900, "told to stop only after " + stoppedAfterMs[0]
            + " ms, past the point where the 3 s lease could be reaped");
        assertEquals(BuildRunner.Result.FENCED, result);
        assertEquals(null, jdbc.queryForObject("SELECT output_image FROM skald.build WHERE id = ?",
            String.class, build));
        window.shutdown();
    }

    @Test
    public void aPassedDeadlineStopsTheWorkerThroughItsOwnHeartbeat() throws Exception {
        // 071ef50 review N2: past deadline_at the lease is not renewed, so the worker stops
        // without any reaper running.
        CoordinatorSettings fast = new CoordinatorSettings(Duration.ofSeconds(2), Duration.ofSeconds(1),
            Duration.ofMinutes(20), 1);
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, fast);
        UUID build = queued("alice");
        CountDownLatch running = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<BuildRunner.Result> result = pool.submit(() -> new BuildRunner(coordinator, fast).runOnce("n1",
            (b, stop) -> {
                running.countDown();
                for (int i = 0; i < 300 && !stop.getAsBoolean(); i++) {
                    Thread.sleep(100);
                }
                return new BuildDriver.Built(DIGEST);
            }));
        assertTrue(running.await(30, TimeUnit.SECONDS));
        jdbc.update("UPDATE skald.build SET deadline_at = now() - interval '1 second' WHERE id = ?", build);
        assertEquals(BuildRunner.Result.FENCED, result.get(10, TimeUnit.SECONDS));
        assertEquals("RUNNING", state(build), "nothing but the reaper may end it");
        coordinator.reap();
        assertEquals("TIMED_OUT", state(build));
        pool.shutdown();
    }

    @Test
    public void noWorkerTransitionIsAcceptedPastTheDeadline() {
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        UUID build = queued("alice");
        Lease lease = coordinator.claim("n1").orElseThrow().lease();
        jdbc.update("UPDATE skald.build SET deadline_at = now() - interval '1 second',"
            + " cancel_requested_at = now() WHERE id = ?", build);
        assertFalse(coordinator.renew(lease));
        assertThrows(Fenced.class, () -> coordinator.toPublishing(lease, DIGEST), "a late success");
        assertThrows(Fenced.class, () -> coordinator.fail(lease, "X", "late"));
        assertThrows(Fenced.class, () -> coordinator.confirmCancelled(lease));
        assertEquals("RUNNING", state(build));
    }

    private static void awaitState(UUID build, String expected, long millis) throws InterruptedException {
        long until = System.currentTimeMillis() + millis;
        while (!expected.equals(state(build)) && System.currentTimeMillis() < until) {
            Thread.sleep(50);
        }
        assertEquals(expected, state(build));
    }

    @Test
    public void aStuckBuildTimesOutWithNobodyCallingReap() throws Exception {
        // 071ef50 review N1: the timer, not a test, settles a passed deadline.
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        UUID build = queued("alice");
        coordinator.claim("n1");
        BuildReaper reaper = new BuildReaper(coordinator, Duration.ofMillis(200));
        reaper.start();
        try {
            jdbc.update("UPDATE skald.build SET deadline_at = now() - interval '1 second' WHERE id = ?", build);
            awaitState(build, "TIMED_OUT", 5000);
            assertEquals(1, reaper.reaped());
        } finally {
            reaper.stop();
        }
    }

    @Test
    public void theReaperOutlivesReapsThatFail() throws Exception {
        // A reaper whose reaps throw (the database is unreachable at first) must keep its
        // timer: a scheduled task that throws is never run again (the 071ef50-F1 lesson), and
        // a silently stopped reaper holds every later lost worker's slot forever.
        FlakyDataSource flaky = new FlakyDataSource(jdbc.getDataSource());
        BuildCoordinator coordinator = new BuildCoordinator(new JdbcTemplate(flaky), ONE);
        UUID build = queued("alice");
        new BuildCoordinator(jdbc, ONE).claim("n1");
        flaky.failing = true;
        BuildReaper reaper = new BuildReaper(coordinator, Duration.ofMillis(100));
        reaper.start();
        try {
            Thread.sleep(600);
            assertTrue(reaper.failures() > 0, "the outage was not even seen");
            flaky.failing = false;
            expireLease(build);
            awaitState(build, "INTERRUPTED", 5000);
        } finally {
            reaper.stop();
        }
    }

    @Test
    public void aDriverReturningATagInsteadOfADigestFailsTheAttempt() {
        // 25d3a98 review N1: a driver bug becomes the attempt's FAILED, not an exception that
        // leaves it RUNNING until reaped.
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        UUID build = queued("alice");
        assertEquals(BuildRunner.Result.FAILED, new BuildRunner(coordinator, ONE).runOnce("n1",
            (b, stop) -> new BuildDriver.Built("registry:5000/c:latest")));
        assertEquals("FAILED", state(build));
        assertEquals("DRIVER_ERROR", jdbc.queryForObject("SELECT error_code FROM skald.build WHERE id = ?",
            String.class, build));
    }

    @Test
    public void aCrashedWorkerIsReapedAndTheQueueMovesOn() {
        // The crash, as the database sees it: a claim, then silence.
        UUID dead = queued("alice");
        UUID next = queued("bob");
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, ONE);
        coordinator.claim("node-that-died");
        assertTrue(coordinator.claim("node-2").isEmpty(), "the running slot is still held");
        expireLease(dead);
        coordinator.reap();
        assertEquals("INTERRUPTED", state(dead));
        assertEquals(next, coordinator.claim("node-2").orElseThrow().buildId());
    }

    @Test
    public void aSupersededAttemptWasNeverStarted() throws Exception {
        // Admission superseding the queued attempt races a coordinator claiming it. Whichever
        // wins, a CANCELLED-by-supersede attempt must never have been RUNNING.
        BuildAdmission admission = new BuildAdmission(jdbc, new AdmissionLimits(100, 100));
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, new CoordinatorSettings(
            Duration.ofSeconds(60), Duration.ofSeconds(20), Duration.ofMinutes(20), 100));
        for (int round = 0; round < 20; round++) {
            UUID first = queued("alice");
            UUID content = contentOf(first);
            UUID bundle = jdbc.queryForObject("SELECT bundle_id FROM skald.build WHERE id = ?", UUID.class, first);
            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch go = new CountDownLatch(1);
            Future<?> a = pool.submit(() -> {
                go.await();
                return admission.request(content, "alice", "again-" + UUID.randomUUID(),
                    new BuildAdmission.Inputs(bundle, Map.of("r", "1")));
            });
            Future<?> c = pool.submit(() -> {
                go.await();
                return coordinator.claim("n");
            });
            go.countDown();
            a.get(30, TimeUnit.SECONDS);
            c.get(30, TimeUnit.SECONDS);
            pool.shutdown();
        }
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.build"
            + " WHERE superseded_by IS NOT NULL AND (started_at IS NOT NULL OR lease_generation > 0)",
            Integer.class));
        // Which side wins each round is up to the scheduler, and either order is legal, so no
        // assertion here demands a particular mix. (A "the race happened" count was removed:
        // every round ends in a supersede or a claim, so it could not fail.)
    }

    @Test
    public void coordinatorSettingsAreValidated() {
        assertEquals(CoordinatorSettings.DEFAULTS, CoordinatorSettings.fromOverrides(Map.of()));
        assertEquals(Duration.ofSeconds(30), CoordinatorSettings.fromOverrides(
            Map.of("lease-seconds", "30", "renew_every_seconds", "10")).lease());
        assertThrows(IllegalArgumentException.class,
            () -> CoordinatorSettings.fromOverrides(Map.of("renew_every_seconds", "40")),
            "renewal slower than half the lease");
        assertThrows(IllegalArgumentException.class,
            () -> CoordinatorSettings.fromOverrides(Map.of("max_running", "0")));
        assertThrows(IllegalArgumentException.class,
            () -> CoordinatorSettings.fromOverrides(Map.of("lease_secs", "30")), "a typo");
    }
}
