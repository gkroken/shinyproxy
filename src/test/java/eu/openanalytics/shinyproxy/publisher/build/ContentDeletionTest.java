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
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Duration;
import java.util.Map;
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
 * Deleting a content item against its builds (WORKPLAN-BUNDLES.md T6, deletion paragraph):
 * refused while builds are unfinished, artifact cleanup enqueued in the deletion's own
 * transaction before the cascade, and admission fenced by the shared content-row lock.
 */
public class ContentDeletionTest {

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    private static JdbcTemplate jdbc;
    private static TransactionTemplate tx;
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
        tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
    }

    @AfterAll
    public static void afterAll() {
        POSTGRES.stop();
    }

    @BeforeEach
    public void clean() {
        jdbc.update("DELETE FROM skald.content");
        jdbc.update("DELETE FROM skald.artifact");
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

    private static UUID admit(UUID c) {
        return new BuildAdmission(jdbc, new AdmissionLimits(100, 100)).request(c, "alice",
            "k-" + UUID.randomUUID(), new BuildAdmission.Inputs(validatedBundle(c), Map.of())).buildId();
    }

    /** The deletion transaction as ContentAdminService runs it: the guard, then the delete. */
    private static boolean delete(UUID c) {
        return Boolean.TRUE.equals(tx.execute(s -> {
            if (!new ContentDeletionGuard(jdbc).prepare(c)) {
                return false;
            }
            jdbc.update("DELETE FROM skald.content WHERE id = ?", c);
            return true;
        }));
    }

    @Test
    public void deletionIsRefusedWhileAnyBuildIsUnfinished() {
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        UUID running = content();
        UUID r0 = admit(running);
        Lease r = coordinator.claim("n").orElseThrow().lease();
        assertEquals(r0, r.buildId());
        assertThrows(ContentDeletionGuard.BuildsInProgress.class, () -> delete(running), "RUNNING");

        UUID queued = content();
        admit(queued);
        assertThrows(ContentDeletionGuard.BuildsInProgress.class, () -> delete(queued), "QUEUED");

        coordinator.toPublishing(r, DIGEST);
        assertThrows(ContentDeletionGuard.BuildsInProgress.class, () -> delete(running), "PUBLISHING");
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM skald.content", Integer.class),
            "a refused deletion removed something");

        coordinator.fail(r, "X", "done");
        assertTrue(delete(running), "a content item with only finished builds could not be deleted");
        assertFalse(delete(UUID.randomUUID()));
    }

    @Test
    public void cleanupIsEnqueuedBeforeTheCascadeAndSurvivesIt() {
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        UUID c = content();
        UUID build = admit(c);
        Lease lease = coordinator.claim("n").orElseThrow().lease();
        coordinator.toPublishing(lease, DIGEST);
        // The image is in the ledger from the moment it exists, linked to its build.
        assertEquals("LIVE", jdbc.queryForObject("SELECT state FROM skald.artifact WHERE subject_build_id = ?",
            String.class, build));
        coordinator.fail(lease, "VERIFY_FAILED", "the pushed image did not verify");

        assertTrue(delete(c));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE id = ?", Integer.class, build));
        Map<String, Object> record = jdbc.queryForMap("SELECT state, delete_requested_at IS NOT NULL AS asked,"
            + " subject_content_id, subject_build_id FROM skald.artifact WHERE subject_build_id = ?", build);
        assertEquals("DELETE_PENDING", record.get("state"));
        assertEquals(Boolean.TRUE, record.get("asked"));
        assertEquals(c, record.get("subject_content_id"), "the record no longer says whose image it was");
        assertEquals(build, record.get("subject_build_id"));
    }

    @Test
    public void aPublishedImageIsPinnedToItsVersionAndAFencedOneIsNotRecorded() {
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        UUID c = content();
        admit(c);
        Lease lease = coordinator.claim("n").orElseThrow().lease();
        assertThrows(Fenced.class, () -> coordinator.toPublishing(
            new Lease(lease.buildId(), lease.generation() + 1, lease.owner()), DIGEST));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.artifact", Integer.class),
            "a fenced transition still recorded its image");
        coordinator.toPublishing(lease, DIGEST);
        coordinator.markLogComplete(lease, 1);
        UUID version = coordinator.succeed(lease, null).id();
        Map<String, Object> record = jdbc.queryForMap("SELECT pinned, subject_version_id FROM skald.artifact"
            + " WHERE subject_build_id = ?", lease.buildId());
        assertEquals(Boolean.TRUE, record.get("pinned"));
        assertEquals(version, record.get("subject_version_id"));
    }

    @Test
    public void aRetryWithTheSameDigestGetsItsOwnPinnedRecord() {
        // 6ae3868-F1, the reviewer's repro: attempt 1 publishes digest D and is interrupted;
        // the retry publishes the SAME D and succeeds. The ledger must hold one record per
        // attempt -- the successful one pinned to its version, the failed one its own,
        // unpinned -- or the live version's image looks like a failed build's.
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        UUID c = content();
        UUID first = admit(c);
        Lease one = coordinator.claim("n1").orElseThrow().lease();
        coordinator.toPublishing(one, DIGEST);
        jdbc.update("UPDATE skald.build SET lease_expires_at = now() - interval '1 second' WHERE id = ?", first);
        coordinator.reap();
        UUID second = admit(c);
        Lease two = coordinator.claim("n2").orElseThrow().lease();
        coordinator.toPublishing(two, DIGEST);
        coordinator.markLogComplete(two, 1);
        UUID version = coordinator.succeed(two, null).id();

        Map<String, Object> won = jdbc.queryForMap("SELECT ref, digest, pinned, subject_version_id"
            + " FROM skald.artifact WHERE subject_build_id = ?", second);
        assertEquals(Boolean.TRUE, won.get("pinned"));
        assertEquals(version, won.get("subject_version_id"));
        assertEquals("sha256:" + "c".repeat(64), won.get("digest"));
        assertEquals("registry:5000/c:build-" + second, won.get("ref"));
        Map<String, Object> lost = jdbc.queryForMap("SELECT pinned, subject_version_id"
            + " FROM skald.artifact WHERE subject_build_id = ?", first);
        assertEquals(Boolean.FALSE, lost.get("pinned"));
        assertEquals(null, lost.get("subject_version_id"));
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM skald.artifact WHERE digest = ?",
            Integer.class, "sha256:" + "c".repeat(64)));
    }

    @Test
    public void aSuccessWhoseImageTheLedgerDoesNotHoldIsRefused() {
        // Fail closed: a version whose image no record pins is one a collector could delete.
        BuildCoordinator coordinator = new BuildCoordinator(jdbc, MANY);
        UUID c = content();
        UUID build = admit(c);
        Lease lease = coordinator.claim("n").orElseThrow().lease();
        coordinator.toPublishing(lease, DIGEST);
        coordinator.markLogComplete(lease, 1);
        jdbc.update("DELETE FROM skald.artifact WHERE subject_build_id = ?", build);
        assertThrows(IllegalStateException.class, () -> coordinator.succeed(lease, null));
        assertEquals("PUBLISHING", jdbc.queryForObject("SELECT state FROM skald.build WHERE id = ?",
            String.class, build));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.content_version", Integer.class));
    }

    @Test
    public void anAdmissionWaitingOnADeletionIsRefusedCleanly() throws Exception {
        // 5c39c0b review N1: the content-row lock admission takes, proved. The deletion holds
        // the lock; an admission for the same item starts and must wait; the deletion commits;
        // the admission must then say CONTENT_NOT_FOUND -- not insert a build for a deleted item
        // and not die on a foreign-key error.
        UUID c = content();
        UUID bundle = validatedBundle(c);
        BuildAdmission admission = new BuildAdmission(jdbc, new AdmissionLimits(100, 100));
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch admissionStarted = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        Future<?> deletion = pool.submit(() -> tx.execute(s -> {
            new ContentDeletionGuard(jdbc).prepare(c);
            locked.countDown();
            try {
                assertTrue(admissionStarted.await(30, TimeUnit.SECONDS));
                Thread.sleep(500);       // the admission is now waiting on the content row
            } catch (InterruptedException ex) {
                throw new IllegalStateException(ex);
            }
            jdbc.update("DELETE FROM skald.content WHERE id = ?", c);
            return null;
        }));
        assertTrue(locked.await(30, TimeUnit.SECONDS));
        Future<Object> admitted = pool.submit(() -> {
            admissionStarted.countDown();
            try {
                return admission.request(c, "alice", "k1", new BuildAdmission.Inputs(bundle, Map.of()));
            } catch (AdmissionRefusal refused) {
                return refused.reason();
            }
        });
        deletion.get(60, TimeUnit.SECONDS);
        assertEquals(AdmissionRefusal.Reason.CONTENT_NOT_FOUND, admitted.get(60, TimeUnit.SECONDS));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.build", Integer.class));
        pool.shutdown();
    }
}
