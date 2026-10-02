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
package eu.openanalytics.shinyproxy.publisher.db;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V2 against a FRESH database and against a POPULATED V1 one (WORKPLAN-BUNDLES.md T6).
 *
 * <p>Every test gets its own database in one PostgreSQL container, so a migration is always
 * applied to exactly the state the test built. The populated case is the one that matters:
 * a real deployment arrives at V2 with content, paths, versions and audit rows, and none of
 * them may change -- not a row, not an id, not V1's recorded checksum.
 *
 * <p>The constraint tests are the schema's half of the T6 contract: each one shows a row the
 * database refuses, because a rule held only in Java holds only for the code that remembers
 * it.
 */
public class MigrationV2Test {

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:16").withDatabaseName("skald");

    @BeforeAll
    public static void beforeAll() {
        POSTGRES.start();
    }

    @AfterAll
    public static void afterAll() {
        POSTGRES.stop();
    }

    /** A new, empty database, migrated to {@code target} ("1", or null for the latest). */
    private static JdbcTemplate database(String target) {
        String name = "t" + UUID.randomUUID().toString().replace("-", "");
        new JdbcTemplate(source(POSTGRES.getJdbcUrl())).execute("CREATE DATABASE " + name);
        String url = POSTGRES.getJdbcUrl().replace("/skald", "/" + name);
        migrate(url, target);
        return new JdbcTemplate(source(url));
    }

    private static DriverManagerDataSource source(String url) {
        return new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static void migrate(String url, String target) {
        var config = Flyway.configure()
            .dataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword())
            .schemas("skald").defaultSchema("skald")
            .locations("classpath:db/migration");
        if (target != null) {
            config = config.target(target);
        }
        config.load().migrate();
    }

    private static String urlOf(JdbcTemplate jdbc) {
        try (var c = jdbc.getDataSource().getConnection()) {
            return c.getMetaData().getURL();
        } catch (java.sql.SQLException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** Every row of {@code table}, with bytea values as hex so rows compare by content. */
    private static List<Map<String, Object>> rows(JdbcTemplate jdbc, String table) {
        List<Map<String, Object>> rows = jdbc.queryForList("SELECT * FROM skald." + table + " ORDER BY id");
        for (Map<String, Object> row : rows) {
            row.replaceAll((column, value) -> value instanceof byte[] bytes
                ? java.util.HexFormat.of().formatHex(bytes) : value);
        }
        return rows;
    }

    // ------------------------------------------------------------------ fresh and populated

    @Test
    public void aFreshDatabaseMigratesStraightToV2() {
        JdbcTemplate jdbc = database(null);
        assertEquals(List.of("1", "2"), jdbc.queryForList(
            "SELECT version FROM skald.flyway_schema_history WHERE success AND version IS NOT NULL"
                + " ORDER BY installed_rank",
            String.class));
        for (String table : List.of("bundle", "build", "artifact")) {
            assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM information_schema.tables"
                + " WHERE table_schema = 'skald' AND table_name = ?", Integer.class, table), table);
        }
        assertEquals("YES", jdbc.queryForObject("SELECT is_nullable FROM information_schema.columns"
            + " WHERE table_schema = 'skald' AND table_name = 'content_version'"
            + " AND column_name = 'build_id'", String.class));
    }

    @Test
    public void aPopulatedV1DatabaseKeepsEveryRowIdPathAndItsChecksum() {
        JdbcTemplate jdbc = database("1");
        UUID content = UUID.randomUUID();
        UUID other = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type) VALUES (?, 'Sales', 'alice', 'shiny')", content);
        jdbc.update("INSERT INTO skald.content (id, title, owner, type, visibility)"
            + " VALUES (?, 'Docs', 'bob', 'quarto_static', 'all_authenticated')", other);
        jdbc.update("INSERT INTO skald.content_path (path, path_key, content_id) VALUES ('Sales/Q3', 'sales/q3', ?)", content);
        jdbc.update("INSERT INTO skald.content_path (path, path_key, content_id, is_current, retired_at)"
            + " VALUES ('old-sales', 'old-sales', NULL, false, now())");
        UUID v1 = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content_version (id, content_id, version, image, created_by)"
            + " VALUES (?, ?, 1, 'registry:5000/sales@sha256:' || repeat('a', 64), 'alice')", v1, content);
        jdbc.update("INSERT INTO skald.content_version (content_id, version, image, spec_json, created_by)"
            + " VALUES (?, 2, 'registry:5000/sales:2', '{\"x\": 1}', 'alice')", content);
        jdbc.update("UPDATE skald.content SET active_version_id = ? WHERE id = ?", v1, content);
        jdbc.update("INSERT INTO skald.content_acl (content_id, principal_type, principal) VALUES (?, 'group', 'sales')", content);
        jdbc.update("INSERT INTO skald.content_env (content_id, key, value_encrypted, is_secret)"
            + " VALUES (?, 'TOKEN', '\\x00ff'::bytea, true)", content);
        jdbc.update("INSERT INTO skald.audit_event (actor, action, subject_type, subject_id)"
            + " VALUES ('alice', 'content.create', 'content', ?)", content.toString());

        List<String> tables = List.of("content", "content_path", "content_version", "content_acl",
            "content_env", "audit_event");
        Map<String, List<Map<String, Object>>> before = new java.util.LinkedHashMap<>();
        for (String table : tables) {
            before.put(table, rows(jdbc, table));
        }
        Object v1Checksum = jdbc.queryForObject(
            "SELECT checksum FROM skald.flyway_schema_history WHERE version = '1'", Object.class);

        migrate(urlOf(jdbc), null);

        for (String table : tables) {
            List<Map<String, Object>> after = rows(jdbc, table);
            if (table.equals("content_version")) {
                // The one column V2 adds; an existing direct-image version has no build.
                for (Map<String, Object> row : after) {
                    assertTrue(row.containsKey("build_id"));
                    assertNull(row.remove("build_id"), "an old version gained a build link");
                }
            }
            assertEquals(before.get(table), after, table + " changed across V2");
        }
        assertEquals(v1Checksum, jdbc.queryForObject(
            "SELECT checksum FROM skald.flyway_schema_history WHERE version = '1'", Object.class),
            "V1's recorded checksum changed: V1 itself was edited");
        assertEquals(Boolean.TRUE, jdbc.queryForObject(
            "SELECT success FROM skald.flyway_schema_history WHERE version = '2'", Boolean.class));
    }

    // ------------------------------------------------------------------ the constraints

    private static UUID content(JdbcTemplate jdbc) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type) VALUES (?, 't', 'alice', 'shiny')", id);
        return id;
    }

    private static UUID bundle(JdbcTemplate jdbc, UUID content) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.bundle (id, content_id, created_by, upload_deadline)"
            + " VALUES (?, ?, 'alice', now() + interval '1 hour')", id, content);
        return id;
    }

    private static final String FINGERPRINT = "f".repeat(64);

    private static UUID build(JdbcTemplate jdbc, UUID content, UUID bundle, String key, String state) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.build (id, content_id, bundle_id, created_by, idempotency_key,"
            + " input_fingerprint, state, finished_at, lease_owner, lease_expires_at, lease_generation,"
            + " output_image) VALUES (?, ?, ?, 'alice', ?, ?, ?,"
            + " CASE WHEN ? IN ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','INTERRUPTED') THEN now() END,"
            + " CASE WHEN ? IN ('RUNNING','PUBLISHING') THEN 'node-1' END,"
            + " CASE WHEN ? IN ('RUNNING','PUBLISHING') THEN now() + interval '60 seconds' END,"
            + " CASE WHEN ? IN ('RUNNING','PUBLISHING') THEN 1 ELSE 0 END,"
            + " CASE WHEN ? = 'SUCCEEDED' THEN 'registry:5000/x@sha256:' || repeat('b', 64) END)",
            id, content, bundle, key, FINGERPRINT, state, state, state, state, state, state);
        return id;
    }

    @Test
    public void theIdempotencyKeyIsUniquePerContentAndNeverReusable() {
        JdbcTemplate jdbc = database(null);
        UUID c = content(jdbc);
        UUID b = bundle(jdbc, c);
        build(jdbc, c, b, "key-1", "FAILED");
        assertThrows(DataIntegrityViolationException.class, () -> build(jdbc, c, b, "key-1", "FAILED"));
        // The same key on ANOTHER content item is a different key.
        UUID c2 = content(jdbc);
        build(jdbc, c2, bundle(jdbc, c2), "key-1", "FAILED");
        assertThrows(DataIntegrityViolationException.class,
            () -> build(jdbc, c, b, "has space", "FAILED"), "a key with whitespace");
        assertThrows(DataIntegrityViolationException.class,
            () -> build(jdbc, c, b, "", "FAILED"), "an empty key");
    }

    @Test
    public void atMostOneQueuedBuildPerContent() {
        JdbcTemplate jdbc = database(null);
        UUID c = content(jdbc);
        UUID b = bundle(jdbc, c);
        build(jdbc, c, b, "a", "QUEUED");
        assertThrows(DataIntegrityViolationException.class, () -> build(jdbc, c, b, "b", "QUEUED"));
        // Running and terminal builds do not count: the supersede rule is about the queue.
        build(jdbc, c, b, "c", "RUNNING");
        build(jdbc, c, b, "d", "CANCELLED");
        UUID c2 = content(jdbc);
        build(jdbc, c2, bundle(jdbc, c2), "a", "QUEUED");
    }

    @Test
    public void aRowCannotClaimAStateItDoesNotCarry() {
        JdbcTemplate jdbc = database(null);
        UUID c = content(jdbc);
        UUID b = bundle(jdbc, c);
        UUID queued = build(jdbc, c, b, "q", "QUEUED");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.build SET state = 'FAILED' WHERE id = ?", queued), "terminal without a finish time");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.build SET state = 'RUNNING' WHERE id = ?", queued), "running without a lease");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.build SET state = 'SUCCEEDED', finished_at = now() WHERE id = ?", queued),
            "success without an image");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.build SET state = 'NOT_A_STATE' WHERE id = ?", queued), "unknown state");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.build SET superseded_by = ? WHERE id = ?", queued, queued),
            "superseded but not cancelled");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.bundle SET state = 'REJECTED', finished_at = now() WHERE id = ?", b),
            "a rejection that names no rule");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "UPDATE skald.bundle SET state = 'VALIDATED', finished_at = now() WHERE id = ?", b),
            "validated without its digests and totals");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "INSERT INTO skald.build (content_id, created_by, idempotency_key, input_fingerprint)"
                + " VALUES (?, 'alice', 'x', ?)", c, FINGERPRINT), "a build without a bundle");
    }

    @Test
    public void exactlyOneVersionPerBuild() {
        JdbcTemplate jdbc = database(null);
        UUID c = content(jdbc);
        UUID built = build(jdbc, c, bundle(jdbc, c), "s", "SUCCEEDED");
        jdbc.update("INSERT INTO skald.content_version (content_id, version, image, created_by, build_id)"
            + " VALUES (?, 1, 'img', 'alice', ?)", c, built);
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "INSERT INTO skald.content_version (content_id, version, image, created_by, build_id)"
                + " VALUES (?, 2, 'img', 'alice', ?)", c, built));
        // Direct-image versions stay valid without one.
        jdbc.update("INSERT INTO skald.content_version (content_id, version, image, created_by)"
            + " VALUES (?, 3, 'img', 'alice')", c);
    }

    @Test
    public void artifactRecordsSurviveTheDeletionOfTheirContent() {
        JdbcTemplate jdbc = database(null);
        UUID c = content(jdbc);
        UUID b = bundle(jdbc, c);
        UUID built = build(jdbc, c, b, "k", "FAILED");
        jdbc.update("INSERT INTO skald.artifact (kind, ref, subject_content_id, subject_bundle_id,"
            + " subject_build_id) VALUES ('bundle_object', 'bundles/' || ?, ?, ?, ?)",
            b.toString(), c, b, built);
        jdbc.update("DELETE FROM skald.content WHERE id = ?", c);
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE id = ?", Integer.class, built));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM skald.bundle WHERE id = ?", Integer.class, b));
        assertEquals(1, jdbc.queryForObject(
            "SELECT count(*) FROM skald.artifact WHERE subject_content_id = ?", Integer.class, c),
            "the ledger record was cascaded away with its content");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "INSERT INTO skald.artifact (kind, ref, subject_content_id) VALUES ('nonsense', 'r', ?)", c));
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
            "INSERT INTO skald.artifact (kind, ref, subject_content_id, state)"
                + " VALUES ('image', 'r2', ?, 'DELETE_PENDING')", c), "pending without a request time");
    }
}
