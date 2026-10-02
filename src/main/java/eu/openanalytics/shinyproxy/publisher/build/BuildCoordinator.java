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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;

/**
 * The durable coordinator: claims QUEUED attempts under a PostgreSQL lease, fences every
 * worker update by lease generation, handles cancellation, and reaps what a lost worker left
 * behind (WORKPLAN-BUNDLES.md T6, "V2 and lifecycle" step 3; decisions 3 and 4 of
 * 2026-10-01). It holds no state in memory: a coordinator in another process, or this one
 * after a restart, sees exactly the same thing, which is what makes several instances safe.
 *
 * <p>Every worker-side transition is one UPDATE whose WHERE clause carries the expected
 * state, the lease's generation and an unexpired lease. Zero rows matched means the attempt
 * is no longer the caller's, and {@link Fenced} is thrown rather than anything being merged.
 * The transitions are spec/lifecycle-v1.json's build machine; none activates anything.
 */
public final class BuildCoordinator {

    /** What a cancel request did. */
    public enum CancelOutcome {
        /** QUEUED: cancelled at once, nothing was running. */
        CANCELLED,
        /** RUNNING: recorded; the attempt is CANCELLED once the worker confirms it stopped. */
        REQUESTED,
        /** PUBLISHING: refused (spec: cancel_refused_states); recovery is deleting the content. */
        REFUSED_PUBLISHING,
        /** Already terminal; nothing changed. */
        ALREADY_FINISHED,
        /** No such build for this content item. */
        NOT_FOUND
    }

    // Distinct from admission's: claims serialise among themselves so the running count is
    // exact, and do not wait on admissions.
    private static final long CLAIM_LOCK = 0x5ca1dad0002L;
    private static final List<String> TERMINAL =
            List.of("SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED");

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final CoordinatorSettings settings;
    private final ObjectMapper json = new ObjectMapper();

    public BuildCoordinator(JdbcTemplate jdbc, CoordinatorSettings settings) {
        this.jdbc = jdbc;
        this.settings = settings;
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
    }

    // ------------------------------------------------------------------ claim and renew

    /**
     * Claims the oldest QUEUED attempt for {@code owner}, if fewer than max_running attempts
     * are running. QUEUED -> RUNNING with a fresh lease, the generation bumped and the wall
     * deadline set. SKIP LOCKED: an attempt an admission is superseding right now is skipped
     * rather than waited for.
     */
    public Optional<BuildDriver.Claimed> claim(String owner) {
        return tx.execute(status -> {
            jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)", Object.class, CLAIM_LOCK);
            int running = jdbc.queryForObject("SELECT count(*) FROM skald.build"
                    + " WHERE state IN ('RUNNING', 'PUBLISHING')", Integer.class);
            if (running >= settings.maxRunning()) {
                return Optional.<BuildDriver.Claimed>empty();
            }
            List<Map<String, Object>> rows = jdbc.queryForList("UPDATE skald.build SET"
                    + " state = 'RUNNING', lease_owner = ?, lease_generation = lease_generation + 1,"
                    + " lease_expires_at = now() + make_interval(secs => ?),"
                    + " deadline_at = now() + make_interval(secs => ?),"
                    + " started_at = now(), updated_at = now()"
                    + " WHERE id = (SELECT id FROM skald.build WHERE state = 'QUEUED'"
                    + "   ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)"
                    // Redundant, and kept as a statement of intent: the subquery's FOR UPDATE
                    // already holds the chosen row for the rest of this statement, so nothing
                    // can supersede it between the choice and this update (a mutant without it
                    // passes every test, which is why this says "redundant" and not "fix").
                    + " AND state = 'QUEUED'"
                    + " RETURNING id, content_id, bundle_id, recipe::text AS recipe, lease_generation",
                    owner, settings.lease().toSeconds(), settings.deadline().toSeconds());
            if (rows.isEmpty()) {
                return Optional.<BuildDriver.Claimed>empty();
            }
            Map<String, Object> row = rows.get(0);
            UUID id = (UUID) row.get("id");
            Lease lease = new Lease(id, ((Number) row.get("lease_generation")).longValue(), owner);
            audit(owner, "build.claimed", id, Map.of("generation", String.valueOf(lease.generation())));
            return Optional.of(new BuildDriver.Claimed(id, (UUID) row.get("content_id"),
                    (UUID) row.get("bundle_id"), recipe((String) row.get("recipe")), lease));
        });
    }

    /** Extends a live lease. False when the lease is no longer the caller's: stop. */
    public boolean renew(Lease lease) {
        return jdbc.update("UPDATE skald.build SET lease_expires_at = now() + make_interval(secs => ?),"
                + " updated_at = now() WHERE id = ? AND lease_generation = ? AND lease_owner = ?"
                + " AND state IN ('RUNNING', 'PUBLISHING') AND lease_expires_at > now()",
                settings.lease().toSeconds(), lease.buildId(), lease.generation(), lease.owner()) == 1;
    }

    /** Has a cancellation been requested for the attempt this lease holds? */
    public boolean cancelRequested(Lease lease) {
        List<Boolean> rows = jdbc.queryForList("SELECT cancel_requested_at IS NOT NULL FROM skald.build"
                + " WHERE id = ? AND lease_generation = ?", Boolean.class, lease.buildId(), lease.generation());
        return !rows.isEmpty() && rows.get(0);
    }

    // ------------------------------------------------------------------ fenced worker transitions

    /** RUNNING -> PUBLISHING: the driver produced an image (a digest reference). */
    public void toPublishing(Lease lease, String image) {
        fenced(lease, "RUNNING", "state = 'PUBLISHING', publishing_at = now(), output_image = ?",
                List.of(image), "build.publishing");
    }

    /** RUNNING or PUBLISHING -> FAILED. */
    public void fail(Lease lease, String code, String detail) {
        int changed = jdbc.update("UPDATE skald.build SET state = 'FAILED', finished_at = now(),"
                + " updated_at = now(), error_code = ?, error_detail = ?"
                + " WHERE id = ? AND lease_generation = ? AND lease_owner = ?"
                + " AND state IN ('RUNNING', 'PUBLISHING') AND lease_expires_at > now()",
                code, detail, lease.buildId(), lease.generation(), lease.owner());
        requireOne(changed, lease, "FAILED");
        audit(lease.owner(), "build.failed", lease.buildId(), Map.of("code", code));
    }

    /** RUNNING -> CANCELLED, only after a requested cancellation and the worker's confirmed stop. */
    public void confirmCancelled(Lease lease) {
        int changed = jdbc.update("UPDATE skald.build SET state = 'CANCELLED', finished_at = now(),"
                + " updated_at = now() WHERE id = ? AND lease_generation = ? AND lease_owner = ?"
                + " AND state = 'RUNNING' AND cancel_requested_at IS NOT NULL AND lease_expires_at > now()",
                lease.buildId(), lease.generation(), lease.owner());
        requireOne(changed, lease, "CANCELLED");
        audit(lease.owner(), "build.cancelled", lease.buildId(), Map.of("confirmed", "true"));
    }

    private void fenced(Lease lease, String from, String set, List<Object> setArgs, String action) {
        List<Object> args = new java.util.ArrayList<>(setArgs);
        args.addAll(List.of(lease.buildId(), lease.generation(), lease.owner(), from));
        int changed = jdbc.update("UPDATE skald.build SET " + set + ", updated_at = now()"
                + " WHERE id = ? AND lease_generation = ? AND lease_owner = ? AND state = ?"
                + " AND lease_expires_at > now()", args.toArray());
        requireOne(changed, lease, from + " -> next");
        audit(lease.owner(), action, lease.buildId(), Map.of("generation", String.valueOf(lease.generation())));
    }

    private static void requireOne(int changed, Lease lease, String what) {
        if (changed != 1) {
            throw new Fenced("build " + lease.buildId() + " (generation " + lease.generation()
                    + ") is no longer this worker's; " + what + " refused");
        }
    }

    // ------------------------------------------------------------------ cancel and reap

    /** A user's cancel request, scoped to the content item the build belongs to. */
    public CancelOutcome cancel(UUID contentId, UUID buildId, String actor) {
        return tx.execute(status -> {
            List<String> states = jdbc.queryForList("SELECT state FROM skald.build WHERE id = ?"
                    + " AND content_id = ? FOR UPDATE", String.class, buildId, contentId);
            if (states.isEmpty()) {
                return CancelOutcome.NOT_FOUND;
            }
            String state = states.get(0);
            CancelOutcome outcome;
            if (state.equals("QUEUED")) {
                jdbc.update("UPDATE skald.build SET state = 'CANCELLED', finished_at = now(),"
                        + " cancel_requested_at = now(), updated_at = now() WHERE id = ?", buildId);
                outcome = CancelOutcome.CANCELLED;
            } else if (state.equals("RUNNING")) {
                jdbc.update("UPDATE skald.build SET cancel_requested_at = coalesce(cancel_requested_at,"
                        + " now()), updated_at = now() WHERE id = ?", buildId);
                outcome = CancelOutcome.REQUESTED;
            } else if (state.equals("PUBLISHING")) {
                outcome = CancelOutcome.REFUSED_PUBLISHING;
            } else {
                outcome = CancelOutcome.ALREADY_FINISHED;
            }
            audit(actor, "build.cancel." + outcome.name().toLowerCase(java.util.Locale.ROOT), buildId, Map.of());
            return outcome;
        });
    }

    /**
     * What a lost worker left behind. A wall deadline passed -> TIMED_OUT; otherwise a lease
     * expired -> INTERRUPTED. No retry is scheduled (decision 4): a retry is a new attempt a
     * user starts. A PUBLISHING attempt is reaped the same way here; reconciliation of what it
     * may already have published is the finalization part's (T6, later). Its version
     * transaction is fenced by this very state change, so it cannot succeed late.
     *
     * @return how many attempts were reaped
     */
    public int reap() {
        List<UUID> timedOut = jdbc.queryForList("UPDATE skald.build SET state = 'TIMED_OUT',"
                + " finished_at = now(), updated_at = now(), error_code = 'DEADLINE_EXCEEDED'"
                + " WHERE state IN ('RUNNING', 'PUBLISHING') AND deadline_at <= now() RETURNING id",
                UUID.class);
        List<UUID> interrupted = jdbc.queryForList("UPDATE skald.build SET state = 'INTERRUPTED',"
                + " finished_at = now(), updated_at = now(), error_code = 'LEASE_EXPIRED'"
                + " WHERE state IN ('RUNNING', 'PUBLISHING') AND lease_expires_at <= now() RETURNING id",
                UUID.class);
        for (UUID id : timedOut) {
            audit("coordinator", "build.timed_out", id, Map.of());
        }
        for (UUID id : interrupted) {
            audit("coordinator", "build.interrupted", id, Map.of());
        }
        return timedOut.size() + interrupted.size();
    }

    /** True if {@code state} is one of the build machine's terminal states. */
    static boolean terminal(String state) {
        return TERMINAL.contains(state);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> recipe(String text) {
        try {
            return text == null ? Map.of() : json.readValue(text, Map.class);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("unreadable recipe", ex);
        }
    }

    private void audit(String actor, String action, UUID buildId, Map<String, String> detail) {
        String body;
        try {
            body = json.writeValueAsString(new TreeMap<>(detail));
        } catch (JsonProcessingException ex) {
            body = "{}";
        }
        jdbc.update("INSERT INTO skald.audit_event (actor, action, subject_type, subject_id,"
                + " detail_json) VALUES (?, ?, 'build', ?, ?::jsonb)", actor, action,
                buildId.toString(), body);
    }
}
