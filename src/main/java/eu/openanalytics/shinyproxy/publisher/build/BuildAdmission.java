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
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Admits a build request: one short transaction that either returns an attempt or refuses
 * with a reason (WORKPLAN-BUNDLES.md T6, "V2 and lifecycle" steps 1-2, decisions 1, 2 and 5
 * of 2026-10-01). It never runs anything; a QUEUED row is the whole of its output.
 *
 * <p>In order, inside the transaction:
 * <ol>
 *   <li>a global advisory lock, so the queue and per-publisher counts below are exact across
 *       content items, and then the content row, FOR UPDATE -- the same coordination lock
 *       version allocation and deletion take;</li>
 *   <li>the idempotency key: a key seen before for the same inputs returns that attempt,
 *       whatever has happened since (even a full queue); for different inputs it is refused.
 *       Checked first so an HTTP retry is never turned into a refusal by the limits;</li>
 *   <li>the bundle: it must belong to this content item and be VALIDATED (an invariant the
 *       schema cannot hold, because it needs the bundle's row: a00a190 review N3);</li>
 *   <li>the limits, counting the QUEUED attempt about to be superseded as already gone;</li>
 *   <li>supersede (decision 1): the content item's QUEUED attempt becomes CANCELLED, and
 *       after the new row exists its superseded_by names it. The database's
 *       one-QUEUED-per-content index is what makes this the only way to queue a second.</li>
 * </ol>
 */
public final class BuildAdmission {

    /** The inputs that decide whether two requests are the same request. */
    public record Inputs(UUID bundleId, Map<String, String> recipe) {
        public Inputs {
            recipe = recipe == null ? Map.of() : Map.copyOf(recipe);
        }
    }

    /** The attempt a request resolved to; {@code created} is false for an idempotent replay. */
    public record Admitted(UUID buildId, boolean created, UUID superseded) { }

    private static final Pattern KEY = Pattern.compile("[\\x21-\\x7e]{1,200}");
    // Any constant: the one lock every admission takes, so counts are not raced.
    private static final long ADMISSION_LOCK = 0x5ca1dad0001L;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AdmissionLimits limits;
    private final ObjectMapper canonical = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    public BuildAdmission(JdbcTemplate jdbc, AdmissionLimits limits) {
        this.jdbc = jdbc;
        this.limits = limits;
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
    }

    public Admitted request(UUID contentId, String actor, String idempotencyKey, Inputs inputs) {
        if (idempotencyKey == null || !KEY.matcher(idempotencyKey).matches()) {
            throw new AdmissionRefusal(AdmissionRefusal.Reason.KEY_INVALID,
                    "an idempotency key is 1 to 200 printable ASCII characters");
        }
        String fingerprint = fingerprint(inputs);
        return tx.execute(status -> admit(contentId, actor, idempotencyKey, inputs, fingerprint));
    }

    private Admitted admit(UUID contentId, String actor, String key, Inputs inputs,
                           String fingerprint) {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)", Object.class, ADMISSION_LOCK);
        if (jdbc.queryForList("SELECT id FROM skald.content WHERE id = ? FOR UPDATE",
                contentId).isEmpty()) {
            throw new AdmissionRefusal(AdmissionRefusal.Reason.CONTENT_NOT_FOUND,
                    "no content item " + contentId);
        }

        List<Map<String, Object>> seen = jdbc.queryForList("SELECT id, input_fingerprint"
                + " FROM skald.build WHERE content_id = ? AND idempotency_key = ?", contentId, key);
        if (!seen.isEmpty()) {
            if (fingerprint.equals(seen.get(0).get("input_fingerprint"))) {
                return new Admitted((UUID) seen.get(0).get("id"), false, null);
            }
            throw new AdmissionRefusal(AdmissionRefusal.Reason.KEY_REUSED_WITH_DIFFERENT_INPUTS,
                    "this idempotency key was used for a different build request");
        }

        List<String> bundle = jdbc.queryForList("SELECT state FROM skald.bundle"
                + " WHERE id = ? AND content_id = ?", String.class, inputs.bundleId(), contentId);
        if (bundle.isEmpty()) {
            throw new AdmissionRefusal(AdmissionRefusal.Reason.BUNDLE_NOT_FOUND,
                    "no bundle " + inputs.bundleId() + " for this content item");
        }
        if (!"VALIDATED".equals(bundle.get(0))) {
            throw new AdmissionRefusal(AdmissionRefusal.Reason.BUNDLE_NOT_VALIDATED,
                    "bundle " + inputs.bundleId() + " is " + bundle.get(0) + ", not VALIDATED");
        }

        List<Map<String, Object>> queued = jdbc.queryForList("SELECT id, created_by"
                + " FROM skald.build WHERE content_id = ? AND state = 'QUEUED' FOR UPDATE",
                contentId);
        UUID superseded = queued.isEmpty() ? null : (UUID) queued.get(0).get("id");
        boolean ownSuperseded = superseded != null && actor.equals(queued.get(0).get("created_by"));

        int active = jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE created_by = ?"
                + " AND state IN ('QUEUED', 'RUNNING', 'PUBLISHING')", Integer.class, actor);
        if (active - (ownSuperseded ? 1 : 0) >= limits.perPublisherActive()) {
            throw new AdmissionRefusal(AdmissionRefusal.Reason.PUBLISHER_LIMIT,
                    "already " + active + " unfinished build(s); the limit is "
                            + limits.perPublisherActive());
        }
        int waiting = jdbc.queryForObject("SELECT count(*) FROM skald.build WHERE state = 'QUEUED'",
                Integer.class);
        if (waiting - (superseded != null ? 1 : 0) >= limits.queueCapacity()) {
            throw new AdmissionRefusal(AdmissionRefusal.Reason.QUEUE_FULL,
                    "the build queue is full (" + limits.queueCapacity() + ")");
        }

        if (superseded != null) {
            jdbc.update("UPDATE skald.build SET state = 'CANCELLED', finished_at = now(),"
                    + " updated_at = now() WHERE id = ? AND state = 'QUEUED'", superseded);
        }
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.build (id, content_id, bundle_id, created_by,"
                + " idempotency_key, input_fingerprint, recipe) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb)",
                id, contentId, inputs.bundleId(), actor, key, fingerprint, json(inputs.recipe()));
        if (superseded != null) {
            jdbc.update("UPDATE skald.build SET superseded_by = ? WHERE id = ?", id, superseded);
            audit(actor, "build.superseded", superseded, Map.of("by", id.toString()));
        }
        audit(actor, "build.admitted", id, Map.of("content", contentId.toString(),
                "bundle", inputs.bundleId().toString()));
        return new Admitted(id, true, superseded);
    }

    /** SHA-256 over the canonical JSON of the inputs: key order never changes the result. */
    String fingerprint(Inputs inputs) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("bundle_id", String.valueOf(inputs.bundleId()));
        doc.put("recipe", new TreeMap<>(inputs.recipe()));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.writeValueAsString(doc).getBytes(StandardCharsets.UTF_8)));
        } catch (JsonProcessingException | NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private String json(Object value) {
        try {
            return canonical.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void audit(String actor, String action, UUID buildId, Map<String, String> detail) {
        jdbc.update("INSERT INTO skald.audit_event (actor, action, subject_type, subject_id,"
                + " detail_json) VALUES (?, ?, 'build', ?, ?::jsonb)",
                actor, action, buildId.toString(), json(new TreeMap<>(detail)));
    }
}
