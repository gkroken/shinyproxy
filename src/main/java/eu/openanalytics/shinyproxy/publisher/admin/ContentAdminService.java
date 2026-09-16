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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.containerproxy.model.runtime.Proxy;
import eu.openanalytics.containerproxy.service.ProxyService;
import eu.openanalytics.containerproxy.service.UserService;
import eu.openanalytics.shinyproxy.publisher.registry.AccessControlProjector;
import eu.openanalytics.shinyproxy.publisher.registry.ContentPath;
import eu.openanalytics.shinyproxy.publisher.registry.ContentSpecRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * The admin-only write path for the content registry.
 *
 * <p><b>Identity and address are separate here, and that is the point.</b> Content is
 * identified by an immutable UUID, which the spec id derives from; the path is a publisher
 * setting that can be renamed. An earlier version keyed everything on a slug and got both
 * halves wrong — the spec id became reusable, so deleting content and re-creating it at the
 * same name handed the new content the old one's cached authorization decisions, and the URL
 * became frozen, because renaming would have changed the spec id that running containers are
 * recorded against.
 *
 * <p>Refusals, each an explicit error rather than a silent adjustment:
 *
 * <ul>
 *   <li><b>Path already used</b>, by live content or by content since deleted — retired paths
 *       stay reserved, so nobody inherits a retired URL's audience and its stale links.</li>
 *   <li><b>Path nested inside another</b>, either way round. Content owns its whole subtree,
 *       so {@code team} and {@code team/reports} cannot both exist: a request would be
 *       satisfiable two ways and the resolver has no basis to choose.</li>
 *   <li><b>{@code visibility = anonymous}</b> — ContainerProxy rejects anonymous principals
 *       before access control is evaluated, so the content would be permanently invisible.</li>
 *   <li><b>Deleting content with live proxies</b> — a proxy whose spec stops resolving
 *       disappears from its own owner's list.</li>
 * </ul>
 *
 * <p><b>Still deliberately absent: any way to change an ACL or a visibility mode.</b> Those
 * remain the two mutations that would make ContainerProxy's uninvalidatable per-session
 * authorization cache a live bug ({@code docs/UPSTREAM_CHANGES.md} section B). Note that the
 * original justification for that scope — "a new spec id has never been cached" — was false
 * while spec ids came from slugs, and holds now only because they come from UUIDs.
 */
@Service
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentAdminService {

    /** Mirrors {@code content_type_known}. */
    private static final Set<String> TYPES =
        Set.of("shiny", "quarto_static", "rmarkdown_static", "plumber", "fastapi", "data");

    /**
     * Mirrors {@code content_visibility_known} minus {@code anonymous}, which the schema
     * permits and Skald cannot yet serve. A separate set rather than a subtraction, so that
     * implementing anonymous access (spine #5) is a one-line change here.
     */
    private static final Set<String> WRITABLE_VISIBILITIES =
        Set.of(AccessControlProjector.VISIBILITY_ACL_ONLY,
            AccessControlProjector.VISIBILITY_ALL_AUTHENTICATED);

    private static final String SELECT_SUMMARY = """
        SELECT c.id, c.title, c.owner, c.type, c.visibility,
               (SELECT p.path FROM skald.content_path p
                 WHERE p.content_id = c.id AND p.is_current) AS path,
               (SELECT v.version FROM skald.content_version v
                 WHERE v.id = c.active_version_id) AS active_version,
               COALESCE((SELECT array_agg(v.version ORDER BY v.version)
                         FROM skald.content_version v WHERE v.content_id = c.id), '{}') AS versions
        FROM skald.content c
        """;

    private final JdbcTemplate jdbc;
    private final ProxyService proxyService;
    private final UserService userService;
    private final ObjectMapper objectMapper;

    public ContentAdminService(JdbcTemplate jdbc,
                               @Lazy ProxyService proxyService,
                               @Lazy UserService userService,
                               ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.proxyService = proxyService;
        this.userService = userService;
        this.objectMapper = objectMapper;
    }

    public List<ContentSummary> list() {
        return jdbc.query(SELECT_SUMMARY + " ORDER BY c.title", this::toSummary);
    }

    /**
     * Resolves a path, following a rename.
     *
     * <p>The admin API has to do this for the same reason a browser gets a 301: a rename must
     * not silently break every script that referenced the old name. A caller asking by a
     * retired path gets the content, with {@code pathIsCurrent = false} so it can notice and
     * update itself.
     */
    public PathResolution resolveByPath(String path) {
        String key = normaliseOrBad(path);

        List<Map<String, Object>> rows = jdbc.queryForList(
            "SELECT content_id, is_current FROM skald.content_path WHERE path_key = ?", key);
        if (rows.isEmpty()) {
            throw notFound("no content at path '" + path + "'");
        }

        UUID contentId = (UUID) rows.get(0).get("content_id");
        if (contentId == null) {
            // Reserved, with nothing behind it. Gone, not missing: the distinction is the
            // promise that nobody else will ever answer at this path.
            throw new ContentAdminException(HttpStatus.GONE,
                "path '" + path + "' belonged to content that has been deleted, and stays "
                    + "reserved so that it can never point at different content");
        }
        return new PathResolution(requireContent(contentId), (Boolean) rows.get(0).get("is_current"));
    }

    @Transactional
    public ContentSummary create(CreateContentRequest request) {
        String title = require(request.title(), "title");
        String owner = require(request.owner(), "owner");
        String type = require(request.type(), "type");
        String path = require(request.path(), "path");
        String visibility = (request.visibility() == null)
            ? AccessControlProjector.VISIBILITY_ACL_ONLY : request.visibility();
        String key = normaliseOrBad(path);

        if (!TYPES.contains(type)) {
            throw bad("unknown type '" + type + "'; expected one of " + sorted(TYPES));
        }
        if (AccessControlProjector.VISIBILITY_ANONYMOUS.equals(visibility)) {
            throw bad("visibility 'anonymous' is not supported: ContainerProxy rejects "
                + "anonymous principals before access control is evaluated, so the content "
                + "would be permanently invisible. See docs/UPSTREAM_CHANGES.md section A; "
                + "public links are planned for static documents in spine #5.");
        }
        if (!WRITABLE_VISIBILITIES.contains(visibility)) {
            throw bad("unknown visibility '" + visibility + "'; expected one of "
                + sorted(WRITABLE_VISIBILITIES));
        }

        UUID contentId = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content (id, title, owner, type, visibility) "
            + "VALUES (?, ?, ?, ?, ?)", contentId, title, owner, type, visibility);
        claimPath(contentId, path, key);

        audit("content.create", contentId, Map.of("path", path, "title", title,
            "owner", owner, "type", type, "visibility", visibility));
        return requireContent(contentId);
    }

    /**
     * Moves content to a new path, keeping the old one reserved and pointing at it.
     *
     * <p>The old row is retired rather than updated, because it is the source of the redirect.
     * Nothing else changes: the spec id derives from the content UUID, so every running
     * container keeps working across a rename.
     */
    @Transactional
    public ContentSummary rename(UUID contentId, RenameRequest request) {
        ContentSummary existing = requireContent(contentId);
        String path = require(request.path(), "path");
        String key = normaliseOrBad(path);

        if (key.equals(normaliseOrBad(existing.path()))) {
            return existing;
        }

        jdbc.update("UPDATE skald.content_path SET is_current = false, retired_at = now() "
            + "WHERE content_id = ? AND is_current", contentId);
        claimPath(contentId, path, key);

        audit("content.rename", contentId, Map.of("from", existing.path(), "to", path));
        return requireContent(contentId);
    }

    /**
     * Adds a version and, unless told otherwise, makes it the active one.
     *
     * <p>The version number is assigned here rather than accepted from the caller: rollback
     * names an existing version through {@link #activate}, so letting a client choose buys
     * nothing and costs a class of conflicts to validate against.
     */
    @Transactional
    public ContentSummary addVersion(UUID contentId, AddVersionRequest request) {
        requireContent(contentId);
        String image = require(request.image(), "image");

        // Serialise allocation for this content item. Without the lock, two concurrent adds read
        // the same max(version) and the second violates content_version_unique, which reached
        // the caller as an unrecoverable error rather than a conflict.
        jdbc.queryForObject("SELECT id::text FROM skald.content WHERE id = ? FOR UPDATE",
            String.class, contentId);

        Integer version = jdbc.queryForObject(
            "SELECT COALESCE(max(version), 0) + 1 FROM skald.content_version WHERE content_id = ?",
            Integer.class, contentId);

        try {
            jdbc.update("INSERT INTO skald.content_version (content_id, version, image, created_by) "
                + "VALUES (?, ?, ?, ?)", contentId, version, image, actor());
        } catch (DataIntegrityViolationException e) {
            throw conflict("version " + version + " already exists");
        }
        audit("content.version.add", contentId,
            Map.of("version", String.valueOf(version), "image", image));

        if (!Boolean.FALSE.equals(request.activate())) {
            setActiveVersion(contentId, version);
        }
        return requireContent(contentId);
    }

    /** Activation and rollback are the same operation: point at a version that already exists. */
    @Transactional
    public ContentSummary activate(UUID contentId, ActivateRequest request) {
        requireContent(contentId);
        if (request.version() == null) {
            throw bad("version is required");
        }
        Integer exists = jdbc.queryForObject(
            "SELECT count(*) FROM skald.content_version WHERE content_id = ? AND version = ?",
            Integer.class, contentId, request.version());
        if (exists == null || exists == 0) {
            throw notFound("no version " + request.version() + " for this content");
        }

        setActiveVersion(contentId, request.version());
        return requireContent(contentId);
    }

    /**
     * Deletes content, refusing while any of its versions still has a live proxy, and leaving
     * its paths reserved.
     *
     * <p>{@code content_version} is {@code ON DELETE CASCADE}, so deleting would otherwise make
     * a running proxy's spec unresolvable — and a proxy whose spec does not resolve vanishes
     * from its own owner's list. The paths are {@code ON DELETE SET NULL} and survive, so the
     * URL answers 410 rather than becoming available to different content.
     */
    @Transactional
    public void delete(UUID contentId) {
        ContentSummary existing = requireContent(contentId);

        List<String> live = liveSpecIds(contentId);
        if (!live.isEmpty()) {
            throw conflict("this content still has running apps (" + String.join(", ", live)
                + "); stop them before deleting, or their owners would lose sight of them");
        }

        jdbc.update("UPDATE skald.content_path SET is_current = false, retired_at = now() "
            + "WHERE content_id = ? AND is_current", contentId);
        jdbc.update("DELETE FROM skald.content WHERE id = ?", contentId);
        audit("content.delete", contentId, Map.of("path", existing.path()));

        // Re-check before committing. A proxy can start between the check above and here, and no
        // database lock prevents that: proxy state lives in ContainerProxy's store, not in
        // PostgreSQL, so locking the content row would serialise nothing. Re-checking inside the
        // transaction turns "delete wins the race" into "delete loses it" — the residual window
        // is between here and the commit, and losing it costs a spurious conflict rather than a
        // stranded container.
        List<String> startedMeanwhile = liveSpecIds(contentId);
        if (!startedMeanwhile.isEmpty()) {
            throw conflict("an app started while this content was being deleted ("
                + String.join(", ", startedMeanwhile) + "); nothing was deleted, try again");
        }
    }

    // ------------------------------------------------------------------ internals

    /**
     * Reserves a path for this content, refusing anything already taken or nested.
     *
     * <p>The uniqueness check spans retired paths as well as live ones. The nesting check has to
     * be a query rather than a constraint, because it is a relationship between rows — which is
     * exactly why {@link #lockPathRoot} has to come first.
     */
    private void claimPath(UUID contentId, String path, String key) {
        lockPathRoot(key);

        List<Map<String, Object>> clashes = jdbc.queryForList("""
            SELECT path_key, is_current FROM skald.content_path
            WHERE path_key = ? OR path_key LIKE ? || '/%' OR ? LIKE path_key || '/%'
            ORDER BY (path_key = ?) DESC
            """, key, key, key, key);

        for (Map<String, Object> clash : clashes) {
            String other = (String) clash.get("path_key");
            if (other.equals(key)) {
                throw conflict("path '" + path + "' is already in use, or was used by content "
                    + "that has since been deleted; retired paths stay reserved so that they can "
                    + "never point at different content");
            }
            // A retired path still owns its subtree: it is the source of a 301, and a deep link
            // below it has to keep resolving to the same content after a rename. Saying "content
            // owns its subtree" for a retired row sends the reader looking for content that is
            // not there.
            throw conflict("path '" + path + "' conflicts with '" + other + "': "
                + (Boolean.TRUE.equals(clash.get("is_current"))
                ? "content owns its whole subtree, so one path cannot sit inside another"
                : "'" + other + "' is a retired path, and a retired path keeps its subtree "
                    + "reserved so that links below it still resolve"));
        }

        try {
            jdbc.update("INSERT INTO skald.content_path (path, path_key, content_id) "
                + "VALUES (?, ?, ?)", path, key, contentId);
        } catch (DataIntegrityViolationException e) {
            // Belt to the lock's braces, and the only guard left if the lock is ever removed
            // from an exact-key collision. Mapping the violation here is what makes a conflict
            // the documented answer for whoever loses a race.
            throw conflict("path '" + path + "' is already in use");
        }
    }

    /**
     * Serialises every path claim that could possibly conflict with this one.
     *
     * <p>Uniqueness of the exact key is backed by a unique index, so the insert above decides it
     * whatever happens concurrently. <b>Nesting is not.</b> It is a relationship between two
     * rows, so no constraint expresses it, and the check above is therefore read-then-write:
     * concurrent claims of {@code team} and {@code team/reports} both find nothing and both
     * insert. Reproduced before this lock existed — four parallel creates of {@code race},
     * {@code race/a}, {@code race/b} and {@code race/a/deep} all returned 201 and all four rows
     * survived, which is precisely the ambiguous state {@code /c/<path>} resolution cannot
     * answer. Pinned by {@code concurrentlyClaimedPathsNeverNestInsideOneAnother}.
     *
     * <p>Two paths can only nest if one is a prefix of the other, which requires them to share a
     * first segment. Locking on that segment is therefore the smallest lock that covers every
     * conflicting pair, and it lets unrelated publishers claim paths in parallel. The lock is
     * transaction-scoped, so the commit or rollback releases it and there is no unlock path to
     * get wrong.
     *
     * <p>{@code hashtext} collisions are harmless: two unrelated roots that hash alike merely
     * serialise against each other.
     */
    private void lockPathRoot(String key) {
        String root = key.split("/", 2)[0];
        jdbc.query("SELECT pg_advisory_xact_lock(hashtext(?))", rs -> {
        }, root);
    }

    private String normaliseOrBad(String path) {
        try {
            return ContentPath.normalise(path);
        } catch (IllegalArgumentException e) {
            throw bad(e.getMessage());
        }
    }

    /** Spec ids of this content's versions that currently have a proxy, in any state. */
    private List<String> liveSpecIds(UUID contentId) {
        Set<String> ids = jdbc.queryForList(
                "SELECT version FROM skald.content_version WHERE content_id = ?",
                Integer.class, contentId).stream()
            .map(v -> ContentSpecRepository.specId(contentId, v))
            .collect(java.util.stream.Collectors.toUnmodifiableSet());

        return proxyService.getAllProxies().stream()
            .map(Proxy::getSpecId)
            .filter(ids::contains)
            .distinct()
            .sorted()
            .toList();
    }

    /**
     * The one place the active version moves, and therefore the one place that records it.
     *
     * <p>Auditing here rather than in {@link #activate} is deliberate: adding a version
     * activates it by default, so auditing per endpoint would leave that activation — a real
     * change to what users are served — unrecorded.
     */
    private void setActiveVersion(UUID contentId, int version) {
        jdbc.update("""
            UPDATE skald.content c SET active_version_id = v.id, updated_at = now()
            FROM skald.content_version v
            WHERE v.content_id = c.id AND v.version = ? AND c.id = ?
            """, version, contentId);
        audit("content.activate", contentId, Map.of("version", String.valueOf(version)));
    }

    private ContentSummary requireContent(UUID contentId) {
        try {
            return jdbc.queryForObject(SELECT_SUMMARY + " WHERE c.id = ?", this::toSummary, contentId);
        } catch (EmptyResultDataAccessException e) {
            throw notFound("no content with id " + contentId);
        }
    }

    private ContentSummary toSummary(ResultSet rs, int rowNum) throws SQLException {
        UUID id = (UUID) rs.getObject("id");
        Integer activeVersion = (Integer) rs.getObject("active_version");
        return new ContentSummary(
            id.toString(),
            rs.getString("path"),
            rs.getString("title"),
            rs.getString("owner"),
            rs.getString("type"),
            rs.getString("visibility"),
            activeVersion,
            (activeVersion == null) ? null : ContentSpecRepository.specId(id, activeVersion),
            versions(rs.getArray("versions")));
    }

    private static List<Integer> versions(Array array) throws SQLException {
        if (array == null) {
            return List.of();
        }
        try {
            Integer[] values = (Integer[]) array.getArray();
            return (values == null) ? List.of() : List.of(values);
        } finally {
            array.free();
        }
    }

    /**
     * Append-only record of every mutation.
     *
     * <p>The subject is the content UUID, never the path. The path is mutable, so identifying
     * the subject by it would orphan every row written before a rename with no way to join old
     * to new — the trail would silently stop being one. The path travels in the detail as a
     * human-readable label.
     */
    private void audit(String action, UUID contentId, Map<String, String> detail) {
        String json;
        try {
            json = objectMapper.writeValueAsString(new HashMap<>(detail));
        } catch (JsonProcessingException e) {
            // Serialising a Map<String,String> cannot fail, but losing the mutation because the
            // audit row could not be written would be worse than losing the detail.
            json = "{}";
        }

        jdbc.update("""
            INSERT INTO skald.audit_event (actor, action, subject_type, subject_id, detail_json)
            VALUES (?, ?, 'content', ?, ?::jsonb)
            """, actor(), action, contentId.toString(), json);
    }

    private String actor() {
        try {
            String user = userService.getCurrentUserId();
            return (user == null) ? "unknown" : user;
        } catch (RuntimeException e) {
            // No security context (a background call). An audit row with a placeholder actor is
            // better than losing the event or failing the write.
            return "unknown";
        }
    }

    private static String require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw bad(field + " is required");
        }
        return value.trim();
    }

    private static List<String> sorted(Set<String> values) {
        return values.stream().sorted().toList();
    }

    private static ContentAdminException bad(String message) {
        return new ContentAdminException(HttpStatus.BAD_REQUEST, message);
    }

    private static ContentAdminException conflict(String message) {
        return new ContentAdminException(HttpStatus.CONFLICT, message);
    }

    private static ContentAdminException notFound(String message) {
        return new ContentAdminException(HttpStatus.NOT_FOUND, message);
    }

}
