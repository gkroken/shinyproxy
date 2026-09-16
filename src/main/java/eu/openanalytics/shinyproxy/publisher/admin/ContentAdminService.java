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
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import eu.openanalytics.shinyproxy.publisher.registry.AccessControlProjector;
import eu.openanalytics.shinyproxy.publisher.registry.ContentSpecRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The admin-only write path for the content registry (spine #1 task 7).
 *
 * <p>Every refusal here exists because an earlier task proved it was needed, and each one is
 * an explicit error rather than a silent adjustment:
 *
 * <ul>
 *   <li><b>Slug collides with a configured spec</b> — WORKPLAN-REGISTRY.md decision 3. YAML
 *       specs are authoritative, and the collision is rejected on write so the publisher gets
 *       exactly one error at the moment they can still act on it, instead of a URL that
 *       silently points somewhere else.</li>
 *   <li><b>{@code visibility = anonymous}</b> — task 5. ContainerProxy rejects anonymous
 *       principals before access control is evaluated, so Skald cannot serve it; accepting the
 *       value would store content that is permanently invisible.</li>
 *   <li><b>Deleting content with live proxies</b> — task 6. {@code content_version} is
 *       {@code ON DELETE CASCADE} from {@code content}, and a proxy whose spec stops resolving
 *       disappears from its own owner's list.</li>
 * </ul>
 *
 * <p><b>Deliberately absent: any way to change an ACL or a visibility mode.</b> Those are the
 * two writes that would make ContainerProxy's per-session authorization cache a live bug — a
 * revoked grant does not reach a session that is already using the app
 * ({@code docs/UPSTREAM_CHANGES.md} section B). Creating, versioning, activating and deleting
 * content do not touch either: a new spec id has never been cached, activation and rollback
 * leave ACLs alone, and deletion is safe because
 * {@code ProxyAccessControlService.canAccess(auth, specId)} null-checks the resolved spec
 * before it consults the cache. Sharing arrives in spine #4, and owns that decision.
 */
@Service
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentAdminService {

    /** Mirrors the {@code content_slug_format} CHECK constraint in V1__content_registry.sql. */
    private static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,49}$");

    /** Mirrors {@code content_type_known}. */
    private static final Set<String> TYPES =
        Set.of("shiny", "quarto_static", "rmarkdown_static", "plumber", "fastapi", "data");

    /**
     * Mirrors {@code content_visibility_known} minus {@code anonymous}, which the schema
     * permits and Skald cannot yet serve. Kept as a separate set rather than a subtraction so
     * that implementing anonymous access (spine #5) is a one-line change here.
     */
    private static final Set<String> WRITABLE_VISIBILITIES =
        Set.of(AccessControlProjector.VISIBILITY_ACL_ONLY,
            AccessControlProjector.VISIBILITY_ALL_AUTHENTICATED);

    private final JdbcTemplate jdbc;
    private final ContentSpecRepository repository;
    private final ShinyProxySpecProvider specProvider;
    private final ProxyService proxyService;
    private final UserService userService;
    private final ObjectMapper objectMapper;

    public ContentAdminService(JdbcTemplate jdbc,
                               ContentSpecRepository repository,
                               @Lazy ShinyProxySpecProvider specProvider,
                               @Lazy ProxyService proxyService,
                               @Lazy UserService userService,
                               ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.repository = repository;
        this.specProvider = specProvider;
        this.proxyService = proxyService;
        this.userService = userService;
        this.objectMapper = objectMapper;
    }

    public List<ContentSummary> list() {
        return jdbc.query("""
            SELECT c.slug, c.owner, c.type, c.visibility,
                   (SELECT v.version FROM skald.content_version v WHERE v.id = c.active_version_id) AS active_version,
                   COALESCE((SELECT array_agg(v.version ORDER BY v.version)
                             FROM skald.content_version v WHERE v.content_id = c.id), '{}') AS versions
            FROM skald.content c
            ORDER BY c.slug
            """, (rs, i) -> new ContentSummary(
            rs.getString("slug"), rs.getString("owner"), rs.getString("type"),
            rs.getString("visibility"),
            (Integer) rs.getObject("active_version"),
            versions(rs.getArray("versions"))));
    }

    @Transactional
    public ContentSummary create(CreateContentRequest request) {
        String slug = require(request.slug(), "slug");
        String owner = require(request.owner(), "owner");
        String type = require(request.type(), "type");
        String visibility = (request.visibility() == null)
            ? AccessControlProjector.VISIBILITY_ACL_ONLY : request.visibility();

        if (!SLUG.matcher(slug).matches()) {
            throw bad("slug must match " + SLUG.pattern()
                + " (lower-case, max 50 characters, so that '<slug>--v<n>' stays inside the "
                + "63-character Kubernetes label limit)");
        }
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

        // Configured specs are authoritative (WORKPLAN-REGISTRY.md decision 3). A registry
        // spec id is always '<slug>--v<n>', never a bare slug, so a non-null lookup on the
        // bare slug can only be a YAML spec.
        if (specProvider.getSpec(slug) != null) {
            throw conflict("'" + slug + "' is a configured spec id and is owned by the "
                + "administrator; registry content cannot shadow it");
        }
        if (repository.slugExists(slug)) {
            throw conflict("content '" + slug + "' already exists");
        }

        // The slugExists check above is advisory: two concurrent creates both pass it and the
        // unique constraint decides. Mapping that violation here is what makes 409 the documented
        // answer in both cases rather than a 500 for whoever loses the race.
        try {
            jdbc.update("INSERT INTO skald.content (slug, owner, type, visibility) VALUES (?, ?, ?, ?)",
                slug, owner, type, visibility);
        } catch (DataIntegrityViolationException e) {
            throw conflict("content '" + slug + "' already exists");
        }
        audit("content.create", slug, Map.of("owner", owner, "type", type, "visibility", visibility));

        return findSummary(slug);
    }

    /**
     * Adds a version and, unless told otherwise, makes it the active one.
     *
     * <p>The version number is assigned here rather than accepted from the caller. Letting a
     * client choose it buys nothing — rollback names an existing version through
     * {@link #activate} — and costs a class of conflicts and gaps to validate against.
     */
    @Transactional
    public ContentSummary addVersion(String slug, AddVersionRequest request) {
        ContentSummary existing = requireContent(slug);
        String image = require(request.image(), "image");

        // Serialise version allocation for this content item. Without the lock, two concurrent
        // adds both read the same max(version) and the second violates content_version_unique;
        // the caller saw a 500 rather than anything meaningful. Locking the content row is
        // enough because every allocation for this item goes through it.
        jdbc.queryForObject("SELECT id::text FROM skald.content WHERE slug = ? FOR UPDATE",
            String.class, slug);

        Integer version = jdbc.queryForObject("""
            SELECT COALESCE(max(v.version), 0) + 1 FROM skald.content_version v
            JOIN skald.content c ON c.id = v.content_id WHERE c.slug = ?
            """, Integer.class, slug);

        try {
            jdbc.update("""
                INSERT INTO skald.content_version (content_id, version, image, created_by)
                SELECT id, ?, ?, ? FROM skald.content WHERE slug = ?
                """, version, image, actor(), slug);
        } catch (DataIntegrityViolationException e) {
            // Belt to the row lock's braces: if allocation ever races anyway, the caller gets
            // the documented conflict rather than an unrecoverable error.
            throw conflict("version " + version + " of '" + slug + "' already exists");
        }
        audit("content.version.add", slug, Map.of("version", String.valueOf(version), "image", image));

        if (!Boolean.FALSE.equals(request.activate())) {
            setActiveVersion(slug, version);
        }
        return findSummary(existing.slug());
    }

    /** Activation and rollback are the same operation: point at a version that already exists. */
    @Transactional
    public ContentSummary activate(String slug, ActivateRequest request) {
        requireContent(slug);
        if (request.version() == null) {
            throw bad("version is required");
        }
        Integer exists = jdbc.queryForObject("""
            SELECT count(*) FROM skald.content_version v
            JOIN skald.content c ON c.id = v.content_id WHERE c.slug = ? AND v.version = ?
            """, Integer.class, slug, request.version());
        if (exists == null || exists == 0) {
            throw notFound("content '" + slug + "' has no version " + request.version());
        }

        setActiveVersion(slug, request.version());
        return findSummary(slug);
    }

    /**
     * Deletes content, refusing while any of its versions still has a live proxy.
     *
     * <p>{@code content_version} is {@code ON DELETE CASCADE} from {@code content}, so this
     * would otherwise make the running proxy's spec unresolvable — and a proxy whose spec does
     * not resolve vanishes from its own owner's list, because
     * {@code ProxyService.getUserProxies} filters through {@code canAccess}. Task 6 proved that
     * by deleting the row under a running container.
     */
    @Transactional
    public void delete(String slug) {
        requireContent(slug);

        List<String> live = liveSpecIds(slug);
        if (!live.isEmpty()) {
            throw conflict("content '" + slug + "' still has running apps (" + String.join(", ", live)
                + "); stop them before deleting, or their owners would lose sight of them");
        }

        jdbc.update("DELETE FROM skald.content WHERE slug = ?", slug);
        audit("content.delete", slug, Map.of());

        // Re-check before committing. A proxy can start between the check above and here, and
        // no database lock can prevent that -- proxy state lives in ContainerProxy's store, not
        // in PostgreSQL, so a row lock on content would serialise nothing. Re-checking inside
        // the transaction turns "delete wins the race" into "delete loses it", which is the
        // right way round: the residual window is between this check and the commit, and the
        // cost of losing that one is a spurious 409 rather than a stranded container.
        List<String> startedMeanwhile = liveSpecIds(slug);
        if (!startedMeanwhile.isEmpty()) {
            throw conflict("content '" + slug + "' had an app start while it was being deleted ("
                + String.join(", ", startedMeanwhile) + "); nothing was deleted, try again");
        }
    }

    // ------------------------------------------------------------------ internals

    /** Spec ids of this content's versions that currently have a proxy, in any state. */
    private List<String> liveSpecIds(String slug) {
        Set<String> ids = Set.copyOf(jdbc.queryForList("""
            SELECT ? || '--v' || v.version FROM skald.content_version v
            JOIN skald.content c ON c.id = v.content_id WHERE c.slug = ?
            """, String.class, slug, slug));

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
     * change to what users are served — unrecorded. The audit trail follows the state change.
     */
    private void setActiveVersion(String slug, int version) {
        jdbc.update("""
            UPDATE skald.content c SET active_version_id = v.id, updated_at = now()
            FROM skald.content_version v
            WHERE v.content_id = c.id AND v.version = ? AND c.slug = ?
            """, version, slug);
        audit("content.activate", slug, Map.of("version", String.valueOf(version)));
    }

    private ContentSummary requireContent(String slug) {
        ContentSummary summary = findSummary(slug);
        if (summary == null) {
            throw notFound("no content with slug '" + slug + "'");
        }
        return summary;
    }

    private ContentSummary findSummary(String slug) {
        return list().stream().filter(c -> c.slug().equals(slug)).findFirst().orElse(null);
    }

    private static List<Integer> versions(java.sql.Array array) throws java.sql.SQLException {
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
     * Append-only record of every mutation. The table has existed since task 2 and nothing has
     * written to it; filling it in as the write path is built is far cheaper than retrofitting
     * an audit trail over endpoints that already ship (CLAUDE.md security invariants).
     */
    private void audit(String action, String slug, Map<String, String> detail) {
        String json;
        try {
            json = objectMapper.writeValueAsString(detail);
        } catch (JsonProcessingException e) {
            // Serialising a Map<String,String> cannot fail, but losing the mutation because the
            // audit row could not be written would be worse than losing the detail.
            json = "{}";
        }

        jdbc.update("""
            INSERT INTO skald.audit_event (actor, action, subject_type, subject_id, detail_json)
            VALUES (?, ?, 'content', ?, ?::jsonb)
            """, actor(), action, slug, json);
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
