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
package eu.openanalytics.shinyproxy.publisher.registry;

import eu.openanalytics.containerproxy.backend.dispatcher.proxysharing.ProxySharingSpecExtension;
import eu.openanalytics.containerproxy.backend.ecs.EcsSpecExtension;
import eu.openanalytics.containerproxy.backend.kubernetes.KubernetesSpecExtension;
import eu.openanalytics.containerproxy.model.spec.AccessControl;
import eu.openanalytics.containerproxy.model.spec.ContainerSpec;
import eu.openanalytics.containerproxy.model.spec.PortMapping;
import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.spec.expression.SpelField;
import eu.openanalytics.containerproxy.model.spec.ISpecExtension;
import eu.openanalytics.shinyproxy.ShinyProxySpecExtension;
import eu.openanalytics.shinyproxy.external.ExternalAppSpecExtension;
import eu.openanalytics.containerproxy.service.ProxyService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads published content out of the registry and projects it into ContainerProxy
 * {@link ProxySpec}s.
 *
 * <p>Spec ids are {@code <slug>--v<n>} (WORKPLAN-REGISTRY.md decision 4). {@code getSpecs()}
 * returns only each item's <em>active</em> version, which is what the index lists;
 * {@link #findSpec} resolves <em>any</em> version, because ContainerProxy re-resolves the
 * spec of a running proxy when stopping it and a superseded version must stay resolvable
 * while its containers live (ADR-0008).
 */
@Repository
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentSpecRepository {

    /**
     * The inverse of {@code c<content.id as 32 hex>--v<n>}. Anchored, and the version is
     * bounded, so a spec id that merely contains "--v" cannot be coerced into a lookup.
     *
     * <p>The id is derived from the content UUID, not from anything a publisher can set. That
     * is what makes it unique over time: deleting content and re-creating it at the same path
     * produces a different UUID and therefore a different spec id, so the new content cannot
     * inherit anything keyed on the old one — including ContainerProxy's per-session
     * authorization cache, which has no invalidation path and previously handed a revoked user
     * access to whatever next occupied the id.
     */
    private static final Pattern SPEC_ID = Pattern.compile("^c([0-9a-f]{32})--v([1-9][0-9]{0,8})$");

    private static final int DEFAULT_PORT = 3838;

    /**
     * Aggregates {@code content_acl} into two arrays alongside the content row, so that
     * listing every spec stays one round trip instead of one per item.
     *
     * <p>{@code array_agg} is ordered so the projected {@link AccessControl} — and therefore
     * the spec fingerprint below — is stable across calls; without it PostgreSQL may return
     * the principals in any order and every request would look like a change.
     *
     * <p>No filter on {@code permission}: {@code viewer} and {@code editor} both grant the
     * right to open the content, and differ only in what the holder may change.
     */
    private static final String ACL_JOIN = """
        LEFT JOIN LATERAL (
            SELECT array_agg(a.principal ORDER BY a.principal)
                     FILTER (WHERE a.principal_type = 'user')  AS acl_users,
                   array_agg(a.principal ORDER BY a.principal)
                     FILTER (WHERE a.principal_type = 'group') AS acl_groups
            FROM skald.content_acl a
            WHERE a.content_id = c.id
        ) acl ON TRUE
        """;

    private static final String SELECT_COLUMNS =
        "SELECT c.id, c.title, c.owner, c.type, c.visibility, v.version, v.image, v.spec_json, " +
            "acl.acl_users, acl.acl_groups, (v.id = c.active_version_id) AS is_active ";

    private static final String SELECT_ACTIVE = SELECT_COLUMNS + """
        FROM skald.content c
        JOIN skald.content_version v ON v.id = c.active_version_id
        """ + ACL_JOIN;

    private static final String SELECT_ONE = SELECT_COLUMNS + """
        FROM skald.content c
        JOIN skald.content_version v ON v.content_id = c.id
        """ + ACL_JOIN + """
        WHERE c.id = ? AND v.version = ?
        """;

    private final JdbcTemplate jdbc;

    /**
     * Built {@link ProxySpec}s, so that repeated lookups of unchanged content return the
     * <em>same instance</em>.
     *
     * <p>This is a correctness requirement, not an optimisation. ShinyProxy builds view-model
     * maps keyed by {@code ProxySpec} objects — {@code IndexController} keys
     * {@code openSwitchInstanceInsteadOfApp}, {@code appUrl} and {@code cleanDescription} by
     * the specs from one {@code getUserSpecs()} call, while {@code BaseController.prepareMap}
     * (line 191) calls {@code getUserSpecs()} again and puts <em>those</em> objects in the
     * model as {@code apps}. The template then looks the first maps up by the second call's
     * objects. That only works if both calls return equal specs, and {@code ProxySpec}'s
     * generated {@code equals} delegates to {@code AccessControl}, which defines no
     * {@code equals} and so compares by identity. A provider that rebuilds specs per call
     * therefore renders a null into a boolean expression and the index page 500s.
     *
     * <p>Entries are rebuilt when the underlying row changes, detected by fingerprint. The map
     * is bounded by the number of distinct content versions resolved since startup.
     */
    private final Map<String, CachedSpec> specCache = new ConcurrentHashMap<>();

    private record CachedSpec(String fingerprint, ProxySpec spec) {
    }

    private final ObjectProvider<ProxyService> proxyService;

    public ContentSpecRepository(JdbcTemplate jdbc, ObjectProvider<ProxyService> proxyService) {
        this.jdbc = jdbc;
        this.proxyService = proxyService;
    }

    /** The active version of every content item, as ProxySpecs. */
    public List<ProxySpec> findActiveSpecs() {
        return jdbc.query(SELECT_ACTIVE, specRowMapper());
    }

    /**
     * The active version, or a superseded one that still has live proxies. Null otherwise.
     *
     * <p>ADR-0008 requires superseded versions to stay resolvable "while their containers live",
     * and both halves of that matter. Resolving them is what keeps a running container visible
     * to its owner across an activate and a rollback. <b>Not</b> resolving them once nothing is
     * running is what keeps activation meaningful: without this condition, any permitted user
     * could start any historical version forever from a bookmarked {@code /app/<slug>--v<n>}
     * URL, so publishing a fix would never retire the version it fixed. Verified against the
     * live stack before this condition existed — v1 was absent from the index and still started
     * a container.
     *
     * <p>The active version short-circuits before the proxy store is consulted, so the hot path
     * — every {@code canAccess} call resolves a spec — costs nothing extra.
     */
    public ProxySpec findSpec(String specId) {
        if (specId == null) {
            return null;
        }
        Matcher matcher = SPEC_ID.matcher(specId);
        if (!matcher.matches()) {
            return null;
        }
        List<ResolvedSpec> found = jdbc.query(SELECT_ONE,
            (ResultSet rs, int rowNum) -> new ResolvedSpec(rs.getBoolean("is_active"), toProxySpec(rs)),
            uuidOf(matcher.group(1)), Integer.parseInt(matcher.group(2)));

        if (found.isEmpty()) {
            return null;
        }
        ResolvedSpec resolved = found.get(0);
        if (resolved.active()) {
            return resolved.spec();
        }
        return hasLiveProxy(specId) ? resolved.spec() : null;
    }

    private record ResolvedSpec(boolean active, ProxySpec spec) {
    }

    /**
     * Whether any proxy currently references this spec id, in any state.
     *
     * <p>{@code ObjectProvider} rather than a direct injection because {@code ProxyService}
     * depends on the spec provider, which depends on this repository. Deferring the lookup to
     * call time breaks the construction cycle; a failure to resolve it is treated as "nothing
     * is running", which is the fail-closed answer and can only happen before the context is
     * ready, when there are no user requests to serve anyway.
     */
    private boolean hasLiveProxy(String specId) {
        try {
            ProxyService proxyService = this.proxyService.getIfAvailable();
            if (proxyService == null) {
                return false;
            }
            return proxyService.getAllProxies().stream()
                .anyMatch(proxy -> specId.equals(proxy.getSpecId()));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private RowMapper<ProxySpec> specRowMapper() {
        return (ResultSet rs, int rowNum) -> toProxySpec(rs);
    }

    private ProxySpec toProxySpec(ResultSet rs) throws SQLException {
        UUID contentId = (UUID) rs.getObject("id");
        String title = rs.getString("title");
        int version = rs.getInt("version");
        String specId = specId(contentId, version);

        String[] aclUsers = principals(rs, "acl_users");
        String[] aclGroups = principals(rs, "acl_groups");

        // The ACL is part of the fingerprint: granting or revoking a principal must produce a
        // NEW ProxySpec instance, or the memoised one below would keep serving the old
        // AccessControl and a revocation would never reach the evaluator at all.
        String fingerprint = String.join("\u0000",
            contentId.toString(), title, rs.getString("owner"), rs.getString("type"),
            rs.getString("visibility"), String.valueOf(version), rs.getString("image"),
            String.join(",", aclUsers), String.join(",", aclGroups));

        CachedSpec cached = specCache.get(specId);
        if (cached != null && cached.fingerprint().equals(fingerprint)) {
            return cached.spec();
        }

        ContainerSpec containerSpec = ContainerSpec.builder()
            .image(new SpelField.String(rs.getString("image")))
            .portMapping(Collections.singletonList(
                PortMapping.builder().name("default").port(DEFAULT_PORT).build()))
            .build();

        ProxySpec spec = ProxySpec.builder()
            .id(specId)
            // The publisher's title, not the path: the index lists display names, and showing
            // a URL fragment where an app name belongs reads as a bug.
            .displayName(title)
            .accessControl(AccessControlProjector.project(
                title, rs.getString("visibility"), rs.getString("owner"), aclUsers, aclGroups))
            .containerSpecs(Collections.singletonList(containerSpec))
            .build();

        // ShinyProxy indexes containers by position and will NPE later without this.
        spec.setContainerIndex();

        addDefaultSpecExtensions(spec, specId);

        specCache.put(specId, new CachedSpec(fingerprint, spec));
        return spec;
    }

    /**
     * Reads one of the aggregated {@code content_acl} arrays.
     *
     * <p>Returns an empty array rather than null for content with no ACL rows, so that
     * {@link AccessControlProjector} never has to distinguish "no grants" from "column
     * absent" — the two mean the same thing and only one of them should exist in code.
     */
    private static String[] principals(ResultSet rs, String column) throws SQLException {
        Array array = rs.getArray(column);
        if (array == null) {
            return new String[0];
        }
        try {
            String[] values = (String[]) array.getArray();
            return (values == null) ? new String[0] : values;
        } finally {
            array.free();
        }
    }

    /**
     * Attaches an empty instance of every spec extension that is dereferenced without a null
     * check.
     *
     * <p>This is not belt-and-braces. {@code ProxySpec.getSpecExtension()} returns null when
     * the extension is absent, and the callers below do not check:
     *
     * <ul>
     *   <li>{@code ShinyProxySpecExtension} — {@code Thymeleaf}, {@code IssueController} and
     *       five methods on {@code ShinyProxySpecProvider}, including {@code getMaxInstances}
     *       and {@code getRuntimeValues}.</li>
     *   <li>{@code ExternalAppSpecExtension} — {@code Thymeleaf.getExternalUrl} (so the index
     *       page fails to render) and {@code AppController}.</li>
     *   <li>{@code ProxySharingSpecExtension} — {@code ProxySharingDispatcher.supportSpec},
     *       which is consulted on the dispatcher path for every proxy.</li>
     * </ul>
     *
     * <p>Every instance is built empty, so each value falls back to the same default a YAML
     * spec with nothing configured would get. Leaving {@code minimumSeatsAvailable} unset is
     * also what makes registry content structurally incapable of requesting proxy sharing,
     * which {@code LazyProxyDispatcherService} refuses for runtime-added specs
     * (WORKPLAN-REGISTRY.md decision 2).
     *
     * <p>{@code MergedSpecProviderTest} asserts that registry specs carry every extension a
     * configured spec carries, so an extension added upstream fails the build rather than a
     * page render. That test is how the Kubernetes and ECS entries below were found.
     */
    private void addDefaultSpecExtensions(ProxySpec spec, String specId) {
        // NOT ShinyProxySpecExtension.builder().build(). Lombok's @Builder ignores a field
        // initialiser unless @Builder.Default is present, and only `maxInstances` has it -- so
        // a built extension leaves `customAppDetails` and `templateProperties` NULL where a
        // YAML-configured spec gets empty collections. `getRuntimeValues` then does
        // `new CustomAppDetails(null)` -> `new ArrayList<>(null)` -> NPE, which took down
        // every start through AppController and AppDirectController, not only /c/<path>.
        // Setting them explicitly is what actually delivers "the same default a YAML spec with
        // nothing configured would get"; the builder alone only looked like it did.
        addSpecExtension(spec, specId, ShinyProxySpecExtension.builder()
            .customAppDetails(new ArrayList<>())
            .templateProperties(new HashMap<>())
            .build());
        addSpecExtension(spec, specId, ExternalAppSpecExtension.builder().build());
        addSpecExtension(spec, specId, ProxySharingSpecExtension.builder().build());

        // Not reachable on the Docker backend v1 targets, but KubernetesBackend and
        // EcsBackend dereference these the same way. Attaching them empty costs nothing and
        // is exactly what a configured spec with no backend-specific settings gets, so
        // enabling another backend later cannot turn registry content into an NPE.
        addSpecExtension(spec, specId, KubernetesSpecExtension.builder().build());
        addSpecExtension(spec, specId, EcsSpecExtension.builder().build());
    }

    private void addSpecExtension(ProxySpec spec, String specId, ISpecExtension extension) {
        extension.setId(specId);
        spec.addSpecExtension(extension);
    }

    /**
     * This content's live path, as the publisher capitalised it, or empty if it has none.
     *
     * <p>A singleton list rather than a nullable string because the caller's next move is a
     * redirect it must not attempt when there is nothing to redirect to. Exactly one row can
     * qualify: {@code content_path_one_current} is a unique index over {@code content_id}
     * filtered on {@code is_current}.
     */
    public List<String> findCurrentPath(UUID contentId) {
        return jdbc.queryForList("""
            SELECT path FROM skald.content_path
            WHERE content_id = ? AND is_current
            """, String.class, contentId);
    }

    /**
     * The spec id of this content's active version, or null if it has none yet.
     *
     * <p>Resolved per request rather than cached. That is what makes a publisher's URL
     * version-independent: activating a new version or rolling back moves
     * {@code active_version_id}, and the next request through {@code /c/<path>} picks it up
     * with nothing to invalidate. Content created but never versioned answers null, which the
     * serving layer reports as 404 — the path is claimed, but there is nothing to serve.
     */
    public String findActiveSpecId(UUID contentId) {
        List<String> found = jdbc.query("""
            SELECT v.version FROM skald.content c
            JOIN skald.content_version v ON v.id = c.active_version_id
            WHERE c.id = ?
            """, (rs, rowNum) -> specId(contentId, rs.getInt("version")), contentId);
        return found.isEmpty() ? null : found.get(0);
    }

    /**
     * {@code c<32 hex>--v<n>}. 45 characters at most, inside the 63-character Kubernetes label
     * limit, and starting with a letter so it is a valid label value on every backend.
     */
    public static String specId(UUID contentId, int version) {
        return "c" + contentId.toString().replace("-", "") + "--v" + version;
    }

    /** The inverse, for callers that hold a spec id and need the content it belongs to. */
    public static UUID contentIdOf(String specId) {
        Matcher matcher = SPEC_ID.matcher(specId == null ? "" : specId);
        if (!matcher.matches()) {
            return null;
        }
        return uuidOf(matcher.group(1));
    }

    private static UUID uuidOf(String hex32) {
        return UUID.fromString(hex32.substring(0, 8) + "-" + hex32.substring(8, 12) + "-"
            + hex32.substring(12, 16) + "-" + hex32.substring(16, 20) + "-" + hex32.substring(20));
    }

}
