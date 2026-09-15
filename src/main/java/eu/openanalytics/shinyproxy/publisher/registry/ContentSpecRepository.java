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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
     * The inverse of {@code <slug>--v<n>}. Anchored, and the version is bounded, so a spec id
     * that merely contains "--v" cannot be coerced into a lookup.
     */
    private static final Pattern SPEC_ID = Pattern.compile("^([a-z0-9][a-z0-9-]{0,49})--v([1-9][0-9]{0,8})$");

    private static final int DEFAULT_PORT = 3838;

    private static final String SELECT_ACTIVE = """
        SELECT c.slug, c.owner, c.type, c.visibility, v.version, v.image, v.spec_json
        FROM skald.content c
        JOIN skald.content_version v ON v.id = c.active_version_id
        """;

    private static final String SELECT_ONE = """
        SELECT c.slug, c.owner, c.type, c.visibility, v.version, v.image, v.spec_json
        FROM skald.content c
        JOIN skald.content_version v ON v.content_id = c.id
        WHERE c.slug = ? AND v.version = ?
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

    public ContentSpecRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** The active version of every content item, as ProxySpecs. */
    public List<ProxySpec> findActiveSpecs() {
        return jdbc.query(SELECT_ACTIVE, specRowMapper());
    }

    /** Any version, active or superseded. Returns null when the id is not ours or not found. */
    public ProxySpec findSpec(String specId) {
        if (specId == null) {
            return null;
        }
        Matcher matcher = SPEC_ID.matcher(specId);
        if (!matcher.matches()) {
            return null;
        }
        List<ProxySpec> found = jdbc.query(SELECT_ONE, specRowMapper(),
            matcher.group(1), Integer.parseInt(matcher.group(2)));
        return found.isEmpty() ? null : found.get(0);
    }

    /** True when a content item with this slug exists, used to reject slug collisions on write. */
    public boolean slugExists(String slug) {
        Integer count = jdbc.queryForObject(
            "SELECT count(*) FROM skald.content WHERE slug = ?", Integer.class, slug);
        return count != null && count > 0;
    }

    private RowMapper<ProxySpec> specRowMapper() {
        return (ResultSet rs, int rowNum) -> toProxySpec(rs);
    }

    private ProxySpec toProxySpec(ResultSet rs) throws SQLException {
        String slug = rs.getString("slug");
        int version = rs.getInt("version");
        String specId = specId(slug, version);

        String fingerprint = String.join("\u0000",
            slug, rs.getString("owner"), rs.getString("type"), rs.getString("visibility"),
            String.valueOf(version), rs.getString("image"));

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
            .displayName(slug)
            .accessControl(accessControlFor(rs))
            .containerSpecs(Collections.singletonList(containerSpec))
            .build();

        // ShinyProxy indexes containers by position and will NPE later without this.
        spec.setContainerIndex();

        addDefaultSpecExtensions(spec, specId);

        specCache.put(specId, new CachedSpec(fingerprint, spec));
        return spec;
    }

    /**
     * Interim access control: the owner, and nobody else.
     *
     * <p>Full projection of {@code content_acl} and the visibility modes is task 5. Until then
     * this fails closed on purpose — an unfinished ACL layer that defaults to "visible" is how
     * content leaks, and a default of "owner only" cannot.
     */
    private AccessControl accessControlFor(ResultSet rs) throws SQLException {
        AccessControl accessControl = new AccessControl();
        accessControl.setUsers(new String[]{rs.getString("owner")});
        return accessControl;
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
        addSpecExtension(spec, specId, ShinyProxySpecExtension.builder().build());
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

    public static String specId(String slug, int version) {
        return slug + "--v" + version;
    }

}
