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

import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.service.UserService;
import eu.openanalytics.containerproxy.spec.expression.SpecExpressionContext;
import eu.openanalytics.containerproxy.spec.expression.SpecExpressionResolver;
import eu.openanalytics.shinyproxy.ShinyProxySpecExtension;
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves YAML-configured specs and registry content through one provider.
 *
 * <p><b>Why a subclass rather than a second {@code IProxySpecProvider}.</b> ContainerProxy
 * injects the interface, so a sibling {@code @Primary} bean would satisfy <em>it</em> — but
 * ShinyProxy's own {@code IndexController}, {@code BaseController} and {@code Thymeleaf}
 * inject the <em>concrete</em> {@code ShinyProxySpecProvider} and call spec-keyed methods on
 * it. {@code getMaxInstances()} in particular builds its map by iterating
 * {@code ShinyProxySpecProvider.getSpecs()}, so registry content would be absent from it and
 * {@code BaseController.validateMaxInstances} would unbox a null {@code Integer} and throw.
 * Subclassing means both the interface and the concrete injection points see the same merged
 * view, with no upstream file modified.
 *
 * <p><b>YAML wins.</b> {@link #getSpec} consults the configured specs first, so a registry row
 * can never take over an id an administrator configured. Slug collisions are rejected when
 * content is created; the filter in {@link #getSpecs} is a second line of defence for a
 * collision that somehow reached the database, and it logs loudly rather than silently
 * picking a winner.
 */
public class MergedSpecProvider extends ShinyProxySpecProvider {

    /**
     * Duplicated from {@code ShinyProxySpecProvider}, where it is private. Widening it there
     * would be a diff against an upstream file for one string; if it ever diverges, the
     * {@code registryContentGetsTheConfiguredDefaultMaxInstances} test fails.
     */
    private static final String PROP_DEFAULT_MAX_INSTANCES = "proxy.default-max-instances";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * An ObjectProvider, not a direct injection: the repository only exists when a DataSource
     * is configured, and without one this class must behave exactly like its parent.
     */
    private ObjectProvider<ContentSpecRepository> repository;

    @Autowired
    public void setRepository(ObjectProvider<ContentSpecRepository> repository) {
        this.repository = repository;
    }

    /**
     * The parent holds these too, but privately, and {@link #getMaxInstances()} has to
     * reproduce its calculation for registry specs. They are injected again rather than the
     * parent's fields being widened, so the diff against upstream stays at zero.
     *
     * <p>The setter is deliberately not named {@code setEnvironment}: the parent already has
     * one, and it assigns a private <em>static</em> field that its {@code @PostConstruct}
     * depends on. Overriding it would break that.
     */
    private SpecExpressionResolver specExpressionResolver;
    private UserService skaldUserService;
    private Environment skaldEnvironment;

    @Autowired
    public void setSpecExpressionResolver(SpecExpressionResolver specExpressionResolver) {
        this.specExpressionResolver = specExpressionResolver;
    }

    @Autowired
    public void setSkaldUserService(@Lazy UserService userService) {
        this.skaldUserService = userService;
    }

    @Autowired
    public void setSkaldEnvironment(Environment environment) {
        this.skaldEnvironment = environment;
    }

    @Override
    public List<ProxySpec> getSpecs() {
        List<ProxySpec> merged = new ArrayList<>(super.getSpecs());
        merged.addAll(registrySpecs());
        return merged;
    }

    /**
     * The active registry specs that are safe to serve, with any that collide with a
     * configured spec id filtered out and logged.
     *
     * <p>Extracted so {@link #getSpecs()} and {@link #getMaxInstances()} cannot disagree about
     * which rows exist: if the max-instances map contained an entry for a colliding id it
     * would overwrite the configured spec's own limit.
     */
    private List<ProxySpec> registrySpecs() {
        ContentSpecRepository repo = repositoryOrNull();
        if (repo == null) {
            return List.of();
        }

        List<ProxySpec> usable = new ArrayList<>();
        for (ProxySpec candidate : repo.findActiveSpecs()) {
            if (super.getSpec(candidate.getId()) != null) {
                logger.error("Registry content '{}' collides with a configured spec of the same " +
                    "id and is being ignored. Configured specs are authoritative; this row " +
                    "should have been rejected when it was created.", candidate.getId());
                continue;
            }
            usable.add(candidate);
        }
        return usable;
    }

    @Override
    public ProxySpec getSpec(String id) {
        // Configured specs are authoritative.
        ProxySpec configured = super.getSpec(id);
        if (configured != null) {
            return configured;
        }

        ContentSpecRepository repo = repositoryOrNull();
        return (repo == null) ? null : repo.findSpec(id);
    }

    /**
     * Re-resolves the max-instances limit for registry content on every call.
     *
     * <p><b>Why this override exists.</b> The parent caches the whole map per <em>session</em>
     * for 60 minutes, on the stated assumption that "this never changes during the lifetime of
     * a session" ({@code ShinyProxySpecProvider.java:99-105}). That is true of YAML specs,
     * which are fixed at boot, and false the moment content can be published at runtime:
     * anything created after a user's session started is missing from that session's cached
     * map, so {@code getMaxInstancesForSpec} returns null and
     * {@code BaseController.validateMaxInstances} throws on unboxing it. The user-visible
     * shape is "my new app doesn't work until I log out", which gets reported as flakiness
     * rather than as a cache (WORKPLAN-REGISTRY.md risk 4).
     *
     * <p><b>What it does.</b> The parent's cache is left alone — it is still correct for the
     * specs it was designed for — and the registry portion of the map is recomputed and
     * overlaid on every call. Entries the parent cached for registry specs are overwritten
     * rather than trusted, so a stale value cannot survive either.
     *
     * <p>The recomputation is not itself cached. It costs one query against the already
     * memoised {@code ContentSpecRepository} plus one SpEL evaluation of the default, which is
     * cheaper than any scheme that would have to work out when to invalidate — and being
     * always-fresh is the entire point of the method.
     */
    @Override
    public Map<String, Integer> getMaxInstances() {
        Map<String, Integer> configured = super.getMaxInstances();

        List<ProxySpec> registrySpecs = registrySpecs();
        if (registrySpecs.isEmpty()) {
            return configured;
        }

        // The parent dereferences the current authentication without checking; on a cache hit
        // it never looks, so this method must not be the one that starts throwing.
        Authentication user = (skaldUserService == null) ? null : skaldUserService.getCurrentAuth();
        if (user == null || specExpressionResolver == null || skaldEnvironment == null) {
            return configured;
        }

        SpecExpressionContext context = SpecExpressionContext
            .create(user, user.getPrincipal(), user.getCredentials())
            .build();

        Integer resolvedDefault = specExpressionResolver.evaluateToInteger(
            skaldEnvironment.getProperty(PROP_DEFAULT_MAX_INSTANCES, String.class, "1"), context);

        Map<String, Integer> merged = new HashMap<>(configured);
        for (ProxySpec spec : registrySpecs) {
            // Always null today -- registry specs carry an empty ShinyProxySpecExtension -- but
            // written as the general case so that letting publishers set a limit later is a
            // change to the write path alone.
            Integer maxInstances = spec.getSpecExtension(ShinyProxySpecExtension.class)
                .getMaxInstances().resolve(specExpressionResolver, context).getValueOrNull();
            merged.put(spec.getId(), (maxInstances != null) ? maxInstances : resolvedDefault);
        }
        return merged;
    }

    /**
     * Null until the context is far enough along to resolve the repository. The parent's
     * {@code @PostConstruct} calls {@link #getSpec} while binding spec extensions, which can
     * run before this bean's dependencies are resolvable; at that point only configured specs
     * exist anyway, so answering from the parent alone is correct rather than merely safe.
     */
    private ContentSpecRepository repositoryOrNull() {
        return (repository == null) ? null : repository.getIfAvailable();
    }

}
