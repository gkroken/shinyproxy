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
import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;

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

    @Override
    public List<ProxySpec> getSpecs() {
        List<ProxySpec> configured = super.getSpecs();

        ContentSpecRepository repo = repositoryOrNull();
        if (repo == null) {
            return configured;
        }

        List<ProxySpec> merged = new ArrayList<>(configured);
        for (ProxySpec candidate : repo.findActiveSpecs()) {
            if (super.getSpec(candidate.getId()) != null) {
                logger.error("Registry content '{}' collides with a configured spec of the same " +
                    "id and is being ignored. Configured specs are authoritative; this row " +
                    "should have been rejected when it was created.", candidate.getId());
                continue;
            }
            merged.add(candidate);
        }
        return merged;
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
     * Null until the context is far enough along to resolve the repository. The parent's
     * {@code @PostConstruct} calls {@link #getSpec} while binding spec extensions, which can
     * run before this bean's dependencies are resolvable; at that point only configured specs
     * exist anyway, so answering from the parent alone is correct rather than merely safe.
     */
    private ContentSpecRepository repositoryOrNull() {
        return (repository == null) ? null : repository.getIfAvailable();
    }

}
