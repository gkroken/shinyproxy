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
package eu.openanalytics.shinyproxy.publisher.dispatch;

import eu.openanalytics.containerproxy.backend.dispatcher.DefaultProxyDispatcher;
import eu.openanalytics.containerproxy.backend.dispatcher.IProxyDispatcher;
import eu.openanalytics.containerproxy.backend.dispatcher.ProxyDispatcherService;
import eu.openanalytics.containerproxy.backend.dispatcher.proxysharing.ProxySharingDispatcher;
import eu.openanalytics.containerproxy.backend.dispatcher.proxysharing.store.IProxySharingStoreFactory;
import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.spec.IProxySpecProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Makes {@link ProxyDispatcherService} tolerate specs that did not exist at startup.
 *
 * <p>Upstream's {@code init()} is {@code @PostConstruct}: it enumerates {@code getSpecs()}
 * exactly once and registers a dispatcher per spec. {@code getDispatcher(specId)} therefore
 * returns {@code null} for anything added later, and {@code ProxyService} calls it at 14
 * sites covering start, stop, pause, resume and health checks. A database-backed spec
 * provider on its own would NPE the first time a user opened runtime-added content.
 *
 * <p>This subclass changes only the {@code null} case. Specs present at startup keep
 * whatever dispatcher upstream registered for them — including proxy-sharing dispatchers —
 * so no existing configuration changes behaviour.
 *
 * <p>Runtime-added specs get {@link DefaultProxyDispatcher}, which is correct for every
 * content type the registry ships. A runtime spec that asks for proxy sharing is rejected
 * loudly instead: see {@link #rejectIfProxySharing}.
 */
public class LazyProxyDispatcherService extends ProxyDispatcherService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    // Every field on the parent is private, so we keep our own references rather than
    // reaching through super.
    private final IProxySpecProvider proxySpecProvider;
    private final DefaultProxyDispatcher defaultProxyDispatcher;

    private final Set<String> loggedSpecIds = ConcurrentHashMap.newKeySet();

    public LazyProxyDispatcherService(IProxySpecProvider proxySpecProvider,
                                      IProxySharingStoreFactory storeFactory,
                                      ConfigurableListableBeanFactory beanFactory,
                                      DefaultProxyDispatcher defaultProxyDispatcher) {
        super(proxySpecProvider, storeFactory, beanFactory, defaultProxyDispatcher);
        this.proxySpecProvider = proxySpecProvider;
        this.defaultProxyDispatcher = defaultProxyDispatcher;
    }

    @Override
    public IProxyDispatcher getDispatcher(String specId) {
        IProxyDispatcher dispatcher = super.getDispatcher(specId);
        if (dispatcher != null) {
            return dispatcher;
        }

        rejectIfProxySharing(specId);

        // This is a hot path -- 14 call sites, some per-request -- so log once per spec.
        if (loggedSpecIds.add(specId)) {
            logger.debug("No dispatcher was registered at startup for spec '{}'; " +
                "using the default dispatcher.", specId);
        }
        return defaultProxyDispatcher;
    }

    /**
     * A proxy-sharing dispatcher is not just an object: upstream's {@code init()} also
     * builds a {@code ProxySharingScaler}, registers two Spring singletons per spec, and
     * adds the scaler to a private {@code closeables} list drained by {@code @PreDestroy}.
     * None of that can be conjured here.
     *
     * <p>So we fail loudly rather than quietly handing back a non-sharing dispatcher.
     * Silent degradation is already the failure mode of upstream's startup-bound metrics
     * ({@code Micrometer} registers per-spec meters once, so runtime-added content gets
     * none, with no error). One of those is enough.
     */
    private void rejectIfProxySharing(String specId) {
        ProxySpec spec = proxySpecProvider.getSpec(specId);
        if (spec != null && ProxySharingDispatcher.supportSpec(spec)) {
            throw new IllegalStateException(String.format(
                "Spec '%s' requests proxy sharing but was not present at startup. " +
                    "Proxy sharing is not supported for runtime-added content; define this " +
                    "spec in the application configuration instead.", specId));
        }
    }

}
