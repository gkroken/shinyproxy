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

import eu.openanalytics.containerproxy.ContainerProxyApplication;
import eu.openanalytics.containerproxy.backend.dispatcher.ProxyDispatcherService;
import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.test.helpers.ShinyProxyClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;

/**
 * The load-bearing test for ADR-0001.
 *
 * <p>ContainerProxy registers proxy dispatchers once, in a {@code @PostConstruct}. If that
 * cannot be worked around from outside the jar, a database-backed spec provider is
 * impossible without forking ContainerProxy, and the whole plan changes shape. This test is
 * the evidence that it can.
 *
 * <p>It is an integration test on purpose. Asserting that {@code getDispatcher()} returns
 * non-null would pass against a broken system; what matters is that a spec which did not
 * exist at startup actually starts a container and serves traffic through the proxy.
 *
 * <p>It also boots its own application context rather than using
 * {@code ShinyProxyInstance}. That helper always adds
 * {@code ShinyProxyInstance.TestConfiguration}, which substitutes its own
 * {@code proxyDispatcherService} through a {@code @Primary @Bean} — a factory-method
 * definition that {@link DispatcherOverrideRegistrar} deliberately steps aside for. Booting
 * through the helper would therefore test the harness instead of the product. This context
 * is wired exactly as production is.
 */
public class LazyProxyDispatcherServiceTest {

    private static final String BOOT_SPEC_ID = "boot-spec";
    private static final String RUNTIME_SPEC_ID = "runtime-added";

    // Distinct from the 7583 that ShinyProxyInstance-based tests use.
    private static final int PORT = 7585;

    private static ConfigurableApplicationContext app;
    private static ShinyProxyClient client;

    @BeforeAll
    public static void beforeAll() {
        SpringApplication application = new SpringApplication(ContainerProxyApplication.class);
        Properties properties = ContainerProxyApplication.getDefaultProperties();
        properties.put("spring.config.location", "src/test/resources/application-test-registry.yml");
        properties.put("server.port", PORT);
        properties.put("management.server.port", PORT % 1000 + 9000);
        application.setDefaultProperties(properties);

        app = application.run();
        client = new ShinyProxyClient("demo", PORT);
    }

    @AfterAll
    public static void afterAll() {
        if (app != null) {
            app.stop();
            app.close();
        }
    }

    @Test
    public void specAddedAfterStartupStartsAndServes() {
        ProxyDispatcherService dispatcherService = app.getBean("proxyDispatcherService", ProxyDispatcherService.class);
        Assertions.assertInstanceOf(LazyProxyDispatcherService.class, dispatcherService,
            "the dispatcher override was not installed -- DispatcherOverrideRegistrar did not retarget the bean");

        ShinyProxySpecProvider specProvider = app.getBean("shinyProxySpecProvider", ShinyProxySpecProvider.class);

        // Preconditions. If this spec were already known, the rest of the test would be
        // exercising the ordinary startup-registered path and would prove nothing.
        Assertions.assertNull(specProvider.getSpec(RUNTIME_SPEC_ID),
            RUNTIME_SPEC_ID + " must not exist at startup");
        Assertions.assertNotNull(dispatcherService.getDispatcher(BOOT_SPEC_ID),
            "the spec present at startup should still have its dispatcher");

        addSpecAfterStartup(specProvider, RUNTIME_SPEC_ID);

        // Upstream returns null here, and that null is what NPEs at 14 call sites in
        // ProxyService.
        Assertions.assertNotNull(dispatcherService.getDispatcher(RUNTIME_SPEC_ID),
            "no dispatcher for a spec added after startup");

        // The part that actually matters: a real container, reached through the proxy.
        String proxyId = client.startProxy(RUNTIME_SPEC_ID);
        Assertions.assertNotNull(proxyId);
        client.testProxyReachable(proxyId);
        client.stopProxy(proxyId);
    }

    /**
     * Adds a spec to the running application, simulating what the database-backed spec
     * provider will do natively in the rest of spine #1.
     *
     * <p>Reflection is used because {@code ShinyProxySpecProvider} is configuration-bound and
     * has no runtime-add path: {@code setSpecs()} replaces the list but does not touch
     * {@code specsMap}, so {@code getSpec(id)} would keep returning null. Both are updated
     * here so the provider is internally consistent, which is the state the real provider
     * will present.
     */
    @SuppressWarnings("unchecked")
    private static void addSpecAfterStartup(ShinyProxySpecProvider specProvider, String specId) {
        ProxySpec runtimeSpec = specProvider.getSpec(BOOT_SPEC_ID).toBuilder().id(specId).build();
        runtimeSpec.setContainerIndex();

        try {
            Field specsField = ShinyProxySpecProvider.class.getDeclaredField("specs");
            specsField.setAccessible(true);
            List<ProxySpec> updated = new ArrayList<>((List<ProxySpec>) specsField.get(specProvider));
            updated.add(runtimeSpec);
            specsField.set(specProvider, updated);

            Field specsMapField = ShinyProxySpecProvider.class.getDeclaredField("specsMap");
            specsMapField.setAccessible(true);
            ((Map<String, ProxySpec>) specsMapField.get(specProvider)).put(specId, runtimeSpec);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("could not add a spec after startup", e);
        }
    }

}
