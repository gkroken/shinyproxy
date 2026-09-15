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

import eu.openanalytics.containerproxy.backend.dispatcher.ProxyDispatcherService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.stereotype.Component;

/**
 * Replaces upstream's {@code proxyDispatcherService} bean with
 * {@link LazyProxyDispatcherService}.
 *
 * <p>This is the single upstream override the project permits (ADR-0001). It is installed
 * by retargeting one bean definition rather than by enabling
 * {@code spring.main.allow-bean-definition-overriding}: that flag is global and permanent,
 * and disabling collision detection for every bean in the application in order to replace
 * one of them is a poor trade. A {@code BeanDefinitionRegistryPostProcessor} runs before
 * any bean is instantiated, touches exactly one definition, and fails at startup if
 * upstream ever moves the bean.
 *
 * <p>{@code ProxyService} (line 104) injects the <em>concrete</em> class
 * {@code ProxyDispatcherService}, not an interface, which is why the replacement must be a
 * subclass. The constructor signature is unchanged, so Spring's constructor autowiring
 * resolves it identically.
 */
@Component
public class DispatcherOverrideRegistrar implements BeanDefinitionRegistryPostProcessor {

    static final String BEAN_NAME = "proxyDispatcherService";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        if (!registry.containsBeanDefinition(BEAN_NAME)) {
            throw new IllegalStateException(String.format(
                "Cannot install the Skald dispatcher override: no bean definition named '%s'. " +
                    "ContainerProxy has probably renamed or restructured ProxyDispatcherService; " +
                    "see docs/DECISIONS.md ADR-0001.", BEAN_NAME));
        }

        BeanDefinition definition = registry.getBeanDefinition(BEAN_NAME);
        String currentClassName = definition.getBeanClassName();

        if (LazyProxyDispatcherService.class.getName().equals(currentClassName)) {
            return; // already installed
        }

        if (ProxyDispatcherService.class.getName().equals(currentClassName)) {
            definition.setBeanClassName(LazyProxyDispatcherService.class.getName());
            return;
        }

        // A @Bean factory method defines this bean, so there is no bean class to retarget:
        // the factory method would still produce the old object. ContainerProxy's own test
        // harness does exactly this (ShinyProxyInstance.TestConfiguration substitutes a
        // dispatcher service that builds TestProxySharingScaler), and replacing it outright
        // would break upstream's proxy-sharing tests.
        //
        // We therefore step aside rather than failing startup -- but loudly, because a
        // deployment in this state silently loses runtime-added content. The regression net
        // is LazyProxyDispatcherServiceTest, which boots without that harness and asserts
        // the installed type.
        logger.warn("The Skald dispatcher override was NOT installed: bean '{}' is defined by " +
                "factory method '{}' rather than by class '{}'. Content added at runtime will " +
                "fail to start (ProxyDispatcherService.getDispatcher returns null for specs " +
                "that did not exist at startup). This is expected under ContainerProxy's test " +
                "harness and a bug anywhere else. See docs/DECISIONS.md ADR-0001.",
            BEAN_NAME, definition.getFactoryMethodName(), ProxyDispatcherService.class.getName());
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // Nothing to do: the work happens on the registry, before instantiation.
    }

}
