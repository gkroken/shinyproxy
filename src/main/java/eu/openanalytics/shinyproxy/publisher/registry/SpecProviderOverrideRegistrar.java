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

import eu.openanalytics.shinyproxy.ShinyProxySpecProvider;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Retargets the {@code shinyProxySpecProvider} bean definition to {@link MergedSpecProvider}.
 *
 * <p>Same technique as {@code DispatcherOverrideRegistrar}, and for the same reason: it
 * replaces one bean definition before instantiation rather than switching on global bean
 * overriding. Because it swaps the class of the existing definition, the
 * {@code @ConfigurationProperties(prefix = "proxy")} binding, the {@code @Primary} marker and
 * the {@code @PostConstruct} callback all carry over untouched — the subclass inherits them.
 *
 * <p><b>This is not a second ContainerProxy override.</b> ADR-0001's tripwire counts overrides
 * of <em>ContainerProxy</em>, the released jar we do not control. {@code ShinyProxySpecProvider}
 * is a class in this repository; the override exists to keep the diff against it at zero, so
 * upstream merges stay clean. Only {@code proxyDispatcherService} touches ContainerProxy.
 *
 * <p>Conditional on a configured DataSource: with no database there is no registry, and the
 * fork should behave exactly as upstream does.
 */
@Component
@ConditionalOnProperty(name = "spring.datasource.url")
public class SpecProviderOverrideRegistrar implements BeanDefinitionRegistryPostProcessor {

    static final String BEAN_NAME = "shinyProxySpecProvider";

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        if (!registry.containsBeanDefinition(BEAN_NAME)) {
            throw new IllegalStateException(String.format(
                "Cannot install the Skald spec provider: no bean definition named '%s'. " +
                    "ShinyProxy has probably renamed or restructured ShinyProxySpecProvider.",
                BEAN_NAME));
        }

        BeanDefinition definition = registry.getBeanDefinition(BEAN_NAME);
        String currentClassName = definition.getBeanClassName();

        if (MergedSpecProvider.class.getName().equals(currentClassName)) {
            return; // already installed
        }
        if (!ShinyProxySpecProvider.class.getName().equals(currentClassName)) {
            throw new IllegalStateException(String.format(
                "Cannot install the Skald spec provider: bean '%s' is a '%s', expected '%s'. " +
                    "Registry content would be invisible, so this fails rather than degrading.",
                BEAN_NAME, currentClassName, ShinyProxySpecProvider.class.getName()));
        }

        definition.setBeanClassName(MergedSpecProvider.class.getName());
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // Nothing to do: the work happens on the registry, before instantiation.
    }

}
