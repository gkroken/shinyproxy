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
package eu.openanalytics.shinyproxy.publisher.bundle;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Binds {@code skald.bundle.limits.*} and turns it into the one {@link ExtractionLimits}
 * bean everything else reads.
 *
 * <p>It is bound as a free-form map rather than ten typed properties on purpose. A typed
 * setter per bound would make an operator's typo — {@code max-file-byte} — a property Spring
 * ignores, which is exactly the silent no-limit this design refuses; as a map, every key
 * reaches {@link ExtractionLimits#fromOverrides} and an unknown one stops startup.
 *
 * <p>Unconditional, unlike {@code ObjectStorageConfig}: a deployment that sets nothing gets
 * the documented defaults, and the only way to fail here is to have configured something
 * that cannot be honoured.
 */
@Configuration
@ConfigurationProperties(prefix = "skald.bundle")
public class BundleLimitsConfig {

    private Map<String, String> limits = new LinkedHashMap<>();

    public Map<String, String> getLimits() {
        return limits;
    }

    public void setLimits(Map<String, String> limits) {
        this.limits = limits == null ? new LinkedHashMap<>() : limits;
    }

    @Bean
    public ExtractionLimits extractionLimits() {
        return ExtractionLimits.fromOverrides(limits);
    }
}
