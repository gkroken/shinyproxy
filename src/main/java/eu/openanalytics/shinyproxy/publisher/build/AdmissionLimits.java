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
package eu.openanalytics.shinyproxy.publisher.build;

import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * How much build work may wait, and how much of it one publisher may hold
 * (WORKPLAN-BUNDLES.md T6, decision 2 of 2026-10-01).
 *
 * <p>{@code queue_capacity}: QUEUED attempts across every content item (default 10, the plan's
 * "finite queue (10)"). {@code per_publisher_active}: QUEUED, RUNNING and PUBLISHING attempts
 * one publisher may hold at once (default 3). Both may be raised or lowered by the operator,
 * never removed: a value must be a positive integer, so "unbounded" cannot be configured
 * (Q3: "a limit may be raised but not removed"). No manifest reaches these.
 *
 * <p>An unknown key stops startup, as {@code ExtractionLimits} does: a typo that Spring would
 * silently ignore is a limit nobody set.
 */
public record AdmissionLimits(int queueCapacity, int perPublisherActive) {

    public static final AdmissionLimits DEFAULTS = new AdmissionLimits(10, 3);

    public AdmissionLimits {
        if (queueCapacity < 1 || perPublisherActive < 1) {
            throw new IllegalArgumentException("admission limits must be positive integers, got"
                    + " queue_capacity=" + queueCapacity + ", per_publisher_active="
                    + perPublisherActive);
        }
    }

    /** The defaults with operator overrides; keys in spec or Spring-relaxed spelling. */
    public static AdmissionLimits fromOverrides(Map<String, ?> overrides) {
        int queue = DEFAULTS.queueCapacity;
        int perPublisher = DEFAULTS.perPublisherActive;
        for (Map.Entry<String, ?> e : overrides.entrySet()) {
            String key = e.getKey() == null ? "" : e.getKey().trim().replace('-', '_')
                    .toLowerCase(Locale.ROOT);
            int value = parse(e.getKey(), e.getValue());
            switch (key) {
                case "queue_capacity" -> queue = value;
                case "per_publisher_active" -> perPublisher = value;
                default -> throw new IllegalArgumentException("unknown admission limit '"
                        + e.getKey() + "'; known limits are "
                        + new TreeSet<>(java.util.List.of("queue_capacity", "per_publisher_active")));
            }
        }
        return new AdmissionLimits(queue, perPublisher);
    }

    private static int parse(String key, Object value) {
        try {
            return Integer.parseInt(String.valueOf(value).trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("admission limit '" + key + "' is not an integer: "
                    + value);
        }
    }
}
