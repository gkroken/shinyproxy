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

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * The coordinator's timing and concurrency (WORKPLAN-BUNDLES.md T6, decisions 2 and 4 of
 * 2026-10-01): lease 60 s renewed every 20 s, one running build at a time, and the plan's
 * 20-minute wall deadline. Configurable, positive only, with renewal well inside the lease --
 * a renewal interval at or above the lease would let every healthy build expire.
 */
public record CoordinatorSettings(Duration lease, Duration renewEvery, Duration deadline,
                                  int maxRunning) {

    public static final CoordinatorSettings DEFAULTS = new CoordinatorSettings(
            Duration.ofSeconds(60), Duration.ofSeconds(20), Duration.ofMinutes(20), 1);

    public CoordinatorSettings {
        if (lease.isNegative() || lease.isZero() || renewEvery.isNegative() || renewEvery.isZero()
                || deadline.isNegative() || deadline.isZero() || maxRunning < 1) {
            throw new IllegalArgumentException("coordinator settings must be positive");
        }
        if (renewEvery.multipliedBy(2).compareTo(lease) > 0) {
            throw new IllegalArgumentException("renew-every (" + renewEvery + ") must be at most"
                    + " half the lease (" + lease + "), or one late renewal expires a healthy build");
        }
    }

    /** Defaults with overrides: lease-seconds, renew-every-seconds, deadline-minutes, max-running. */
    public static CoordinatorSettings fromOverrides(Map<String, ?> overrides) {
        Duration lease = DEFAULTS.lease;
        Duration renew = DEFAULTS.renewEvery;
        Duration deadline = DEFAULTS.deadline;
        int running = DEFAULTS.maxRunning;
        for (Map.Entry<String, ?> e : overrides.entrySet()) {
            String key = e.getKey() == null ? "" : e.getKey().trim().replace('-', '_')
                    .toLowerCase(Locale.ROOT);
            long value;
            try {
                value = Long.parseLong(String.valueOf(e.getValue()).trim());
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("coordinator setting '" + e.getKey()
                        + "' is not an integer: " + e.getValue());
            }
            switch (key) {
                case "lease_seconds" -> lease = Duration.ofSeconds(value);
                case "renew_every_seconds" -> renew = Duration.ofSeconds(value);
                case "deadline_minutes" -> deadline = Duration.ofMinutes(value);
                case "max_running" -> running = Math.toIntExact(value);
                default -> throw new IllegalArgumentException("unknown coordinator setting '"
                        + e.getKey() + "'; known settings are " + new TreeSet<>(List.of(
                        "lease_seconds", "renew_every_seconds", "deadline_minutes", "max_running")));
            }
        }
        return new CoordinatorSettings(lease, renew, deadline, running);
    }
}
