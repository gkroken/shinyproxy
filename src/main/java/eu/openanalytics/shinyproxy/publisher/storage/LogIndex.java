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
package eu.openanalytics.shinyproxy.publisher.storage;

/**
 * What a reader may safely fetch right now. Mutable, and the only mutable artifact here.
 *
 * <p>"An index advertises only persisted contiguous chunks" — so {@code lastSequence} is
 * the end of an unbroken run from 1, never the highest sequence that happens to exist. A
 * log with chunks 1, 2 and 4 advertises 2. Advertising 4 would tell a reader to fetch a
 * chunk 3 that is not there, and the plan's requirement is exactly that readers "may lag
 * but cannot observe a completion index pointing at absent chunks": lagging is fine,
 * pointing at a hole is not.
 *
 * @param generation the lease generation that published this index. A writer fenced out of
 *                   its lease must not be able to move the index backwards or forwards,
 *                   and this is what lets a later publish tell that it is the stale one.
 */
public record LogIndex(long generation, long lastSequence, long bytes) {
}
