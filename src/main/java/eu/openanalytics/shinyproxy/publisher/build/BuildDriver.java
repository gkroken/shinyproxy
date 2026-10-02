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

import java.util.Map;
import java.util.UUID;

/**
 * What actually builds: T7's BuildKit driver, or a fake in T6's tests (the plan: "Use a fake
 * driver for deterministic crash/concurrency tests only here"). The coordinator owns the
 * attempt's state; a driver only reports an {@link Outcome}, and may ask whether a
 * cancellation was requested.
 */
public interface BuildDriver {

    /** What the coordinator hands a driver for one claimed attempt. */
    record Claimed(UUID buildId, UUID contentId, UUID bundleId, Map<String, Object> recipe,
                   Lease lease) { }

    /** How the attempt ended, from the driver's side. */
    sealed interface Outcome permits Built, Failed, Stopped { }

    /** An image exists at this digest reference; the attempt moves on to PUBLISHING. */
    record Built(String image) implements Outcome { }

    /** A build step failed; {@code code} is short and machine-readable. */
    record Failed(String code, String detail) implements Outcome { }

    /** The driver stopped the whole worker because a cancellation was requested. */
    record Stopped() implements Outcome { }

    /**
     * Runs the attempt. {@code cancelRequested} is the attempt's stop signal: true on a
     * requested cancellation AND when the lease is lost. It is answered from memory and never
     * blocks.
     *
     * <p>The bound every driver must keep (cab64b9 review N1): poll the signal at least every
     * renew_every / 2 (10 s at the defaults), INCLUDING while waiting on a long call -- the
     * runner declares the lease lost half a period before the database could expire it, and
     * from that expiry another coordinator may claim the slot. On a true signal the driver
     * must stop the WHOLE worker (worker_disposal: the container, its descendants and its
     * volumes), not merely stop reading it, and then return {@link Stopped} (for a
     * cancellation) or anything (for a lost lease -- it is not written). T7 tests this with a
     * driver blocked in a long call.
     */
    Outcome run(Claimed build, java.util.function.BooleanSupplier cancelRequested) throws Exception;
}
