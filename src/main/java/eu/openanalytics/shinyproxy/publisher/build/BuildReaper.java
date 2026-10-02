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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs {@link BuildCoordinator#reap()} every {@code period}: expired leases become
 * INTERRUPTED and passed deadlines TIMED_OUT, without a caller (071ef50 review N1).
 *
 * <p>The task never throws. A scheduled task that throws is never run again -- the defect
 * 071ef50-F1 found in the heartbeat -- and a reaper that silently stopped would leave every
 * later lost worker's slot held forever. A failed reap is logged and the next tick tries
 * again.
 */
public final class BuildReaper {

    private static final Logger log = LoggerFactory.getLogger(BuildReaper.class);

    private final BuildCoordinator coordinator;
    private final Duration period;
    private final AtomicLong reaped = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();
    private ScheduledExecutorService timer;

    public BuildReaper(BuildCoordinator coordinator, Duration period) {
        this.coordinator = coordinator;
        this.period = period;
    }

    public synchronized void start() {
        if (timer != null) {
            return;
        }
        timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "skald-build-reaper");
            t.setDaemon(true);
            return t;
        });
        long every = period.toMillis();
        timer.scheduleAtFixedRate(this::tick, every, every, TimeUnit.MILLISECONDS);
    }

    void tick() {
        try {
            int n = coordinator.reap();
            if (n > 0) {
                reaped.addAndGet(n);
                log.info("reaped {} build attempt(s) whose lease or deadline had passed", n);
            }
        } catch (Throwable failure) {
            failures.incrementAndGet();
            log.warn("reaping failed; retrying in {}", period, failure);
        }
    }

    public synchronized void stop() {
        if (timer != null) {
            timer.shutdownNow();
            timer = null;
        }
    }

    /** Attempts reaped since start; for tests and metrics. */
    public long reaped() {
        return reaped.get();
    }

    /** Reaps that threw since start; for tests and metrics. */
    public long failures() {
        return failures.get();
    }
}
