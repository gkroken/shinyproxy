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

import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs one claimed attempt through a {@link BuildDriver}: claim, keep the lease alive while
 * the driver works, then write the outcome -- every write fenced (WORKPLAN-BUNDLES.md T6,
 * step 4's shape, without the image publication that is T7's and the version transaction
 * that is a later T6 part). No request thread ever waits on this.
 *
 * <p>The heartbeat renews the lease every renew_every. A renewal the database REFUSES means
 * the lease is gone (reaped, or the deadline passed): the attempt is no longer this
 * worker's, and the driver is told to stop through the same signal as a cancellation;
 * whatever it returns afterwards is not written. A renewal that THROWS (a connection blip,
 * a failover) is not an answer, so it is retried on the next tick -- but the worker is
 * declared lost once the last SUCCESSFUL renewal is older than lease minus renew_every,
 * which is always before the database could expire the lease. That bound is the point: the
 * slot must not look free to another coordinator while this worker still runs untrusted
 * code (071ef50-F1, where one thrown renewal killed the heartbeat task for good --
 * ScheduledExecutorService suppresses every run after a task throws -- and the first worker
 * ran on beside the next).
 */
public final class BuildRunner {

    /** What one call did. */
    public enum Result {
        /** Nothing to claim, or the running limit is reached. */
        IDLE,
        /** The driver built an image; the attempt is PUBLISHING. */
        PUBLISHING,
        /** The driver reported a failure, or threw. */
        FAILED,
        /** A requested cancellation was confirmed by the driver's stop. */
        CANCELLED,
        /** The lease was lost while the driver ran; nothing the driver said was written. */
        FENCED
    }

    private final BuildCoordinator coordinator;
    private final CoordinatorSettings settings;

    public BuildRunner(BuildCoordinator coordinator, CoordinatorSettings settings) {
        this.coordinator = coordinator;
        this.settings = settings;
    }

    /**
     * The cancel flag as the driver's stop signal sees it. A read that throws is "keep going":
     * the driver must not receive the exception, and a lease lost meanwhile is still caught by
     * the heartbeat.
     */
    private boolean cancelRequested(Lease lease) {
        try {
            return coordinator.cancelRequested(lease);
        } catch (RuntimeException unanswered) {
            return false;
        }
    }

    public Result runOnce(String owner, BuildDriver driver) {
        long claimStarted = System.nanoTime();
        Optional<BuildDriver.Claimed> claimed = coordinator.claim(owner);
        if (claimed.isEmpty()) {
            return Result.IDLE;
        }
        // Measured from BEFORE the claim: the database set the expiry no earlier than this,
        // so a local deadline counted from here is never later than the real one.
        BuildDriver.Claimed build = claimed.get();
        Lease lease = build.lease();
        AtomicBoolean lost = new AtomicBoolean(false);
        ScheduledExecutorService heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "skald-lease-" + lease.buildId());
            t.setDaemon(true);
            return t;
        });
        long every = settings.renewEvery().toMillis();
        long tolerate = settings.lease().minus(settings.renewEvery()).toNanos();
        AtomicLong lastRenewed = new AtomicLong(claimStarted);
        heartbeat.scheduleAtFixedRate(() -> {
            // Never throws: a scheduled task that throws is never run again.
            if (lost.get()) {
                return;
            }
            long started = System.nanoTime();
            try {
                if (coordinator.renew(lease)) {
                    lastRenewed.set(started);
                } else {
                    lost.set(true);
                }
            } catch (Throwable unanswered) {
                if (System.nanoTime() - lastRenewed.get() >= tolerate) {
                    lost.set(true);
                }
            }
        }, every, every, TimeUnit.MILLISECONDS);
        try {
            BuildDriver.Outcome outcome;
            try {
                outcome = driver.run(build, () -> lost.get() || cancelRequested(lease));
            } catch (Exception ex) {
                outcome = new BuildDriver.Failed("DRIVER_ERROR", ex.getClass().getSimpleName());
            }
            if (lost.get()) {
                return Result.FENCED;
            }
            if (outcome instanceof BuildDriver.Built built) {
                coordinator.toPublishing(lease, built.image());
                return Result.PUBLISHING;
            }
            if (outcome instanceof BuildDriver.Stopped) {
                coordinator.confirmCancelled(lease);
                return Result.CANCELLED;
            }
            BuildDriver.Failed failed = (BuildDriver.Failed) outcome;
            coordinator.fail(lease, failed.code(), failed.detail());
            return Result.FAILED;
        } catch (Fenced fenced) {
            return Result.FENCED;
        } finally {
            heartbeat.shutdownNow();
        }
    }
}
