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
import java.util.function.BooleanSupplier;
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
 * declared lost once the last SUCCESSFUL renewal is older than lease minus half of
 * renew_every, which is always before the database could expire the lease. That cutoff is evaluated by
 * the driver's stop signal itself, from memory, so a renewal that HANGS cannot delay it; and
 * the cancel flag reaches the driver through the heartbeat's renewal, so the driver's thread
 * never waits on the database. That bound is the point: the
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
        FENCED,
        /**
         * This thread was interrupted (the process is stopping): the driver stopped the worker
         * and nothing was written. The lease expires and the reaper makes the attempt
         * INTERRUPTED, which is what it was; it did not fail.
         */
        INTERRUPTED
    }

    private final BuildCoordinator coordinator;
    private final CoordinatorSettings settings;

    /**
     * What happens after the driver built an image and the attempt is PUBLISHING, while this
     * runner still holds the lease (step 5's first half): verify the pushed digest and the
     * persisted log. Returns the log's last sequence, which becomes the attempt's committed
     * log cursor. Anything it throws fails the attempt (PUBLISHING -> FAILED: "push,
     * verification or the version transaction failed"). The version transaction itself is
     * T9's (succeed(), with its spec_json; user decision 2026-10-03).
     */
    public interface Publishing {
        long publish(BuildDriver.Claimed build, String image) throws Exception;
    }

    /** The longest error detail written for a failed publication. */
    static final int DETAIL_MAX = 200;

    private final Publishing publishing;

    public BuildRunner(BuildCoordinator coordinator, CoordinatorSettings settings) {
        this(coordinator, settings, null);
    }

    public BuildRunner(BuildCoordinator coordinator, CoordinatorSettings settings, Publishing publishing) {
        this.coordinator = coordinator;
        this.settings = settings;
        this.publishing = publishing;
    }

    /** Printable ASCII, at most {@link #DETAIL_MAX} characters. */
    static String detail(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < text.length() && b.length() < DETAIL_MAX; i++) {
            char c = text.charAt(i);
            b.append(c >= 0x20 && c < 0x7f ? c : '?');
        }
        return b.toString();
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
        // The cutoff: half a renewal period before the lease could expire. It must be MORE
        // than one period after the last success, or a healthy worker is declared lost in the
        // moment before each on-time renewal completes (measured: lease - renew_every, exactly
        // one period, stopped three healthy builds). renew_every <= lease/2 leaves one and a
        // half periods, so one failed renewal is survived; and the worker still stops half a
        // period before the database could expire it (10 s at the defaults).
        long tolerate = settings.lease().minus(settings.renewEvery().dividedBy(2)).toNanos();
        AtomicLong lastRenewed = new AtomicLong(claimStarted);
        AtomicBoolean cancelled = new AtomicBoolean(false);
        // The worker's one question, answered from memory only: lost, cancelled, or too long
        // since the last renewal the database confirmed. A function of TIME, so it turns true
        // on schedule however long a renewal is stuck -- a renewal that hangs (an unreachable
        // host, a half-open connection, a pool wait) never returns to say so (071ef50-F1).
        BooleanSupplier stop = () -> {
            if (!lost.get() && System.nanoTime() - lastRenewed.get() >= tolerate) {
                lost.set(true);
            }
            return lost.get() || cancelled.get();
        };
        heartbeat.scheduleAtFixedRate(() -> {
            // Never throws: a scheduled task that throws is never run again. A renewal the
            // database REFUSES is definitive. One that throws or hangs is no answer; the time
            // cutoff in `stop` covers it.
            if (lost.get()) {
                return;
            }
            long started = System.nanoTime();
            try {
                Optional<Boolean> renewed = coordinator.renewAndReadCancel(lease);
                if (renewed.isEmpty()) {
                    lost.set(true);
                } else {
                    lastRenewed.set(started);
                    cancelled.set(renewed.get());
                }
            } catch (Throwable unanswered) {
                // retried on the next tick
            }
        }, 0, every, TimeUnit.MILLISECONDS);
        try {
            BuildDriver.Outcome outcome;
            try {
                outcome = driver.run(build, stop);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return Result.INTERRUPTED;
            } catch (Exception ex) {
                outcome = new BuildDriver.Failed("DRIVER_ERROR", ex.getClass().getSimpleName());
            }
            if (stop.getAsBoolean() && lost.get()) {
                return Result.FENCED;
            }
            if (outcome instanceof BuildDriver.Built built) {
                try {
                    coordinator.toPublishing(lease, built.image());
                } catch (IllegalArgumentException notADigest) {
                    // A driver bug (a tag where a digest belongs) is the attempt's failure,
                    // not an exception for the caller: the attempt would otherwise sit RUNNING
                    // until reaped (25d3a98 review N1).
                    coordinator.fail(lease, "DRIVER_ERROR", notADigest.getMessage());
                    return Result.FAILED;
                }
                if (publishing == null) {
                    return Result.PUBLISHING;
                }
                long cursor;
                try {
                    cursor = publishing.publish(build, built.image());
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return Result.INTERRUPTED;
                } catch (Exception unverified) {
                    coordinator.fail(lease, "PUBLISH_VERIFY", detail(unverified.getMessage()));
                    return Result.FAILED;
                }
                coordinator.markLogComplete(lease, cursor);
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
