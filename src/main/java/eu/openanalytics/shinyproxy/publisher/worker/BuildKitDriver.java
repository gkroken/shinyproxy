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
package eu.openanalytics.shinyproxy.publisher.worker;

import eu.openanalytics.shinyproxy.publisher.build.BuildDriver;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Recipe;
import eu.openanalytics.shinyproxy.publisher.storage.BuildLogWriter;
import eu.openanalytics.shinyproxy.publisher.storage.HeadTailLog;
import eu.openanalytics.shinyproxy.publisher.storage.LogFinal;
import eu.openanalytics.shinyproxy.publisher.storage.LogLines;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Push;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Request;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.LogsParam;
import org.mandas.docker.client.LogStream;
import org.mandas.docker.client.exceptions.NotFoundException;
import org.mandas.docker.client.messages.ContainerState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * The real {@link BuildDriver}: one rootless worker per attempt behind its own gateway
 * ({@link DockerWorkerLauncher}), the context and buildctl through {@link BuildKitClient}.
 *
 * <p><b>The stop bound (T6 carry (a), cab64b9 review N1).</b> Every Docker call, the
 * context preparation included, runs on ONE work thread. The caller's thread does nothing
 * but wait on it in slices of {@code poll} and ask the stop signal between them, so it
 * answers the signal within {@code poll} however long any call blocks: a launch waiting
 * for its daemon, a hung daemon request, a RUN step that sleeps. On a true signal it
 * SIGKILLs the worker and removes every container of the attempt, so all of its code
 * stops, then interrupts the work thread and waits for it at most {@code settle}. The
 * volumes, network and loop device are disposed of by the work thread itself as its last
 * act after a stop, and by this thread only if the work thread has ended: a Docker call
 * ignores the interrupt, so a create may land late, and removing a volume under it would
 * make Docker re-create that volume unlabelled (0c71146-F1). {@code poll} must be at most
 * renew_every / 2.
 *
 * <p><b>Worker death is State.Running, never State.OOMKilled (T5 gate F6 carry (1)).</b>
 * A RUN step that is OOM-killed inside the worker sets the WORKER's OOMKilled flag while
 * the daemon keeps running and building; the step's own failure, if the build does not
 * tolerate it, reaches the client as a failed build.
 *
 * <p>Failure details are short and printable ASCII: a build's last log line is the
 * publisher's code talking, and it is shown, not interpreted.
 */
public final class BuildKitDriver implements BuildDriver {

    /** What a claimed attempt is built from. Part 4 reads it from the bundle store. */
    public interface ContextSource {
        Prepared prepare(Claimed build) throws Exception;
    }

    /** A verified payload on disk, its recipe, the repository to push to, and its cleanup. */
    public record Prepared(Path payload, Recipe recipe, String repository, Runnable release) { }

    /** The deployment's choices for every attempt. */
    public record Config(Settings settings, int quotaMegabytes, Egress egress, Credential credential,
                         Duration poll, Duration settle, HeadTailLog.Limits logLimits) {

        public Config {
            if (poll.isNegative() || poll.isZero() || settle.isNegative()) {
                throw new IllegalArgumentException("poll must be positive and settle not negative");
            }
        }
    }

    static final int DETAIL_MAX = 200;
    /** How long the decision waits for the rest of an exited client's output. */
    static final long FOLLOW_SETTLE_MILLIS = 30_000;
    private static final Logger log = LoggerFactory.getLogger(BuildKitDriver.class);

    private final DockerClient docker;
    private final DockerWorkerLauncher launcher;
    private final BuildKitClient client;
    private final ContextSource source;
    private final BuildLogWriter logs;
    private final Config config;
    /** The last attempt's work thread, so a test can wait for its own disposal. */
    volatile Thread lastWork;

    public BuildKitDriver(DockerClient docker, DockerWorkerLauncher launcher, BuildKitClient client,
                          ContextSource source, BuildLogWriter logs, Config config) {
        this.docker = docker;
        this.launcher = launcher;
        this.client = client;
        this.source = source;
        this.logs = logs;
        this.config = config;
    }

    /** The attempt id the launcher names every object by: the build id's 32 hex digits. */
    static String attemptId(Claimed build) {
        return build.buildId().toString().replace("-", "");
    }

    @Override
    public Outcome run(Claimed build, BooleanSupplier cancelRequested) throws Exception {
        Handle h = DockerWorkerLauncher.handle(attemptId(build));
        HeadTailLog buildLog = new HeadTailLog(logs, build.contentId(), build.buildId(), build.lease().generation(),
                config.logLimits());
        AtomicBoolean aborted = new AtomicBoolean();
        AtomicReference<Outcome> result = new AtomicReference<>();
        AtomicReference<Throwable> crashed = new AtomicReference<>();
        Thread work = new Thread(() -> {
            try {
                result.set(attempt(build, h, aborted, buildLog));
            } catch (Throwable t) {
                crashed.set(t);
            } finally {
                if (aborted.get()) {
                    // The last thing this thread does: its calls are synchronous (a Jersey
                    // request ignores an interrupt), so anything a late call made exists by
                    // now, and nothing of the attempt is made after this (0c71146-F1).
                    // The stop's interrupt only served to wake this thread; left pending, it
                    // makes the first retry's sleep throw and the whole disposal give up on
                    // one transient daemon error (904eb75-F1). Cleared, the disposal runs to
                    // the end.
                    Thread.interrupted();
                    disposeQuietly(h, "work thread, after a stop");
                }
            }
        }, "skald-build-" + h.attemptId());
        lastWork = work;
        work.setDaemon(true);
        work.start();
        long poll = config.poll().toMillis();
        try {
            while (work.isAlive()) {
                if (cancelRequested.getAsBoolean()) {
                    aborted.set(true);
                    stopEverything(h, work);
                    buildLog.line("[skald] stopped", false);
                    buildLog.finish("STOPPED");
                    return new Stopped();
                }
                work.join(poll);
            }
        } catch (InterruptedException e) {
            aborted.set(true);
            stopEverything(h, work);
            throw e;
        }
        // The work is over; whatever it said, nothing of the attempt outlives this call.
        List<String> left = launcher.dispose(h);
        if (!left.isEmpty()) {
            log.warn("attempt {}: disposal left {}", h.attemptId(), left);
        }
        // A stop that arrives after the work ended stopped nothing, so the outcome is what
        // happened: Stopped would claim a stop that never occurred (T8 carry (4): the
        // attempt goes on to PUBLISHING with its cancel request recorded).
        Outcome outcome = crashed.get() != null
                ? new Failed("DRIVER_ERROR", detail(crashed.get().getClass().getSimpleName()))
                : result.get();
        return withLog(buildLog, outcome);
    }

    /**
     * Ends the attempt's log with its outcome. A success is a success only with a complete
     * log: if the log failed or could not be finished, the attempt is a log failure instead,
     * never a silent success (WORKPLAN-BUNDLES.md: "if durability cannot be recovered, stop
     * the build and report a storage/log failure").
     */
    private Outcome withLog(HeadTailLog buildLog, Outcome outcome) {
        String label = outcome instanceof Built ? "BUILT"
                : outcome instanceof Failed f ? "FAILED:" + f.code() : "STOPPED";
        if (outcome instanceof Failed f) {
            buildLog.line("[skald] failed: " + f.code() + " " + f.detail(), false);
        }
        Optional<LogFinal> fin = buildLog.finish(label);
        if (outcome instanceof Built && (fin.isEmpty() || !fin.get().complete())) {
            return new Failed("LOG_STORAGE", detail(buildLog.failure() != null ? buildLog.failure()
                    : "the build log could not be finished complete"));
        }
        return outcome;
    }

    /**
     * The stop path. Every process of the attempt ends at once: the worker by one SIGKILL,
     * then every container of the attempt. Volumes, the network and the loop device are NOT
     * touched while the work thread may still be in a daemon call: a create that lands
     * after a volume was removed makes Docker re-create that volume for its bind, unlabelled
     * and beyond any disposal (0c71146-F1). The full disposal is the work thread's own last
     * act after a stop; this thread does it too only if the work thread has ended within
     * {@code settle}.
     */
    private void stopEverything(Handle h, Thread work) throws InterruptedException {
        List<String> killed = launcher.killWorker(h);
        List<String> removed = launcher.removeContainers(h);
        work.interrupt();
        work.join(Math.max(1, config.settle().toMillis()));
        if (work.isAlive()) {
            log.warn("attempt {}: stopped; kill {}, containers {}; the work thread is still in a daemon"
                    + " call and disposes of the attempt when it returns", h.attemptId(), killed, removed);
            return;
        }
        disposeQuietly(h, "after a stop");
    }

    private void disposeQuietly(Handle h, String when) {
        try {
            List<String> left = launcher.dispose(h);
            if (!left.isEmpty()) {
                log.warn("attempt {}: disposal {} left {}", h.attemptId(), when, left);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("attempt {}: disposal {} interrupted", h.attemptId(), when);
        }
    }

    /** The work thread: every Docker call of the attempt. */
    private Outcome attempt(Claimed build, Handle h, AtomicBoolean aborted, HeadTailLog buildLog) throws Exception {
        buildLog.line("[skald] attempt " + h.attemptId() + ": preparing the build context", false);
        Prepared prepared;
        try {
            prepared = source.prepare(build);
        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            return new Failed("CONTEXT", detail(e.getMessage()));
        }
        try {
            if (aborted.get()) {
                return new Stopped();
            }
            Push push = new Push(config.egress().registry(), prepared.repository(), build.buildId(),
                    config.credential());
            buildLog.line("[skald] launching the build worker", false);
            try {
                launcher.launch(new Request(h.attemptId(), config.settings(), config.quotaMegabytes(),
                        config.egress()));
            } catch (IllegalStateException e) {
                return new Failed("WORKER_LAUNCH", detail(e.getMessage()));
            }
            if (aborted.get()) {
                return new Stopped();
            }
            try {
                client.stage(h, prepared.payload(), prepared.recipe());
                if (aborted.get()) {
                    return new Stopped();
                }
                buildLog.line("[skald] building", false);
                client.start(h, push);
            } catch (java.io.IOException | IllegalStateException
                     | org.mandas.docker.client.exceptions.DockerException e) {
                return new Failed("STAGE", detail(e.getMessage()));
            }
            Thread follower = follow(h, buildLog);
            while (!aborted.get()) {
                buildLog.tick();
                if (buildLog.failed()) {
                    // The log could not be persisted: the build stops, and says why.
                    return new Failed("LOG_STORAGE", detail(buildLog.failure()));
                }
                var exit = client.exitCode(h);
                if (exit.isPresent()) {
                    // The client exited, so its output is ending: take all of it before
                    // deciding, since a failure's detail is its last line.
                    follower.join(FOLLOW_SETTLE_MILLIS);
                }
                // A push that completed is the outcome, whatever happens to the worker after.
                if (exit.isPresent() && exit.get() == 0) {
                    try {
                        return new Built(client.pushed(h, push));
                    } catch (IllegalStateException e) {
                        return new Failed("BUILD_RESULT", detail(e.getMessage()));
                    }
                }
                // The one death check, before a failed exit is read as the build's: a client
                // whose worker died fails too, and the cause is the worker. It also ends an
                // attempt whose client hangs on a dead worker.
                if (!workerRunning(h)) {
                    return new Failed("WORKER_DIED", detail(workerState(h)));
                }
                if (exit.isPresent()) {
                    return new Failed("BUILD_FAILED", detail("exit " + exit.get() + ": " + buildLog.lastLine()));
                }
                Thread.sleep(config.poll().toMillis());
            }
            return new Stopped();
        } finally {
            prepared.release().run();
        }
    }

    /**
     * Follows the client's stderr (buildctl's progress, every RUN step's output included)
     * into the log, on its own thread, until the client's output ends. Its stdout is the
     * metadata and is not followed.
     */
    private Thread follow(Handle h, HeadTailLog buildLog) {
        Thread t = new Thread(() -> {
            LogLines lines = new LogLines(config.logLimits().lineBytes(), buildLog::line);
            try (LogStream stream = docker.logs(h.client(), LogsParam.follow(), LogsParam.stderr())) {
                while (stream.hasNext()) {
                    lines.feed(stream.next().content());
                }
            } catch (Exception e) {
                buildLog.line("[skald] the build log stream ended: " + detail(e.getMessage()), false);
            } finally {
                lines.end();
            }
        }, "skald-log-" + h.attemptId());
        t.setDaemon(true);
        t.start();
        return t;
    }

    private boolean workerRunning(Handle h) throws Exception {
        try {
            return docker.inspectContainer(h.worker()).state().running();
        } catch (NotFoundException e) {
            return false;
        }
    }

    private String workerState(Handle h) throws Exception {
        try {
            ContainerState s = docker.inspectContainer(h.worker()).state();
            return "the worker exited " + s.exitCode() + (Boolean.TRUE.equals(s.oomKilled())
                    ? " (OOMKilled)" : "");
        } catch (NotFoundException e) {
            return "the worker is gone";
        }
    }

    /** Printable ASCII, at most {@link #DETAIL_MAX} characters; anything else becomes '?'. */
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
}
