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
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Credential;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitClient.Push;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Request;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.exceptions.NotFoundException;
import org.mandas.docker.client.messages.ContainerState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
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
 * disposes of the WHOLE attempt at once (the worker, its descendants, the gateway, the
 * client and every volume), then interrupts the work thread, waits for it at most
 * {@code settle}, and disposes again: a launch still in flight may have made an object
 * after the first pass. {@code poll} must be at most renew_every / 2.
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
                         Duration poll, Duration settle) {

        public Config {
            if (poll.isNegative() || poll.isZero() || settle.isNegative()) {
                throw new IllegalArgumentException("poll must be positive and settle not negative");
            }
        }
    }

    static final int DETAIL_MAX = 200;
    private static final Logger log = LoggerFactory.getLogger(BuildKitDriver.class);

    private final DockerClient docker;
    private final DockerWorkerLauncher launcher;
    private final BuildKitClient client;
    private final ContextSource source;
    private final Config config;

    public BuildKitDriver(DockerClient docker, DockerWorkerLauncher launcher, BuildKitClient client,
                          ContextSource source, Config config) {
        this.docker = docker;
        this.launcher = launcher;
        this.client = client;
        this.source = source;
        this.config = config;
    }

    /** The attempt id the launcher names every object by: the build id's 32 hex digits. */
    static String attemptId(Claimed build) {
        return build.buildId().toString().replace("-", "");
    }

    @Override
    public Outcome run(Claimed build, BooleanSupplier cancelRequested) throws Exception {
        Handle h = DockerWorkerLauncher.handle(attemptId(build));
        AtomicBoolean aborted = new AtomicBoolean();
        AtomicReference<Outcome> result = new AtomicReference<>();
        AtomicReference<Throwable> crashed = new AtomicReference<>();
        Thread work = new Thread(() -> {
            try {
                result.set(attempt(build, h, aborted));
            } catch (Throwable t) {
                crashed.set(t);
            }
        }, "skald-build-" + h.attemptId());
        work.setDaemon(true);
        work.start();
        long poll = config.poll().toMillis();
        try {
            while (work.isAlive()) {
                if (cancelRequested.getAsBoolean()) {
                    aborted.set(true);
                    stopEverything(h, work);
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
        if (crashed.get() != null) {
            return new Failed("DRIVER_ERROR", detail(crashed.get().getClass().getSimpleName()));
        }
        return result.get();
    }

    private void stopEverything(Handle h, Thread work) throws InterruptedException {
        // The worker first, by one SIGKILL: untrusted code stops here, whatever the work
        // thread is doing. Then everything else.
        List<String> killed = launcher.killWorker(h);
        List<String> first = launcher.dispose(h);
        work.interrupt();
        work.join(Math.max(1, config.settle().toMillis()));
        List<String> left = launcher.dispose(h);
        if (work.isAlive() || !left.isEmpty()) {
            log.warn("attempt {}: stopped; kill {}, first pass left {}, second left {}, work thread {}",
                    h.attemptId(), killed, first, left, work.isAlive() ? "still running" : "done");
        }
    }

    /** The work thread: every Docker call of the attempt. */
    private Outcome attempt(Claimed build, Handle h, AtomicBoolean aborted) throws Exception {
        Prepared prepared;
        try {
            prepared = source.prepare(build);
        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            return new Failed("CONTEXT", detail(e.getMessage()));
        }
        try {
            Push push = new Push(config.egress().registry(), prepared.repository(), build.buildId(),
                    config.credential());
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
                client.start(h, push);
            } catch (java.io.IOException | IllegalStateException
                     | org.mandas.docker.client.exceptions.DockerException e) {
                return new Failed("STAGE", detail(e.getMessage()));
            }
            while (!aborted.get()) {
                var exit = client.exitCode(h);
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
                    return new Failed("BUILD_FAILED", detail("exit " + exit.get() + ": "
                            + lastLine(client.log(h))));
                }
                Thread.sleep(config.poll().toMillis());
            }
            return new Stopped();
        } finally {
            prepared.release().run();
        }
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

    static String lastLine(String log) {
        List<String> lines = log.strip().lines().filter(l -> !l.isBlank()).toList();
        return lines.isEmpty() ? "" : lines.get(lines.size() - 1);
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
