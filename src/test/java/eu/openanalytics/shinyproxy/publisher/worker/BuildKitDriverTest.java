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

import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Built;
import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Claimed;
import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Failed;
import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Outcome;
import eu.openanalytics.shinyproxy.publisher.build.BuildDriver.Stopped;
import eu.openanalytics.shinyproxy.publisher.build.Lease;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Recipe;
import eu.openanalytics.shinyproxy.publisher.storage.BuildLogWriter;
import eu.openanalytics.shinyproxy.publisher.storage.HeadTailLog;
import eu.openanalytics.shinyproxy.publisher.storage.LogFinal;
import eu.openanalytics.shinyproxy.publisher.storage.ObjectKeys;
import eu.openanalytics.shinyproxy.publisher.storage.ObjectStoreException;
import eu.openanalytics.shinyproxy.publisher.storage.TestObjectStore;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitDriver.Config;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitDriver.ContextSource;
import eu.openanalytics.shinyproxy.publisher.worker.BuildKitDriver.Prepared;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Egress;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.LogStream;
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;
import org.mandas.docker.client.exceptions.NotFoundException;
import org.mandas.docker.client.messages.Volume;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The driver against real Docker: its outcomes, the stop bound while a call blocks, worker
 * death, and a RUN step's OOM that is not worker death. Every case ends with nothing of the
 * attempt left on the host. `make test` builds the worker and gateway images first.
 */
public class BuildKitDriverTest {

    private static final String WORKER = "skald-buildkit-worker:test";
    private static final String GATEWAY = "skald-egress-gateway:test";
    /** The bound under test: renew_every / 2 at the defaults is 10 s; the driver polls every 1 s. */
    private static final Duration POLL = Duration.ofSeconds(1);
    private static DockerClient docker;
    private static DockerWorkerLauncher launcher;
    private static BuildKitClient client;
    private static TestRegistry registry;
    private static TestObjectStore logStore;
    /** Swapped by a case that needs a failing store; reset after each case. */
    private static BuildLogWriter logWriter;
    /** Small, so a modest build overflows the head and exercises the tail. */
    private static final HeadTailLog.Limits LOG_LIMITS = new HeadTailLog.Limits(16 << 10, 16 << 10, 1024,
            Duration.ofSeconds(2), 64 << 10, 3, Duration.ofMillis(200));

    @BeforeAll
    public static void start() throws Exception {
        docker = new JerseyDockerClientBuilder().fromEnv().build();
        for (String image : List.of(WORKER, GATEWAY, Images.HELPER, Images.SETUP, TestRegistry.IMAGE)) {
            assertNotNull(docker.inspectImage(image), image + " is missing; run `make test`");
        }
        Images images = Images.of(WORKER, GATEWAY);
        launcher = new DockerWorkerLauncher(docker, WorkerProfile.load("runc-rootless"), images);
        client = new BuildKitClient(docker, launcher, images);
        registry = new TestRegistry(docker, "skald-bkd", 15032);
        logStore = new TestObjectStore("skald-bkd-logs");
        logWriter = new BuildLogWriter(logStore.store, logStore.bucket);
    }

    @org.junit.jupiter.api.AfterEach
    public void resetLogWriter() {
        if (logStore != null) {
            logWriter = new BuildLogWriter(logStore.store, logStore.bucket);
        }
    }

    @AfterAll
    public static void stop() throws Exception {
        if (docker != null) {
            try {
                if (registry != null) {
                    registry.close();
                }
                if (logStore != null) {
                    logStore.close();
                }
            } finally {
                docker.close();
            }
        }
    }

    /** The driver the current case made last; assertNothingLeft waits for its work thread. */
    private static volatile BuildKitDriver lastDriver;

    private static BuildKitDriver driver(Settings settings, ContextSource source) {
        return lastDriver = new BuildKitDriver(docker, launcher, client, source, logWriter, new Config(settings, 256,
                new Egress(List.of(registry.outer), registry.name, List.of("pypi.org"), List.of(), List.of(), List.of()),
                TestRegistry.CRED, POLL, Duration.ofSeconds(30), LOG_LIMITS));
    }

    private static Claimed claimed() {
        UUID id = UUID.randomUUID();
        return new Claimed(id, UUID.randomUUID(), UUID.randomUUID(), Map.of(), new Lease(id, 1, "test"));
    }

    /** A context of one file and a Dockerfile whose last steps are {@code steps}. */
    private static ContextSource source(Path dir, String steps, AtomicInteger released) throws Exception {
        Path payload = Files.createDirectories(dir.resolve("payload"));
        Files.writeString(payload.resolve("app.py"), "print('hello')\n");
        Recipe recipe = new Recipe("FROM " + registry.base() + "\nCOPY app/ /app/\n" + steps,
                Map.of("skald/test.lock", "lock\n".getBytes(StandardCharsets.UTF_8)));
        return build -> new Prepared(payload, recipe, "content/bkd", released::incrementAndGet);
    }

    private static Handle handle(Claimed c) {
        return DockerWorkerLauncher.handle(BuildKitDriver.attemptId(c));
    }

    /** Waits, from a side thread, for the attempt's client to run; the stop flips then. */
    private static Thread whenClientRuns(Handle h, Runnable then) {
        Thread t = new Thread(() -> {
            try {
                for (int i = 0; i < 1800; i++) {
                    try {
                        if (docker.inspectContainer(h.client()).state().running()) {
                            then.run();
                            return;
                        }
                    } catch (NotFoundException e) {
                        // not yet
                    }
                    Thread.sleep(500);
                }
            } catch (Exception e) {
                // the test's own assertions report it
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void assertNothingLeft(Claimed c) throws Exception {
        // After a stop the disposal is the work thread's last act, and run() may return
        // before it ends (a slow daemon: the kill alone took 18 s once, and the settle ran
        // out). What is checked is what is left once that thread is done.
        Thread work = lastDriver == null ? null : lastDriver.lastWork;
        if (work != null) {
            work.join(180_000);
            assertFalse(work.isAlive(), "the work thread ended");
        }
        Handle h = handle(c);
        assertEquals(List.of(), launcher.leftovers(h), "nothing of the attempt is left");
        // By NAME too: a volume Docker re-created for a bind carries no label, and the
        // label-based leftovers() cannot see it (0c71146-F1).
        String id = h.attemptId();
        List<String> named = new java.util.ArrayList<>();
        docker.listContainers(DockerClient.ListContainersParam.allContainers()).forEach(ct -> ct.names().stream()
                .filter(n -> n.contains(id)).forEach(n -> named.add("container " + n)));
        var volumes = docker.listVolumes().volumes();
        if (volumes != null) {
            volumes.stream().filter(v -> v.name().contains(id)).forEach(v -> named.add("volume " + v.name()));
        }
        docker.listNetworks().stream().filter(n -> n.name().contains(id)).forEach(n -> named.add("network " + n.name()));
        assertEquals(List.of(), named, "nothing named for the attempt is left");
    }

    @Test
    public void aRunStepKilledForMemoryIsNotWorkerDeathAndTheBuildGoesOn(@TempDir Path dir) throws Exception {
        // T5 gate F6 carry (1). The worker gets 1 GiB; one RUN step grows past it and is
        // OOM-killed, which sets the WORKER's OOMKilled flag while its daemon keeps building.
        // The step tolerates its own death, so the build must succeed.
        AtomicInteger released = new AtomicInteger();
        String grow = "awk 'BEGIN { s = sprintf(\"%1048576s\", \"\"); for (i = 1; i <= 1600; i++) a[i] = s \"\" i }'";
        ContextSource source = source(dir, "RUN [\"sh\", \"-c\", \"" + grow.replace("\"", "\\\"")
                + " || echo survived > /survived\"]\nRUN [\"cat\", \"/survived\"]\n", released);
        Claimed c = claimed();
        Handle h = handle(c);
        AtomicBoolean sawOomFlag = new AtomicBoolean();
        Thread watch = new Thread(() -> {
            try {
                while (!sawOomFlag.get()) {
                    try {
                        var s = docker.inspectContainer(h.worker()).state();
                        if (Boolean.TRUE.equals(s.oomKilled()) && s.running()) {
                            sawOomFlag.set(true);
                        }
                    } catch (NotFoundException e) {
                        // not yet, or already disposed
                    }
                    Thread.sleep(250);
                }
            } catch (Exception e) {
                // reported by the assertion below
            }
        });
        watch.setDaemon(true);
        watch.start();
        Settings oneGig = new Settings("2", "1g", "512", "256m", "2097152", "204800");
        Outcome outcome = driver(oneGig, source).run(c, () -> false);
        watch.interrupt();
        assertInstanceOf(Built.class, outcome, outcome.toString());
        assertTrue(((Built) outcome).image().matches(registry.name + ":5000/content/bkd@sha256:[0-9a-f]{64}"));
        assertTrue(sawOomFlag.get(), "the worker was flagged OOMKilled while it still ran");
        assertEquals(1, released.get(), "the context is released once");
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aStopWhileARunStepSleepsDisposesOfTheWholeWorkerWithinTheBound(@TempDir Path dir) throws Exception {
        // T6 carry (a): the driver is blocked in a long call (buildctl, while a RUN sleeps).
        AtomicInteger released = new AtomicInteger();
        Claimed c = claimed();
        Handle h = handle(c);
        AtomicBoolean stop = new AtomicBoolean();
        long[] flipped = new long[1];
        long[] workerGone = new long[1];
        Thread watcher = whenClientRuns(h, () -> {
            try {
                Thread.sleep(15_000);
            } catch (InterruptedException e) {
                return;
            }
            flipped[0] = System.nanoTime();
            stop.set(true);
            // When the WORKER stops is what the lease needs: at the defaults the runner
            // flips the signal 10 s (renew_every / 2) before the database could expire it.
            try {
                workerGone[0] = untilStopped(h.worker());
            } catch (Exception e) {
                // reported by the assertion
            }
        });
        Hold record = new Hold();
        Outcome outcome = driverOn(record.wrap("none", "none"), source(dir, "RUN [\"sleep\", \"600\"]\n", released))
                .run(c, stop::get);
        long took = System.nanoTime() - flipped[0];
        watcher.join(10_000);
        System.out.println("SKALD-TIMING stop during RUN: returned " + took / 1_000_000 + " ms after the stop");
        assertStoppedInTime("stop during RUN", flipped[0], record.kill, workerGone[0]);
        assertInstanceOf(Stopped.class, outcome, outcome.toString());
        assertTrue(flipped[0] > 0, "the stop flipped while the client ran");
        // The signal is read within POLL; what follows is disposal itself, which the
        // daemon times (force-removing the worker kills the sleeping RUN with it).
        assertTrue(took < Duration.ofSeconds(90).toNanos(), "returned " + took / 1_000_000 + " ms after the stop");
        assertNothingLeft(c);
    }

    /**
     * A Docker client whose one chosen call, once armed, blocks until released and ignores
     * interrupts: a daemon call that hangs. The call then goes through, so an object it
     * creates appears late.
     */
    private static final class Hold {
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final AtomicBoolean armed = new AtomicBoolean();
        /** When the driver called killContainer, and when that call returned (nanoTime). */
        final long[] kill = new long[2];
        /** When positive: every frame of a followed log stream arrives this many ms late. */
        volatile long logFrameDelayMillis;
        /** When set: the work thread's first removeContainer of this name fails, as a daemon 500 would. */
        volatile String failRemoveOnce;
        /** Every method the work thread called, in order. */
        final List<String> workCalls = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        /** The first inspectContainer from outside the work thread: the stop path's kill. */
        final long[] firstStopCall = new long[1];

        DockerClient wrap(String method, String target) {
            return (DockerClient) Proxy.newProxyInstance(DockerClient.class.getClassLoader(),
                    new Class<?>[] {DockerClient.class}, (proxy, m, args) -> {
                        boolean interrupted = false;
                        if (m.getName().equals(method) && args != null
                                && java.util.Arrays.stream(args).anyMatch(a -> target.equals(a instanceof Volume v ? v.name() : a))
                                && armed.compareAndSet(true, false)) {
                            entered.countDown();
                            while (true) {
                                try {
                                    release.await();
                                    break;
                                } catch (InterruptedException e) {
                                    interrupted = true;
                                }
                            }
                        }
                        if (firstStopCall[0] == 0 && m.getName().equals("inspectContainer")
                                && !Thread.currentThread().getName().startsWith("skald-build-")) {
                            firstStopCall[0] = System.nanoTime();
                        }
                        if (Thread.currentThread().getName().startsWith("skald-build-")) {
                            workCalls.add(m.getName());
                            String fail = failRemoveOnce;
                            if (fail != null && m.getName().equals("removeContainer") && fail.equals(args[0])) {
                                failRemoveOnce = null;
                                throw new org.mandas.docker.client.exceptions.DockerException(
                                        "simulated transient failure of removeContainer " + fail);
                            }
                        }
                        boolean killing = m.getName().equals("killContainer") && kill[0] == 0;
                        if (killing) {
                            kill[0] = System.nanoTime();
                        }
                        try {
                            Object result = m.invoke(docker, args);
                            if (m.getName().equals("logs") && logFrameDelayMillis > 0) {
                                return slow((LogStream) result, logFrameDelayMillis);
                            }
                            return result;
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        } finally {
                            if (killing) {
                                kill[1] = System.nanoTime();
                            }
                            if (interrupted) {
                                Thread.currentThread().interrupt();
                            }
                        }
                    });
        }
    }

    /** A log stream whose every frame arrives {@code millis} late: a follower that falls behind. */
    private static LogStream slow(LogStream real, long millis) {
        return (LogStream) Proxy.newProxyInstance(LogStream.class.getClassLoader(), new Class<?>[] {LogStream.class},
                (proxy, m, args) -> {
                    if (m.getName().equals("next")) {
                        Thread.sleep(millis);
                    }
                    try {
                        return m.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    private static BuildKitDriver driverOn(DockerClient d, ContextSource source) {
        Images images = Images.of(WORKER, GATEWAY);
        DockerWorkerLauncher l = new DockerWorkerLauncher(d, WorkerProfile.load("runc-rootless"), images);
        return lastDriver = new BuildKitDriver(d, l, new BuildKitClient(d, l, images), source, logWriter,
                new Config(Settings.defaults(), 256,
                new Egress(List.of(registry.outer), registry.name, List.of("pypi.org"), List.of(), List.of(), List.of()),
                TestRegistry.CRED, POLL, Duration.ofSeconds(30), LOG_LIMITS));
    }

    /**
     * The bound, split into what the driver controls and what the daemon does. The driver
     * must ISSUE the worker's kill within one poll of the stop (plus a margin for the
     * label-checking inspect before it): asserted strictly. The daemon then ends the
     * container; at the defaults the lease leaves it renew_every / 2 = 10 s. Measured here
     * at 3 to 14 s on a shared host, so that half is printed and asserted only to be
     * under 30 s -- a driver that waited for its work thread (the settle, 30 s) fails it.
     * The 10 s margin on the target host is T10's measurement (WORKPLAN-BUNDLES.md T7).
     */
    private static void assertStoppedInTime(String what, long flipped, long[] kill, long stopped) {
        long issued = kill[0] - flipped;
        long returned = kill[1] - flipped;
        long gone = stopped - flipped;
        System.out.println("SKALD-TIMING " + what + ": kill issued " + issued / 1_000_000 + " ms, kill returned "
                + returned / 1_000_000 + " ms, worker stopped " + gone / 1_000_000 + " ms after the stop");
        assertTrue(kill[0] > 0 && issued >= 0 && issued < POLL.plusSeconds(4).toNanos(),
                what + ": the kill was issued within one poll: " + issued / 1_000_000 + " ms");
        assertTrue(stopped > 0 && gone < Duration.ofSeconds(30).toNanos(),
                what + ": the worker stopped without waiting for the work thread: " + gone / 1_000_000 + " ms");
    }

    /**
     * When the container stopped running (or is gone): what the lease needs is the untrusted
     * code stopped. A SIGKILLed worker exists, exited, until the disposal removes it.
     */
    private static long untilStopped(String container) throws Exception {
        while (true) {
            try {
                if (!docker.inspectContainer(container).state().running()) {
                    return System.nanoTime();
                }
            } catch (NotFoundException e) {
                return System.nanoTime();
            }
            Thread.sleep(100);
        }
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aStopRemovesTheWorkerAtOnceEvenWhileTheWorkThreadIsHungInADaemonCall(@TempDir Path dir)
            throws Exception {
        // The work thread's poll of the client hangs and ignores its interrupt, so it never
        // returns to see the abort: only the disposal done BEFORE waiting for it can remove
        // the worker within renew_every / 2.
        Claimed c = claimed();
        Handle h = handle(c);
        Hold hold = new Hold();
        AtomicBoolean stop = new AtomicBoolean();
        long[] times = new long[2];
        Thread side = whenClientRuns(h, () -> {
            try {
                Thread.sleep(10_000);
                hold.armed.set(true);
                if (!hold.entered.await(30, TimeUnit.SECONDS)) {
                    return;
                }
                times[0] = System.nanoTime();
                stop.set(true);
                times[1] = untilStopped(h.worker());
            } catch (Exception e) {
                // reported by the assertions
            }
        });
        Outcome outcome;
        BuildKitDriver d = driverOn(hold.wrap("inspectContainer", h.client()),
                source(dir, "RUN [\"sleep\", \"600\"]\n", new AtomicInteger()));
        try {
            outcome = d.run(c, stop::get);
        } finally {
            hold.release.countDown();
        }
        side.join(10_000);
        // The work thread was still in its held call when run() returned; it disposes of the
        // attempt as its last act once the call returns.
        d.lastWork.join(180_000);
        assertFalse(d.lastWork.isAlive(), "the work thread ended");
        assertInstanceOf(Stopped.class, outcome, outcome.toString());
        assertTrue(times[0] > 0, "the poll hung and the stop flipped");
        assertStoppedInTime("hung work thread", times[0], hold.kill, times[1]);
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aCreateThatOutlastsTheSettleLeavesNothingOnceItReturns(@TempDir Path dir) throws Exception {
        // 0c71146-F1: a create is in flight at the daemon when the stop comes, and returns
        // only after run() has: the context volume's create (in staging) and the client's
        // create (holding the credential in its configuration). The stop path removes only
        // containers, so no volume is removed under the late create (Docker would re-create
        // it unlabelled for the client's binds); the work thread disposes of everything as
        // its last act. Checked by label AND by name once the work thread has ended.
        for (String[] held : List.of(new String[] {"createVolume", "ctx"}, new String[] {"createContainer", "client"})) {
            Claimed c = claimed();
            Handle h = handle(c);
            Hold hold = new Hold();
            hold.armed.set(true);
            // 904eb75-F1: the work thread's own disposal meets one transient removal failure
            // of the late client (a daemon 500 during a kill). Its retry sleeps, which threw at
            // once while the stop's interrupt was still pending, and the disposal gave up.
            hold.failRemoveOnce = h.client();
            AtomicBoolean stop = new AtomicBoolean();
            Thread side = new Thread(() -> {
                try {
                    if (hold.entered.await(10, TimeUnit.MINUTES)) {
                        stop.set(true);
                    }
                } catch (InterruptedException e) {
                    // test over
                }
            });
            side.setDaemon(true);
            side.start();
            BuildKitDriver d = driverOn(hold.wrap(held[0], held[1].equals("ctx") ? h.contextVolume() : h.client()),
                    source(dir.resolve(held[1]), "RUN [\"true\"]\n", new AtomicInteger()));
            Outcome outcome;
            try {
                outcome = d.run(c, stop::get);
                assertTrue(d.lastWork.isAlive(), held[0] + ": the held call outlasted the settle");
            } finally {
                hold.release.countDown();
            }
            assertInstanceOf(Stopped.class, outcome, outcome.toString());
            d.lastWork.join(180_000);
            assertFalse(d.lastWork.isAlive(), held[0] + ": the work thread ended");
            if (held[1].equals("client")) {
                assertTrue(hold.failRemoveOnce == null, "the late client's removal failed once, and was retried");
            }
            assertNothingLeft(c);
        }
    }

    @Test
    @Timeout(value = 3, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aStopWhileTheContextIsStillBeingPreparedReturnsAtOnce() throws Exception {
        // The long call here is the context source, which never returns: only the poll
        // between waits can see the signal.
        Claimed c = claimed();
        CountDownLatch entered = new CountDownLatch(1);
        ContextSource blocked = build -> {
            entered.countDown();
            Thread.sleep(Long.MAX_VALUE);
            return null;
        };
        AtomicBoolean stop = new AtomicBoolean();
        long[] flipped = new long[1];
        Thread flip = new Thread(() -> {
            try {
                entered.await();
                Thread.sleep(3000);
                flipped[0] = System.nanoTime();
                stop.set(true);
            } catch (InterruptedException e) {
                // test over
            }
        });
        flip.start();
        Hold record = new Hold();
        Outcome outcome = driverOn(record.wrap("none", "none"), blocked).run(c, stop::get);
        long acted = record.firstStopCall[0] - flipped[0];
        System.out.println("SKALD-TIMING stop during prepare: the stop path's first inspect " + acted / 1_000_000
                + " ms after the stop");
        assertInstanceOf(Stopped.class, outcome, outcome.toString());
        // The work thread made no Docker call (it is inside prepare), so the first call is the
        // stop path's: the worker kill's inspect.
        assertTrue(record.firstStopCall[0] > 0 && acted >= 0 && acted < POLL.plusSeconds(2).toNanos(),
                "the stop was acted on within one poll: " + acted / 1_000_000 + " ms");
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aWorkerThatDiesMidBuildIsReportedAsSuch(@TempDir Path dir) throws Exception {
        AtomicInteger released = new AtomicInteger();
        Claimed c = claimed();
        Handle h = handle(c);
        whenClientRuns(h, () -> {
            try {
                Thread.sleep(10_000);
                docker.killContainer(h.worker());
            } catch (Exception e) {
                // reported by the outcome
            }
        });
        Outcome outcome = driver(Settings.defaults(), source(dir, "RUN [\"sleep\", \"600\"]\n", released))
                .run(c, () -> false);
        assertInstanceOf(Failed.class, outcome, outcome.toString());
        assertEquals("WORKER_DIED", ((Failed) outcome).code(), outcome.toString());
        assertEquals(1, released.get());
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 3, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aContextThatArrivesAfterTheStopLaunchesNothing(@TempDir Path dir) throws Exception {
        // The source ignores the interrupt and returns normally once the stop has come: the
        // work thread must not go on to launch a worker for a stopped attempt.
        Claimed c = claimed();
        AtomicBoolean stop = new AtomicBoolean();
        ContextSource ready = source(dir, "RUN [\"true\"]\n", new AtomicInteger());
        ContextSource late = build -> {
            while (!stop.get()) {
                Thread.onSpinWait();
            }
            long until = System.nanoTime() + 2_000_000_000L;
            while (System.nanoTime() < until) {
                Thread.onSpinWait();
            }
            return ready.prepare(build);
        };
        Thread flip = new Thread(() -> {
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                return;
            }
            stop.set(true);
        });
        flip.start();
        Hold record = new Hold();
        BuildKitDriver d = driverOn(record.wrap("none", "none"), late);
        Outcome outcome = d.run(c, stop::get);
        d.lastWork.join(60_000);
        assertInstanceOf(Stopped.class, outcome, outcome.toString());
        // No launch began: a launch's first act is createNetwork, and staging's is
        // createVolume. (The work thread's own disposal after the stop runs helper
        // containers, so createContainer alone would not tell.)
        assertTrue(record.workCalls.stream().noneMatch(m -> m.equals("createNetwork") || m.equals("createVolume")),
                "the work thread launched nothing: " + record.workCalls);
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aWorkerThatDiesUnderAHungClientIsReportedWithoutWaitingForTheClient(@TempDir Path dir)
            throws Exception {
        // The client is paused, so it never exits: only the death check in the poll loop can
        // end the attempt (a client hung on a dead worker).
        AtomicInteger released = new AtomicInteger();
        Claimed c = claimed();
        Handle h = handle(c);
        whenClientRuns(h, () -> {
            try {
                Thread.sleep(10_000);
                docker.pauseContainer(h.client());
                docker.killContainer(h.worker());
            } catch (Exception e) {
                // reported by the outcome
            }
        });
        Outcome outcome = driver(Settings.defaults(), source(dir, "RUN [\"sleep\", \"600\"]\n", released))
                .run(c, () -> false);
        assertInstanceOf(Failed.class, outcome, outcome.toString());
        assertEquals("WORKER_DIED", ((Failed) outcome).code(), outcome.toString());
        assertNothingLeft(c);
    }

    @Test
    public void aFailingStepIsABuildFailureWithItsLastLine(@TempDir Path dir) throws Exception {
        AtomicInteger released = new AtomicInteger();
        Claimed c = claimed();
        Outcome outcome = driver(Settings.defaults(), source(dir,
                "RUN [\"sh\", \"-c\", \"echo the step says \\u00e9 goodbye; exit 3\"]\n", released))
                .run(c, () -> false);
        assertInstanceOf(Failed.class, outcome, outcome.toString());
        Failed failed = (Failed) outcome;
        assertEquals("BUILD_FAILED", failed.code(), failed.toString());
        assertTrue(failed.detail().startsWith("exit 1: "), failed.detail());
        assertTrue(failed.detail().chars().allMatch(ch -> ch >= 0x20 && ch < 0x7f), failed.detail());
        assertTrue(failed.detail().length() <= BuildKitDriver.DETAIL_MAX);
        assertTrue(failed.detail().contains("did not complete successfully"),
                "the detail is buildctl's own last line: " + failed.detail());
        assertEquals(1, released.get());
        assertNothingLeft(c);
        // The log: finished with the outcome, and it ends with the step's own output and
        // the failure, where an admin looks first.
        LogFinal fin = logWriter.readFinal(c.contentId(), c.buildId()).orElseThrow();
        assertEquals("failed:BUILD_FAILED", fin.outcome());
        assertTrue(fin.complete());
        List<String> texts = texts(c);
        assertTrue(texts.stream().anyMatch(l -> l.contains("the step says " + (char) 0xe9 + " goodbye")), texts.toString());
        assertTrue(texts.get(texts.size() - 1).startsWith("[skald] failed: BUILD_FAILED exit 1: "),
                texts.get(texts.size() - 1));
    }

    /** Every record of the attempt's log, read back from the store, in order. */
    private static List<JsonNode> records(Claimed c) throws Exception {
        List<JsonNode> out = new java.util.ArrayList<>();
        for (long seq = 1; ; seq++) {
            String key = ObjectKeys.logChunk(c.contentId(), c.buildId(), seq);
            if (logStore.store.head(logStore.bucket, key).isEmpty()) {
                return out;
            }
            try (var in = logStore.store.open(logStore.bucket, key)) {
                for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                    out.add(new ObjectMapper().readTree(line));
                }
            }
        }
    }

    private static List<String> texts(Claimed c) throws Exception {
        return records(c).stream().filter(r -> r.has("t")).map(r -> r.path("t").asText()).toList();
    }

    @Test
    public void aBuildLogKeepsItsHeadAndItsTailAndEndsWithTheOutcome(@TempDir Path dir) throws Exception {
        // About 50 KiB of RUN output against a 16 KiB head and a 16 KiB tail: the head holds
        // the driver's own lines and the build's start, the middle is dropped and marked, and
        // the tail holds the end, the push included.
        Claimed c = claimed();
        Outcome outcome = driver(Settings.defaults(), source(dir,
                "RUN [\"sh\", \"-c\", \"i=0; while [ $i -lt 2000 ]; do echo flood-line-$i; i=$((i+1)); done\"]\n",
                new AtomicInteger())).run(c, () -> false);
        assertInstanceOf(Built.class, outcome, outcome.toString());
        assertNothingLeft(c);
        LogFinal fin = logWriter.readFinal(c.contentId(), c.buildId()).orElseThrow();
        assertEquals("built", fin.outcome());
        assertTrue(fin.complete());
        assertTrue(fin.truncated(), "the middle was dropped");
        List<JsonNode> r = records(c);
        long markers = r.stream().filter(x -> x.path("cut").isObject()).count();
        assertEquals(1, markers);
        assertTrue(r.get(0).path("t").asText().startsWith("[skald] attempt "), r.get(0).toString());
        int marker = 0;
        while (!r.get(marker).path("cut").isObject()) {
            marker++;
        }
        // Line numbers: contiguous on each side, and the marker counts the gap exactly.
        for (int i = 1; i < marker; i++) {
            assertEquals(r.get(i - 1).path("n").asLong() + 1, r.get(i).path("n").asLong());
        }
        assertEquals(r.get(marker - 1).path("n").asLong() + r.get(marker).path("cut").path("lines").asLong() + 1,
                r.get(marker + 1).path("n").asLong());
        List<String> tail = r.subList(marker + 1, r.size()).stream().map(x -> x.path("t").asText()).toList();
        assertTrue(tail.stream().anyMatch(l -> l.contains("pushing manifest")), "the push is in the tail");
        // buildctl prints a RUN's line as "#<step> <seconds> <text>".
        assertTrue(r.subList(0, marker).stream().anyMatch(x -> x.path("t").asText().endsWith(" flood-line-0")),
                "the flood began in the head");
        assertTrue(r.stream().noneMatch(x -> x.path("t").asText().endsWith(" flood-line-1000")),
                "the middle is gone");
        assertTrue(r.subList(marker + 1, r.size()).stream().anyMatch(x -> x.path("t").asText().endsWith(" flood-line-1999")),
                "the flood's end is in the tail");
    }

    @Test
    public void aFollowerThatLagsIsDrainedBeforeTheFailureIsDecided(@TempDir Path dir) throws Exception {
        // Every log frame arrives 100 ms late, so the follower is behind when the client
        // exits. The decision must wait for the rest of the output: a failure's detail is
        // its last line, and without the wait it would be a stale one.
        Claimed c = claimed();
        Hold slowLogs = new Hold();
        slowLogs.logFrameDelayMillis = 100;
        Outcome outcome = driverOn(slowLogs.wrap("none", "none"), source(dir,
                "RUN [\"sh\", \"-c\", \"i=0; while [ $i -lt 40 ]; do echo step-line-$i; i=$((i+1)); done; exit 3\"]\n",
                new AtomicInteger())).run(c, () -> false);
        assertInstanceOf(Failed.class, outcome, outcome.toString());
        assertEquals("BUILD_FAILED", ((Failed) outcome).code());
        assertTrue(((Failed) outcome).detail().contains("did not complete successfully"),
                "the detail is buildctl's real last line: " + ((Failed) outcome).detail());
        assertNothingLeft(c);
    }

    @Test
    public void aSuccessWhoseLogCannotBeFinishedIsALogFailure(@TempDir Path dir) throws Exception {
        // Every chunk persists, but final.json cannot be written: the image was pushed, yet
        // a success without a complete log is not one.
        var real = logStore.store;
        var noFinal = (eu.openanalytics.shinyproxy.publisher.storage.ObjectStore) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {eu.openanalytics.shinyproxy.publisher.storage.ObjectStore.class},
                (proxy, m, args) -> {
                    if (m.getName().equals("putIfAbsent") && String.valueOf(args[1]).endsWith("/final.json")) {
                        throw new ObjectStoreException("simulated outage at the end");
                    }
                    try {
                        return m.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
        logWriter = new BuildLogWriter(noFinal, logStore.bucket);
        Claimed c = claimed();
        Outcome outcome = driver(Settings.defaults(), source(dir, "RUN [\"true\"]\n", new AtomicInteger()))
                .run(c, () -> false);
        assertInstanceOf(Failed.class, outcome, outcome.toString());
        assertEquals("LOG_STORAGE", ((Failed) outcome).code(), outcome.toString());
        assertTrue(((Failed) outcome).detail().contains("simulated outage at the end"), outcome.toString());
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void aLogStoreThatGoesDownStopsTheBuild(@TempDir Path dir) throws Exception {
        // "If durability cannot be recovered, stop the build and report a storage/log
        // failure rather than mark a silent success." Every chunk write fails; the build
        // (a RUN that sleeps) is stopped and the attempt fails as LOG_STORAGE.
        var real = logStore.store;
        var down = (eu.openanalytics.shinyproxy.publisher.storage.ObjectStore) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {eu.openanalytics.shinyproxy.publisher.storage.ObjectStore.class},
                (proxy, m, args) -> {
                    if (m.getName().equals("putIfAbsent") && String.valueOf(args[1]).contains("/chunks/")) {
                        throw new ObjectStoreException("simulated outage");
                    }
                    try {
                        return m.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
        logWriter = new BuildLogWriter(down, logStore.bucket);
        Claimed c = claimed();
        long started = System.nanoTime();
        Outcome outcome = driver(Settings.defaults(), source(dir, "RUN [\"sleep\", \"300\"]\n", new AtomicInteger()))
                .run(c, () -> false);
        assertInstanceOf(Failed.class, outcome, outcome.toString());
        assertEquals("LOG_STORAGE", ((Failed) outcome).code(), outcome.toString());
        assertTrue(((Failed) outcome).detail().contains("simulated outage"), outcome.toString());
        assertTrue(System.nanoTime() - started < Duration.ofMinutes(4).toNanos(), "it did not wait for the sleep");
        assertNothingLeft(c);
        assertTrue(new BuildLogWriter(real, logStore.bucket).readFinal(c.contentId(), c.buildId()).isEmpty(),
                "no final.json for a log that failed");
    }

    @Test
    public void aContextThatCannotBePreparedLaunchesNothing() throws Exception {
        Claimed c = claimed();
        Outcome outcome = driver(Settings.defaults(), build -> {
            throw new IllegalStateException("no such bundle");
        }).run(c, () -> false);
        assertEquals(new Failed("CONTEXT", "no such bundle"), outcome);
        assertNothingLeft(c);
    }

    @Test
    public void detailsArePrintableAsciiAndBounded() {
        assertEquals("a?b??c", BuildKitDriver.detail("a" + (char) 0xe9 + "b\n" + (char) 0x1b + "c"));
        assertEquals(BuildKitDriver.DETAIL_MAX, BuildKitDriver.detail("x".repeat(500)).length());
        assertEquals("", BuildKitDriver.detail(null));
    }
}
