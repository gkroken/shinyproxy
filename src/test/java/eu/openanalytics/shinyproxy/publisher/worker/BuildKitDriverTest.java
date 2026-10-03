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
import org.mandas.docker.client.builder.jersey.JerseyDockerClientBuilder;
import org.mandas.docker.client.exceptions.NotFoundException;
import org.mandas.docker.client.messages.Volume;

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
    }

    @AfterAll
    public static void stop() throws Exception {
        if (docker != null) {
            try {
                if (registry != null) {
                    registry.close();
                }
            } finally {
                docker.close();
            }
        }
    }

    private static BuildKitDriver driver(Settings settings, ContextSource source) {
        return new BuildKitDriver(docker, launcher, client, source, new Config(settings, 256,
                new Egress(List.of(registry.outer), registry.name, List.of("pypi.org"), List.of(), List.of(), List.of()),
                TestRegistry.CRED, POLL, Duration.ofSeconds(30)));
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
        assertEquals(List.of(), launcher.leftovers(handle(c)), "nothing of the attempt is left");
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
        /** The first inspectContainer from outside the work thread: the stop path's kill. */
        final long[] firstStopCall = new long[1];

        DockerClient wrap(String method, String target) {
            return (DockerClient) Proxy.newProxyInstance(DockerClient.class.getClassLoader(),
                    new Class<?>[] {DockerClient.class}, (proxy, m, args) -> {
                        boolean interrupted = false;
                        if (m.getName().equals(method) && args != null && args.length > 0
                                && target.equals(args[0] instanceof Volume v ? v.name() : args[0])
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
                        boolean killing = m.getName().equals("killContainer") && kill[0] == 0;
                        if (killing) {
                            kill[0] = System.nanoTime();
                        }
                        try {
                            return m.invoke(docker, args);
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

    private static BuildKitDriver driverOn(DockerClient d, ContextSource source) {
        Images images = Images.of(WORKER, GATEWAY);
        DockerWorkerLauncher l = new DockerWorkerLauncher(d, WorkerProfile.load("runc-rootless"), images);
        return new BuildKitDriver(d, l, new BuildKitClient(d, l, images), source, new Config(Settings.defaults(), 256,
                new Egress(List.of(registry.outer), registry.name, List.of("pypi.org"), List.of(), List.of(), List.of()),
                TestRegistry.CRED, POLL, Duration.ofSeconds(30)));
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
        try {
            outcome = driverOn(hold.wrap("inspectContainer", h.client()),
                    source(dir, "RUN [\"sleep\", \"600\"]\n", new AtomicInteger())).run(c, stop::get);
        } finally {
            hold.release.countDown();
        }
        side.join(10_000);
        assertInstanceOf(Stopped.class, outcome, outcome.toString());
        assertTrue(times[0] > 0, "the poll hung and the stop flipped");
        assertStoppedInTime("hung work thread", times[0], hold.kill, times[1]);
        assertNothingLeft(c);
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    public void anObjectMadeAfterTheFirstDisposalIsRemovedByTheSecond(@TempDir Path dir) throws Exception {
        // The context volume's create is in flight at the daemon when the stop comes; it lands
        // after the first disposal has looked for it. Only the disposal after the work thread
        // is joined can find it.
        Claimed c = claimed();
        Handle h = handle(c);
        Hold hold = new Hold();
        hold.armed.set(true);
        AtomicBoolean stop = new AtomicBoolean();
        Thread side = new Thread(() -> {
            try {
                if (!hold.entered.await(10, TimeUnit.MINUTES)) {
                    return;
                }
                stop.set(true);
                // The first pass is over once the attempt's network is gone: it is removed last.
                while (true) {
                    try {
                        docker.inspectNetwork(h.network());
                    } catch (NotFoundException e) {
                        break;
                    }
                    Thread.sleep(100);
                }
            } catch (Exception e) {
                // reported by the assertions
            } finally {
                hold.release.countDown();
            }
        });
        side.setDaemon(true);
        side.start();
        Outcome outcome = driverOn(hold.wrap("createVolume", h.contextVolume()),
                source(dir, "RUN [\"true\"]\n", new AtomicInteger())).run(c, stop::get);
        assertInstanceOf(Stopped.class, outcome, outcome.toString());
        assertTrue(stop.get(), "the stop flipped while the create was held");
        assertNothingLeft(c);
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
        assertEquals(1, released.get());
        assertNothingLeft(c);
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
        assertEquals("last", BuildKitDriver.lastLine("first\nlast\n\n  \n"));
        assertEquals("", BuildKitDriver.lastLine(""));
    }
}
