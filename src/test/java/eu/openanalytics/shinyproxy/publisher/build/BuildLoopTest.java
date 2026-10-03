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

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The loop never dies of what runOnce throws (T6 carry (c)), pauses when idle, and stops. */
public class BuildLoopTest {

    @Test
    public void whateverAnAttemptThrowsTheLoopGoesOn() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch done = new CountDownLatch(1);
        BuildLoop loop = new BuildLoop(() -> {
            int n = calls.incrementAndGet();
            switch (n) {
                case 1 -> throw new IllegalStateException("a database blip");
                case 2 -> throw new AssertionError("a driver bug, as an Error");
                case 3 -> throw new Exception("checked");
                case 4 -> {
                    return BuildRunner.Result.FAILED;
                }
                case 5 -> {
                    return BuildRunner.Result.PUBLISHING;
                }
                default -> {
                    done.countDown();
                    return BuildRunner.Result.IDLE;
                }
            }
        }, Duration.ofMillis(10));
        loop.start();
        try {
            assertTrue(done.await(10, TimeUnit.SECONDS), "the loop reached its sixth call");
        } finally {
            loop.stop();
        }
        assertEquals(3, loop.failures(), "three throws, each logged and survived");
        assertEquals(2, loop.attempts(), "two attempts that ran");
    }

    @Test
    public void anIdleLoopPausesAndStopEndsIt() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BuildLoop loop = new BuildLoop(() -> {
            calls.incrementAndGet();
            return BuildRunner.Result.IDLE;
        }, Duration.ofMillis(200));
        loop.start();
        Thread.sleep(1000);
        loop.stop();
        int seen = calls.get();
        assertTrue(seen >= 2 && seen <= 8, "paused between idle calls: " + seen + " calls in 1 s at 200 ms");
        Thread.sleep(500);
        assertEquals(seen, calls.get(), "nothing runs after stop");
    }
}
