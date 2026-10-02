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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The build-worker profile of {@code spec/isolation-profile-v1.json}, turned into the
 * Docker API fields of one launch.
 *
 * <p><b>One definition.</b> The spec states each bound as the docker CLI argument the T3/T5
 * probes launched the worker with ({@code --memory=<memory_limit>}, ...). This class fills
 * the placeholders and parses every resulting argument by an exact rule into the API field
 * the CLI would have set. An argument in any other form is refused, so a spec edit that
 * this launcher cannot express stops the launch instead of being dropped.
 * {@code dev/fixtures/worker/cli-hostconfig.json} records what the CLI itself made of the
 * same arguments at production values, and {@code WorkerProfileTest} holds this class to
 * it.
 *
 * <p><b>Refuse to start, never run weaker</b> (the spec's {@code seam.refuse_to_start}). A
 * runtime must be {@code measured} and {@code selectable}, and its {@code enforces} list must
 * cover every bound's probe, except the bounds it records as {@code waived} (for
 * runc-rootless, no-new-privileges, signed off 2026-09-26). The daemon bounds are buildkitd's
 * own and hold under any runtime. A forbidden argument ({@code --privileged},
 * {@code seccomp=unconfined}, ...) anywhere in the profile is a refusal too.
 */
public final class WorkerProfile {

    static final String SPEC_RESOURCE = "skald/spec/isolation-profile-v1.json";
    static final String SECCOMP_RESOURCE = "skald/spec/build-worker-seccomp-v1.json";
    /** Stands in for the seccomp profile's path; the API takes the profile's JSON itself. */
    private static final String SECCOMP_TOKEN = "@seccomp-profile";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]*");
    private static final Pattern SIZE = Pattern.compile("([0-9]{1,15})([bkmg]?)");
    private static final Pattern CPUS = Pattern.compile("[0-9]{1,4}(?:\\.[0-9]{1,9})?");
    private static final Pattern COUNT = Pattern.compile("[1-9][0-9]{0,8}");
    /**
     * Docker's own networks. "host" shares the host's network namespace, and "bridge" (or
     * "default") is the network every other unconfigured container is on, so neither is an
     * attempt's isolated egress network.
     */
    private static final Set<String> RESERVED_NETWORKS = Set.of("host", "bridge", "default", "none");

    /**
     * The configurable values a deployment chooses, as the strings the spec's placeholders
     * take. Each is checked here, so nothing reaches a launch argument unparsed.
     */
    public record Settings(String cpuQuota, String memoryLimit, String pidLimit, String tmpfsSize,
                           String stepLogMaxBytes, String stepLogMaxBytesPerSecond) {

        public Settings {
            if (!CPUS.matcher(cpuQuota).matches() || new BigDecimal(cpuQuota).signum() <= 0) {
                throw new IllegalArgumentException("cpu quota " + cpuQuota);
            }
            for (String size : List.of(memoryLimit, tmpfsSize)) {
                if (!SIZE.matcher(size).matches() || bytes(size) <= 0) {
                    throw new IllegalArgumentException("size " + size);
                }
            }
            for (String count : List.of(pidLimit, stepLogMaxBytes, stepLogMaxBytesPerSecond)) {
                if (!COUNT.matcher(count).matches()) {
                    throw new IllegalArgumentException("count " + count);
                }
            }
        }

        /**
         * WORKPLAN-BUNDLES.md's initial ceilings: 2 CPUs, 4 GiB with no extra swap (swap is
         * set equal to memory), 512 PIDs; the probes' 256 MiB scratch tmpfs; BuildKit's own
         * step-log defaults, pinned so an upstream change cannot lift them unnoticed.
         */
        public static Settings defaults() {
            return new Settings("2", "4g", "512", "256m", "2097152", "204800");
        }

        Map<String, String> placeholders() {
            Map<String, String> out = new TreeMap<>();
            out.put("cpu_quota", cpuQuota);
            out.put("memory_limit", memoryLimit);
            out.put("pid_limit", pidLimit);
            out.put("tmpfs_size", tmpfsSize);
            out.put("step_log_max_bytes", stepLogMaxBytes);
            out.put("step_log_max_bytes_per_second", stepLogMaxBytesPerSecond);
            return out;
        }
    }

    /** One launch's Docker API fields, as the CLI would have set them. */
    public record Launch(long nanoCpus, long memory, long memorySwap, int pidsLimit,
                         boolean readOnlyRootfs, Map<String, String> tmpfs,
                         List<String> securityOpt, String networkMode, List<String> binds,
                         List<String> env) {

        public Launch {
            tmpfs = Collections.unmodifiableMap(new LinkedHashMap<>(tmpfs));
            securityOpt = List.copyOf(securityOpt);
            binds = List.copyOf(binds);
            env = List.copyOf(env);
        }
    }

    private final String runtime;
    /** Bound name -> argument template, every bound this runtime launches with, by name. */
    private final TreeMap<String, String> arguments;
    private final String seccompJson;

    private WorkerProfile(String runtime, TreeMap<String, String> arguments, String seccompJson) {
        this.runtime = runtime;
        this.arguments = arguments;
        this.seccompJson = seccompJson;
    }

    /** The shipped profile for {@code runtime}, or a refusal saying why it cannot launch. */
    public static WorkerProfile load(String runtime) {
        return parse(resource(SPEC_RESOURCE), runtime, compact(resource(SECCOMP_RESOURCE)));
    }

    public String runtime() {
        return runtime;
    }

    static WorkerProfile parse(JsonNode spec, String runtime, String seccompJson) {
        JsonNode rt = spec.path("seam").path("runtimes").path(runtime);
        if (rt.isMissingNode()) {
            throw new IllegalStateException("the isolation profile has no runtime " + runtime);
        }
        if (!"measured".equals(rt.path("status").asText()) || !rt.path("selectable").asBoolean(false)) {
            throw new IllegalStateException("runtime " + runtime
                    + " is not measured and selectable; refusing to start a worker under it");
        }
        Set<String> enforces = new HashSet<>();
        rt.path("enforces").forEach(e -> enforces.add(e.asText()));
        Set<String> waived = new HashSet<>();
        rt.path("waived").fieldNames().forEachRemaining(waived::add);

        JsonNode profile = spec.path("profiles").path("build-worker");
        List<String> forbidden = new ArrayList<>();
        profile.path("forbidden_arguments").forEach(f -> forbidden.add(f.asText()));
        if (forbidden.isEmpty()) {
            throw new IllegalStateException("the build-worker profile lists no forbidden arguments");
        }
        TreeMap<String, String> arguments = new TreeMap<>();
        for (String section : List.of("bounds", "daemon_bounds")) {
            Iterator<Map.Entry<String, JsonNode>> it = profile.path(section).fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> bound = it.next();
                String name = bound.getKey();
                String argument = bound.getValue().path("argument").asText();
                refuseForbidden(name, argument, forbidden);
                if (waived.contains(name)) {
                    continue;
                }
                // buildkitd enforces its own bounds whatever runs it; the runtime's must be
                // measured under it.
                String probe = bound.getValue().path("probe").asText();
                if (section.equals("bounds") && !enforces.contains(probe)) {
                    throw new IllegalStateException("runtime " + runtime + " does not enforce '"
                            + probe + "' (bound " + name + "); refusing to start rather than "
                            + "run without it");
                }
                arguments.put(name, argument);
            }
        }
        if (!arguments.containsKey("seccomp") || !arguments.containsKey("network")
                || !arguments.containsKey("workspace")) {
            throw new IllegalStateException("the profile lacks a seccomp, network or workspace bound");
        }
        return new WorkerProfile(runtime, arguments, seccompJson);
    }

    /**
     * Refuses {@code argument} if it is, or begins as, a forbidden one. Checked on the spec's
     * templates. A filled value cannot produce one: the only placeholder that could
     * ({@code --network=<egress_network>} filled with "host") is closed by the reserved
     * network names, and the form parser refuses everything else.
     */
    private static void refuseForbidden(String bound, String argument, List<String> forbidden) {
        for (String f : forbidden) {
            if (argument.equals(f) || argument.startsWith(f + "=") || argument.startsWith(f + ":")
                    || argument.startsWith(f + " ")) {
                throw new IllegalStateException("bound " + bound + " is the forbidden argument " + f);
            }
        }
    }

    /**
     * The API fields for one launch on {@code network} with workspace {@code quotaVolume}.
     *
     * @throws IllegalStateException when a filled argument is in a form this cannot express
     */
    public Launch launch(Settings settings, String network, String quotaVolume) {
        if (!NAME.matcher(network).matches() || !NAME.matcher(quotaVolume).matches()) {
            throw new IllegalArgumentException("network and volume names must be plain names");
        }
        if (RESERVED_NETWORKS.contains(network)) {
            throw new IllegalArgumentException("'" + network + "' is Docker's own network, not "
                    + "an attempt's isolated one");
        }
        Map<String, String> fill = new TreeMap<>(settings.placeholders());
        fill.put("egress_network", network);
        fill.put("quota_volume", quotaVolume);
        fill.put("seccomp_profile", SECCOMP_TOKEN);

        Long nanoCpus = null;
        Long memory = null;
        Long memorySwap = null;
        Integer pids = null;
        boolean readOnly = false;
        Map<String, String> tmpfs = new LinkedHashMap<>();
        List<String> securityOpt = new ArrayList<>();
        String networkMode = null;
        List<String> binds = new ArrayList<>();
        List<String> env = new ArrayList<>();
        for (Map.Entry<String, String> bound : arguments.entrySet()) {
            String arg = fillIn(bound.getKey(), bound.getValue(), fill);
            Matcher m;
            if ((m = Pattern.compile("--cpus=(" + CPUS.pattern() + ")").matcher(arg)).matches()) {
                nanoCpus = once(nanoCpus, new BigDecimal(m.group(1)).movePointRight(9)
                        .longValueExact(), arg);
            } else if ((m = Pattern.compile("--memory=(.+)").matcher(arg)).matches()) {
                memory = once(memory, bytes(m.group(1)), arg);
            } else if ((m = Pattern.compile("--memory-swap=(.+)").matcher(arg)).matches()) {
                memorySwap = once(memorySwap, bytes(m.group(1)), arg);
            } else if ((m = Pattern.compile("--pids-limit=(" + COUNT.pattern() + ")").matcher(arg)).matches()) {
                pids = once(pids, Integer.valueOf(m.group(1)), arg);
            } else if (arg.equals("--read-only")) {
                readOnly = true;
            } else if ((m = Pattern.compile("--tmpfs=(/[A-Za-z0-9/_.-]+):([A-Za-z0-9,=._-]+)").matcher(arg)).matches()) {
                if (tmpfs.put(m.group(1), m.group(2)) != null) {
                    throw new IllegalStateException("two tmpfs at " + m.group(1));
                }
            } else if (arg.equals("--security-opt=no-new-privileges")) {
                securityOpt.add("no-new-privileges");
            } else if (arg.equals("--security-opt=seccomp=" + SECCOMP_TOKEN)) {
                securityOpt.add("seccomp=" + seccompJson);
            } else if ((m = Pattern.compile("--network=(" + NAME.pattern() + ")").matcher(arg)).matches()) {
                networkMode = once(networkMode, m.group(1), arg);
            } else if ((m = Pattern.compile("--volume=(" + NAME.pattern() + "):/workspace").matcher(arg)).matches()) {
                binds.add(m.group(1) + ":/workspace");
            } else if ((m = Pattern.compile("--env=([A-Z_][A-Z0-9_]*=[A-Za-z0-9._/-]*)").matcher(arg)).matches()) {
                env.add(m.group(1));
            } else {
                throw new IllegalStateException("bound " + bound.getKey() + ": the argument '"
                        + arg + "' is in no form this launcher can express; refusing to start");
            }
        }
        if (nanoCpus == null || memory == null || memorySwap == null || pids == null
                || networkMode == null || binds.isEmpty()) {
            throw new IllegalStateException("the profile does not bound cpu, memory, swap, "
                    + "pids, network and workspace");
        }
        return new Launch(nanoCpus, memory, memorySwap, pids, readOnly, tmpfs, securityOpt,
                networkMode, binds, env);
    }

    private static String fillIn(String name, String template, Map<String, String> fill) {
        String arg = template;
        for (Map.Entry<String, String> f : fill.entrySet()) {
            arg = arg.replace("<" + f.getKey() + ">", f.getValue());
        }
        if (arg.contains("<") || arg.contains(">")) {
            throw new IllegalStateException("bound " + name + " has a placeholder no value fills: "
                    + template);
        }
        return arg;
    }

    private static <T> T once(T previous, T value, String arg) {
        if (previous != null) {
            throw new IllegalStateException("the profile sets " + arg + " twice");
        }
        return value;
    }

    /** Docker's binary units: k, m, g are powers of 1024; no suffix or b is bytes. */
    static long bytes(String size) {
        Matcher m = SIZE.matcher(size);
        if (!m.matches()) {
            throw new IllegalStateException("not a size: " + size);
        }
        long n = Long.parseLong(m.group(1));
        int shift = switch (m.group(2)) {
            case "k" -> 10;
            case "m" -> 20;
            case "g" -> 30;
            default -> 0;
        };
        if (Long.numberOfLeadingZeros(n) <= shift) {
            throw new IllegalStateException("size overflows: " + size);
        }
        return n << shift;
    }

    /** The profile as the CLI sends it: the same JSON with insignificant whitespace removed. */
    static String compact(JsonNode seccomp) {
        try {
            return JSON.writeValueAsString(seccomp);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static JsonNode resource(String name) {
        try (InputStream in = WorkerProfile.class.getClassLoader().getResourceAsStream(name)) {
            if (in == null) {
                throw new IllegalStateException(name + " is not packaged");
            }
            return JSON.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
