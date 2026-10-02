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

import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Launch;
import eu.openanalytics.shinyproxy.publisher.worker.WorkerProfile.Settings;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.ListContainersParam;
import org.mandas.docker.client.DockerClient.ListNetworksParam;
import org.mandas.docker.client.DockerClient.ListVolumesParam;
import org.mandas.docker.client.DockerClient.LogsParam;
import org.mandas.docker.client.DockerClient.RemoveContainerParam;
import org.mandas.docker.client.LogStream;
import org.mandas.docker.client.exceptions.DockerException;
import org.mandas.docker.client.exceptions.NotFoundException;
import org.mandas.docker.client.exceptions.VolumeNotFoundException;
import org.mandas.docker.client.messages.ContainerConfig;
import org.mandas.docker.client.messages.ContainerExit;
import org.mandas.docker.client.messages.HostConfig;
import org.mandas.docker.client.messages.NetworkConfig;
import org.mandas.docker.client.messages.Volume;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The trusted launcher: starts one rootless BuildKit worker for one attempt, with
 * everything it needs and nothing it should not have, and disposes of all of it
 * (WORKPLAN-BUNDLES.md "Build sandbox and dependency network"; decision 6; T7 part 3).
 *
 * <p>Per attempt, every object labelled {@value #ATTEMPT_LABEL}=&lt;attempt&gt;:
 * <ul>
 *   <li>an INTERNAL network, the worker's only one: no route out except the gateway;</li>
 *   <li>the egress gateway (squid, {@link GatewayConfig}'s rule) on that network and on the
 *       operator's outer networks, where the registry and mirrors live;</li>
 *   <li>a config volume holding squid.conf and buildkitd.toml, written by a helper and
 *       mounted read-only. Files reach containers through volumes, never host paths: the
 *       platform itself runs in a container, and decision 6 forbids host bind mounts;</li>
 *   <li>the socket volume, shared only with the trusted client (decision 2026-09-26);</li>
 *   <li>the workspace: a loop-backed ext4 volume of a fixed size, mounted nosuid,nodev, made
 *       by a privileged setup container. That privilege is the launcher's (decision 6
 *       allows it); the worker never sees the device;</li>
 *   <li>the worker, launched with {@link WorkerProfile}'s fields exactly, plus the
 *       read-only-root environment and the daemon's arguments the probes measured
 *       (dev/shipping_worker.py: ENVIRONMENT, SOCKET_MOUNT, DAEMON_ARGS).</li>
 * </ul>
 *
 * <p>A launch that fails part-way disposes of what it made before rethrowing. Disposal is
 * idempotent, never stops at the first error, and reports what it could not remove: an
 * object it reports was left behind is the caller's to escalate, not to forget.
 */
public final class DockerWorkerLauncher {

    public static final String ATTEMPT_LABEL = "eu.skald.build-attempt";
    /** The worker's uid, owner of its workspace and socket (dev/shipping_worker.py). */
    static final String WORKER_UID = "2401";
    static final String SOCKET_MOUNT = "/skald-sock";
    public static final String SOCKET_ADDRESS = "unix://" + SOCKET_MOUNT + "/bk.sock";
    static final String CONFIG_MOUNT = "/skald-conf";
    static final List<String> ENVIRONMENT = List.of("HOME=/tmp/home", "TMPDIR=/tmp",
            "XDG_RUNTIME_DIR=/tmp/run");
    static final List<String> DAEMON_ARGS = List.of("--oci-worker-snapshotter=native", "--root",
            "/workspace/buildkit", "--addr", SOCKET_ADDRESS, "--config", CONFIG_MOUNT + "/buildkitd.toml");
    /** Where quota images live: one shared named volume, one file per attempt. */
    static final String QUOTA_IMAGES_VOLUME = "skald-quota-images";
    private static final Pattern ATTEMPT = Pattern.compile("[a-z0-9]{8,40}");
    static final long GATEWAY_MEMORY = 256L << 20;
    static final int REMOVAL_ATTEMPTS = 12;
    static final long REMOVAL_PAUSE_MILLIS = 5_000;
    private static final Pattern LOOP = Pattern.compile("/dev/loop[0-9]{1,4}");

    /** The images the launcher runs, each by digest: the derived worker and gateway, a
     *  small helper (busybox) and the privileged setup image (mkfs.ext4, losetup). */
    public record Images(String worker, String gateway, String helper, String setup) {

        /** The static busybox the probes use (dev/shipping_worker.py BUSYBOX_IMAGE). */
        public static final String HELPER = "busybox@sha256:"
                + "ea2b9914a16a4ac1981994af97b318f7c7d4db76b580c56177f08bf76f4a0be8";
        /** debian:12-slim, pinned: the probes' quota setup image (dev/quota_volume.py). */
        public static final String SETUP = "debian@sha256:"
                + "88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171";

        /** The operator-built worker and gateway with the pinned helper and setup images. */
        public static Images of(String worker, String gateway) {
            return new Images(worker, gateway, HELPER, SETUP);
        }
    }

    /** Where the gateway may let the worker go. */
    public record Egress(List<String> outerNetworks, String registry, List<String> repos,
                         List<String> privateMirrors, List<String> gatewayDns,
                         List<String> gatewayExtraHosts) {

        public Egress {
            outerNetworks = List.copyOf(outerNetworks);
            repos = List.copyOf(repos);
            privateMirrors = List.copyOf(privateMirrors);
            gatewayDns = List.copyOf(gatewayDns);
            gatewayExtraHosts = List.copyOf(gatewayExtraHosts);
        }
    }

    public record Request(String attemptId, Settings settings, int quotaMegabytes, Egress egress) {

        public Request {
            if (!ATTEMPT.matcher(attemptId).matches()) {
                throw new IllegalArgumentException("an attempt id is 8-40 of [a-z0-9]");
            }
            if (quotaMegabytes < 64 || quotaMegabytes > 1 << 20) {
                throw new IllegalArgumentException("quota " + quotaMegabytes + " MiB");
            }
        }
    }

    /** One launched worker, by the names of everything it owns. Opaque to callers. */
    public record Handle(String attemptId, String network, String gateway, String worker,
                         String socketVolume, String configVolume, String workspaceVolume,
                         String quotaImage) {
    }

    private final DockerClient docker;
    private final WorkerProfile profile;
    private final Images images;

    public DockerWorkerLauncher(DockerClient docker, WorkerProfile profile, Images images) {
        this.docker = docker;
        this.profile = profile;
        this.images = images;
    }

    static Handle handle(String attemptId) {
        String p = "skald-b-" + attemptId;
        return new Handle(attemptId, p + "-net", p + "-gw", p + "-worker", p + "-sock",
                p + "-conf", p + "-ws", "skald-quota-" + attemptId + ".img");
    }

    /**
     * Starts the attempt's worker and returns once its daemon reports a worker, or throws
     * after disposing of everything it made.
     */
    public Handle launch(Request request) throws InterruptedException {
        Handle h = handle(request.attemptId());
        Map<String, String> labels = Map.of(ATTEMPT_LABEL, request.attemptId());
        // Outside the try: a refusal has made nothing, so there is nothing to dispose, and
        // disposing would tear down whatever holds the names -- which, when it carries this
        // attempt's label, is a LIVE launch of the same attempt (67b7c17-F1). A stale one is
        // the reconciliation's to sweep: it knows from the lease that the attempt is dead.
        try {
            refuseTakenNames(h);
        } catch (DockerException e) {
            throw new IllegalStateException("could not check the attempt's names: " + e.getMessage(), e);
        }
        try {
            String squid = GatewayConfig.squidConf(request.egress().registry(),
                    request.egress().repos(), request.egress().privateMirrors());
            Launch launch = profile.launch(request.settings(), h.network(), h.workspaceVolume());

            docker.createNetwork(NetworkConfig.builder().name(h.network()).internal(true)
                    .checkDuplicate(true).labels(labels).build());
            for (String v : List.of(h.socketVolume(), h.configVolume())) {
                createOwnedVolume(v, labels, null);
            }
            writeConfig(h, squid, buildkitdToml(request.egress().registry()), labels);
            startGateway(h, request.egress(), labels);
            makeWorkspace(h, request.quotaMegabytes(), labels);
            startWorker(h, launch, labels);
            return h;
        } catch (InterruptedException e) {
            dispose(h);
            throw e;
        } catch (DockerException | RuntimeException e) {
            List<String> left = dispose(h);
            throw new IllegalStateException("could not launch the worker for attempt "
                    + request.attemptId() + ": " + e.getMessage()
                    + (left.isEmpty() ? "" : "; LEFT BEHIND: " + left), e);
        }
    }

    /**
     * Refuses to launch over an object that already carries one of the attempt's names.
     * Docker's volume create is idempotent by name and returns an existing volume whatever
     * its driver and options, so a stale or foreign volume would otherwise become the
     * worker's workspace or the gateway's configuration (9a2658d-F1). Containers and the
     * network would refuse a duplicate themselves; they are checked here too, so the
     * refusal comes before anything is made.
     */
    private void refuseTakenNames(Handle h) throws DockerException, InterruptedException {
        List<String> taken = new ArrayList<>();
        for (String v : List.of(h.workspaceVolume(), h.socketVolume(), h.configVolume())) {
            try {
                docker.inspectVolume(v);
                taken.add("volume " + v);
            } catch (NotFoundException | VolumeNotFoundException e) {
                // free
            }
        }
        for (String c : List.of(h.worker(), h.gateway())) {
            try {
                docker.inspectContainer(c);
                taken.add("container " + c);
            } catch (NotFoundException | VolumeNotFoundException e) {
                // free
            }
        }
        try {
            docker.inspectNetwork(h.network());
            taken.add("network " + h.network());
        } catch (NotFoundException | VolumeNotFoundException e) {
            // free
        }
        if (!taken.isEmpty()) {
            throw new IllegalStateException("the attempt's names are already taken, refusing to "
                    + "adopt what is there: " + taken);
        }
    }

    /**
     * Creates a volume and then checks the daemon made THIS one: our labels, and when
     * {@code options} is given, exactly those driver options. A name taken between the
     * check above and this call would otherwise be adopted silently.
     */
    void createOwnedVolume(String name, Map<String, String> labels, Map<String, String> options)
            throws DockerException, InterruptedException {
        Volume.Builder b = Volume.builder().name(name).labels(labels);
        if (options != null) {
            b.driver("local").driverOpts(options);
        }
        docker.createVolume(b.build());
        Volume made = docker.inspectVolume(name);
        Map<String, String> got = made.labels() == null ? Map.of() : made.labels();
        if (!labels.entrySet().stream().allMatch(e -> e.getValue().equals(got.get(e.getKey())))
                || (options != null && !options.equals(made.options()))) {
            throw new IllegalStateException("volume " + name + " is not the one this launch made");
        }
    }

    /** buildkitd.toml: the registry speaks plain HTTP, reached only through the gateway. */
    static String buildkitdToml(String registry) {
        return "[registry.\"" + registry + ":5000\"]\n  http = true\n";
    }

    private void writeConfig(Handle h, String squid, String toml, Map<String, String> labels)
            throws DockerException, InterruptedException {
        // The texts travel as environment values of a one-shot helper and are written with
        // printf %s, so no shell parses their content.
        runHelper("conf-" + h.attemptId(), images.helper(), false,
                List.of(h.configVolume() + ":/c", h.socketVolume() + ":/s"),
                List.of("SQUID_CONF=" + squid, "BUILDKITD_TOML=" + toml),
                List.of("sh", "-c", "printf %s \"$SQUID_CONF\" > /c/squid.conf"
                        + " && printf %s \"$BUILDKITD_TOML\" > /c/buildkitd.toml"
                        + " && chmod 0644 /c/squid.conf /c/buildkitd.toml"
                        + " && chown " + WORKER_UID + ":" + WORKER_UID + " /s"), labels);
    }

    private void startGateway(Handle h, Egress egress, Map<String, String> labels)
            throws DockerException, InterruptedException {
        // Hardened (9a2658d N1): squid parses every request build code sends and sits on the
        // operator's outer networks. It runs as its own user already; it needs nothing
        // writable but /tmp (measured: with pid_filename none, stdio logs and no cache_dir it
        // starts read-only, all capabilities dropped, under no-new-privileges).
        HostConfig.Builder hc = HostConfig.builder()
                .networkMode(h.network())
                .binds(h.configVolume() + ":" + CONFIG_MOUNT + ":ro")
                .readonlyRootfs(true)
                .tmpfs(Map.of("/tmp", "rw,noexec,nosuid,nodev,size=16m"))
                .capDrop("ALL")
                .securityOpt("no-new-privileges")
                .memory(GATEWAY_MEMORY)
                .memorySwap(GATEWAY_MEMORY)
                .pidsLimit(128)
                .nanoCpus(1_000_000_000L)
                .privileged(false);
        if (!egress.gatewayDns().isEmpty()) {
            hc.dns(egress.gatewayDns());
        }
        if (!egress.gatewayExtraHosts().isEmpty()) {
            hc.extraHosts(egress.gatewayExtraHosts());
        }
        docker.createContainer(ContainerConfig.builder().image(images.gateway())
                .cmd("squid", "-N", "-f", CONFIG_MOUNT + "/squid.conf")
                .labels(labels).hostConfig(hc.build()).build(), h.gateway());
        for (String outer : egress.outerNetworks()) {
            docker.connectToNetwork(h.gateway(), outer);
        }
        docker.startContainer(h.gateway());
        waitForLog(h.gateway(), "Accepting HTTP", 30);
    }

    private void makeWorkspace(Handle h, int megabytes, Map<String, String> labels)
            throws DockerException, InterruptedException {
        try {
            docker.inspectVolume(QUOTA_IMAGES_VOLUME);
        } catch (NotFoundException | VolumeNotFoundException e) {
            // mandas reports a missing volume as VolumeNotFoundException, which is NOT a
            // NotFoundException (it extends DockerException directly).
            docker.createVolume(Volume.builder().name(QUOTA_IMAGES_VOLUME).build());
        }
        String out = runHelper("quota-" + h.attemptId(), images.setup(), true,
                List.of(QUOTA_IMAGES_VOLUME + ":/s"), List.of(),
                List.of("sh", "-c", "truncate -s " + megabytes + "M /s/" + h.quotaImage()
                        + " && mkfs.ext4 -q -F /s/" + h.quotaImage()
                        + " && losetup --find --show /s/" + h.quotaImage()), labels);
        String loop = out.strip().lines().reduce((a, b) -> b).orElse("");
        if (!LOOP.matcher(loop).matches()) {
            throw new IllegalStateException("the quota image did not attach: " + out.strip());
        }
        Map<String, String> volumeLabels = new LinkedHashMap<>(labels);
        volumeLabels.put("eu.skald.loop-device", loop);
        createOwnedVolume(h.workspaceVolume(), volumeLabels,
                Map.of("type", "ext4", "device", loop, "o", "nosuid,nodev"));
        runHelper("chown-" + h.attemptId(), images.helper(), false,
                List.of(h.workspaceVolume() + ":/w"), List.of(),
                List.of("chown", WORKER_UID + ":" + WORKER_UID, "/w"), labels);
    }

    private void startWorker(Handle h, Launch launch, Map<String, String> labels)
            throws DockerException, InterruptedException {
        List<String> binds = new ArrayList<>(launch.binds());
        binds.add(h.socketVolume() + ":" + SOCKET_MOUNT);
        binds.add(h.configVolume() + ":" + CONFIG_MOUNT + ":ro");
        List<String> env = new ArrayList<>(launch.env());
        env.addAll(ENVIRONMENT);
        String proxy = "http://" + h.gateway() + ":" + GatewayConfig.PORT;
        env.add("http_proxy=" + proxy);
        env.add("HTTP_PROXY=" + proxy);
        HostConfig hc = HostConfig.builder()
                .nanoCpus(launch.nanoCpus())
                .memory(launch.memory())
                .memorySwap(launch.memorySwap())
                .pidsLimit(launch.pidsLimit())
                .readonlyRootfs(launch.readOnlyRootfs())
                .tmpfs(launch.tmpfs())
                .securityOpt(launch.securityOpt())
                .networkMode(launch.networkMode())
                .binds(binds)
                .privileged(false)
                .build();
        docker.createContainer(ContainerConfig.builder().image(images.worker()).cmd(DAEMON_ARGS)
                .env(env).labels(labels).hostConfig(hc).build(), h.worker());
        docker.startContainer(h.worker());
        // 120 s: a 60 s wait was missed once under load (the daemon stalled after its fsverity
        // check and reported a worker only later); a healthy start takes a few seconds.
        waitForLog(h.worker(), "found worker", 120);
    }

    /**
     * Removes everything the attempt owns, in dependency order, and returns what is still
     * there afterwards (empty when clean). Never throws for a missing object; every step is
     * attempted whatever an earlier one did.
     */
    public List<String> dispose(Handle h) throws InterruptedException {
        // Only what carries THIS attempt's label is removed: an object that merely has one
        // of its names (a refused launch over a foreign volume, 9a2658d-F1) is not ours.
        List<String> errors = new ArrayList<>();
        for (String c : List.of(h.worker(), h.gateway(), "skald-helper-conf-" + h.attemptId(),
                "skald-helper-quota-" + h.attemptId(), "skald-helper-chown-" + h.attemptId())) {
            quietly(errors, () -> {
                if (ours(docker.inspectContainer(c).config().labels(), h)) {
                    retrying(() -> docker.removeContainer(c, RemoveContainerParam.forceKill(),
                            RemoveContainerParam.removeVolumes()));
                }
            });
        }
        for (String v : List.of(h.workspaceVolume(), h.socketVolume(), h.configVolume())) {
            quietly(errors, () -> {
                if (ours(docker.inspectVolume(v).labels(), h)) {
                    retrying(() -> docker.removeVolume(v));
                }
            });
        }
        // Detach EVERY device still backed by this attempt's image, found by its backing file
        // as leftovers() finds it -- not through the volume's label, which is missing when
        // the launch failed before the volume existed (9a2658d-F2). The file-name match is the
        // guard against a reused device number (dev/quota_volume.py). Then delete the image.
        String image = h.quotaImage();
        quietly(errors, () -> runHelper("cleanup-" + h.attemptId(), images.setup(), true,
                List.of(QUOTA_IMAGES_VOLUME + ":/s"), List.of(),
                List.of("sh", "-c", "for f in /sys/block/loop*/loop/backing_file; do"
                        + " case \"$(cat \"$f\" 2>/dev/null)\" in"
                        + " */" + image + "|*/" + image + "\" (deleted)\")"
                        + " d=${f#/sys/block/}; losetup -d /dev/${d%%/*} ;; esac; done;"
                        + " rm -f /s/" + image), Map.of(ATTEMPT_LABEL, h.attemptId())));
        quietly(errors, () -> {
            if (ours(docker.inspectNetwork(h.network()).labels(), h)) {
                docker.removeNetwork(h.network());
            }
        });
        List<String> left = leftovers(h);
        left.addAll(errors.stream().filter(e -> !e.contains("No such") && !e.contains("not found"))
                .map(e -> "error: " + e).toList());
        return left;
    }

    /**
     * Runs a removal, retrying for up to a minute while the daemon answers with anything
     * but "not found". Measured: a force-remove of a worker whose process was stuck returned
     * HTTP 500 while the kill was still in flight; the container exited (137) shortly
     * after, but the disposal had already given up, and its three volumes stayed "in use".
     */
    private static void retrying(Step removal) throws Exception {
        for (int attempt = 1; ; attempt++) {
            try {
                removal.run();
                return;
            } catch (NotFoundException | VolumeNotFoundException e) {
                return;
            } catch (DockerException e) {
                if (attempt >= REMOVAL_ATTEMPTS) {
                    throw e;
                }
                Thread.sleep(REMOVAL_PAUSE_MILLIS);
            }
        }
    }

    private static boolean ours(Map<String, String> labels, Handle h) {
        return labels != null && h.attemptId().equals(labels.get(ATTEMPT_LABEL));
    }

    /** What still exists for this attempt: containers, volumes, network, attached image. */
    public List<String> leftovers(Handle h) throws InterruptedException {
        List<String> left = new ArrayList<>();
        try {
            docker.listContainers(ListContainersParam.allContainers(),
                    ListContainersParam.withLabel(ATTEMPT_LABEL, h.attemptId()))
                    .forEach(c -> left.add("container " + c.names()));
            List<Volume> volumes = docker.listVolumes(ListVolumesParam.filter("label",
                    ATTEMPT_LABEL + "=" + h.attemptId())).volumes();
            if (volumes != null) {
                volumes.forEach(v -> left.add("volume " + v.name()));
            }
            docker.listNetworks(ListNetworksParam.withLabel(ATTEMPT_LABEL, h.attemptId()))
                    .forEach(n -> left.add("network " + n.name()));
            String attached = runHelper("check-" + h.attemptId(), images.setup(), true,
                    List.of(QUOTA_IMAGES_VOLUME + ":/s"), List.of(),
                    List.of("sh", "-c", "grep -l '" + h.quotaImage() + "' /sys/block/loop*/loop/backing_file"
                            + " 2>/dev/null; ls /s/" + h.quotaImage() + " 2>/dev/null; true"),
                    Map.of(ATTEMPT_LABEL, h.attemptId()));
            attached.strip().lines().filter(l -> !l.isBlank()).forEach(l -> left.add("quota " + l));
        } catch (DockerException e) {
            left.add("could not list: " + e.getMessage());
        }
        return left;
    }

    /** Runs a one-shot container to completion, removes it, and returns its output. */
    private String runHelper(String name, String image, boolean privileged, List<String> binds,
                             List<String> env, List<String> cmd, Map<String, String> labels)
            throws DockerException, InterruptedException {
        String container = "skald-helper-" + name;
        docker.createContainer(ContainerConfig.builder().image(image).cmd(cmd).env(env)
                .labels(labels).hostConfig(HostConfig.builder().binds(binds)
                        .networkMode("none").privileged(privileged).build()).build(), container);
        try {
            docker.startContainer(container);
            ContainerExit exit = docker.waitContainer(container);
            String out = logs(container);
            if (exit.statusCode() != 0) {
                throw new IllegalStateException(name + " exited " + exit.statusCode() + ": " + out.strip());
            }
            return out;
        } finally {
            docker.removeContainer(container, RemoveContainerParam.forceKill());
        }
    }

    private void waitForLog(String container, String marker, int seconds)
            throws DockerException, InterruptedException {
        String seen = "";
        for (int i = 0; i < seconds * 2; i++) {
            seen = logs(container);
            if (seen.contains(marker)) {
                return;
            }
            if (!Boolean.TRUE.equals(docker.inspectContainer(container).state().running())) {
                break;
            }
            Thread.sleep(500);
        }
        throw new IllegalStateException(container + " did not report '" + marker + "': "
                + tail(seen));
    }

    /** A container's whole output so far, stdout and stderr. */
    String logs(String container) throws DockerException, InterruptedException {
        LogStream stream = docker.logs(container, LogsParam.stdout(), LogsParam.stderr());
        try {
            return stream.readFully();
        } finally {
            try {
                stream.close();
            } catch (IOException e) {
                // the output is already read; a failed close leaks nothing of ours
            }
        }
    }

    private static String tail(String s) {
        String t = s.strip();
        return t.length() > 400 ? t.substring(t.length() - 400) : t;
    }

    private interface Step {
        void run() throws Exception;
    }

    private static void quietly(List<String> errors, Step step) throws InterruptedException {
        try {
            step.run();
        } catch (InterruptedException e) {
            throw e;
        } catch (NotFoundException | VolumeNotFoundException e) {
            // already gone
        } catch (Exception e) {
            errors.add(String.valueOf(e.getMessage()));
        }
    }
}
