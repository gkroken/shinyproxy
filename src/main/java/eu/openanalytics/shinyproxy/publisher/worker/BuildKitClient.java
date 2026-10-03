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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.shinyproxy.publisher.recipe.RecipeGenerator.Recipe;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Handle;
import eu.openanalytics.shinyproxy.publisher.worker.DockerWorkerLauncher.Images;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.mandas.docker.client.DockerClient;
import org.mandas.docker.client.DockerClient.LogsParam;
import org.mandas.docker.client.DockerClient.RemoveContainerParam;
import org.mandas.docker.client.LogStream;
import org.mandas.docker.client.exceptions.DockerException;
import org.mandas.docker.client.exceptions.NotFoundException;
import org.mandas.docker.client.exceptions.VolumeNotFoundException;
import org.mandas.docker.client.messages.ContainerState;
import org.mandas.docker.client.messages.ContainerConfig;
import org.mandas.docker.client.messages.HostConfig;
import org.mandas.docker.client.messages.LogConfig;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The trusted side of one build: it stages the build context into the attempt's context
 * volume, then runs buildctl in a client container on the worker's socket volume, which
 * pushes through the gateway and reports the pushed digest.
 *
 * <p><b>No host path reaches any container.</b> The context travels as a tar stream
 * through the Docker API into a stopped helper that mounts the context volume; the client
 * mounts that volume read-only. Its layout is {@code ctx/app/**} (the verified payload),
 * {@code ctx/skald/*} (the recipe's server-written files) and {@code df/Dockerfile}, which
 * is OUTSIDE the context, so no COPY can read it.
 *
 * <p><b>The registry credential is the client's alone.</b> The worker pulls and pushes
 * with what buildctl's session hands it per request; build code never holds it (the T5
 * attack matrix's "registry write 401"). The credential reaches the client as an
 * environment value, which a shell writes to a 0600 file on the client's tmpfs and then
 * unsets. It is visible to Docker API holders through inspect until the client is removed,
 * and to nobody else; the client container is never reachable by build code.
 *
 * <p><b>Nothing build code says is parsed as the result.</b> buildctl's progress, which
 * carries every RUN step's output, goes to the client's stderr; the client's stdout carries
 * only the metadata file, printed after buildctl succeeded. buildctl cannot write the
 * metadata to /dev/stdout directly (measured: it renames a temporary file next to it).
 */
public final class BuildKitClient {

    static final String CONTEXT_MOUNT = "/c";
    static final String METADATA = "/tmp/meta.json";
    /** What the client may use: its tmpfs holds one small config file and the metadata. */
    static final long CLIENT_MEMORY = 256L << 20;
    private static final String HOST_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
    private static final Pattern REGISTRY = Pattern.compile(
            "(?=.{1,253}$)" + HOST_LABEL + "(?:\\." + HOST_LABEL + ")*");
    /** The distribution spec's repository name, lower case: no ',' can reach --output. */
    private static final Pattern REPOSITORY = Pattern.compile(
            "(?=.{1,200}$)[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*");
    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern RECIPE_FILE = Pattern.compile("skald/[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The registry login the client hands buildctl. Never printed. */
    public record Credential(String username, String password) {

        public Credential {
            if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
                throw new IllegalArgumentException("a registry credential needs a user and a password");
            }
        }

        @Override
        public String toString() {
            return "Credential[" + username + ", ****]";
        }
    }

    /**
     * Where the image goes: {@code <registry>:5000/<repository>:build-<buildId>}, the tag
     * the coordinator ledgers. {@code registry} is the host name the gateway allows.
     */
    public record Push(String registry, String repository, UUID buildId, Credential credential) {

        public Push {
            if (!REGISTRY.matcher(registry).matches()) {
                throw new IllegalArgumentException("not a registry host name: " + registry);
            }
            if (!REPOSITORY.matcher(repository).matches()) {
                throw new IllegalArgumentException("not a repository name: " + repository);
            }
            if (buildId == null || credential == null) {
                throw new IllegalArgumentException("a push needs a build id and a credential");
            }
        }

        String registryAddress() {
            return registry + ":5000";
        }

        String name() {
            return registryAddress() + "/" + repository + ":build-" + buildId;
        }

        /** The reference the attempt reports: by digest, never by tag. */
        public String byDigest(String digest) {
            return registryAddress() + "/" + repository + "@" + digest;
        }
    }

    private final DockerClient docker;
    private final DockerWorkerLauncher launcher;
    private final Images images;

    public BuildKitClient(DockerClient docker, DockerWorkerLauncher launcher, Images images) {
        this.docker = docker;
        this.launcher = launcher;
        this.images = images;
    }

    static String stageHelper(Handle h) {
        return "skald-helper-stage-" + h.attemptId();
    }

    /**
     * Fills the attempt's context volume. Refuses if the volume already exists: a stale one
     * of the same attempt would carry an earlier context, and a foreign one is not ours.
     */
    public void stage(Handle h, Path payload, Recipe recipe) throws DockerException, InterruptedException, IOException {
        for (String key : recipe.files().keySet()) {
            if (!RECIPE_FILE.matcher(key).matches()) {
                throw new IllegalArgumentException("a recipe file is skald/<name>: " + key);
            }
        }
        if (!Files.isDirectory(payload, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("the payload is not a directory: " + payload);
        }
        try {
            docker.inspectVolume(h.contextVolume());
            throw new IllegalStateException("volume " + h.contextVolume() + " is already taken, refusing to adopt it");
        } catch (NotFoundException | VolumeNotFoundException e) {
            // free
        }
        Map<String, String> labels = Map.of(DockerWorkerLauncher.ATTEMPT_LABEL, h.attemptId());
        launcher.createOwnedVolume(h.contextVolume(), labels, null);
        String helper = stageHelper(h);
        docker.createContainer(ContainerConfig.builder().image(images.helper()).cmd("true").labels(labels)
                .hostConfig(HostConfig.builder().networkMode("none")
                        .binds(h.contextVolume() + ":" + CONTEXT_MOUNT).build()).build(), helper);
        try {
            copyTar(helper, out -> writeContext(out, payload, recipe));
        } finally {
            docker.removeContainer(helper, RemoveContainerParam.forceKill());
        }
    }

    private interface TarBody {
        void write(OutputStream out) throws IOException;
    }

    /** Streams a tar into a stopped container's {@link #CONTEXT_MOUNT}, without a file on disk. */
    private void copyTar(String container, TarBody body) throws DockerException, InterruptedException, IOException {
        PipedInputStream in = new PipedInputStream(1 << 16);
        PipedOutputStream pipe = new PipedOutputStream(in);
        AtomicReference<IOException> failed = new AtomicReference<>();
        Thread writer = new Thread(() -> {
            try (pipe) {
                body.write(pipe);
            } catch (IOException e) {
                failed.set(e);
            }
        }, "skald-stage-" + container);
        writer.setDaemon(true);
        writer.start();
        try {
            docker.copyToContainer(in, container, CONTEXT_MOUNT);
        } finally {
            // Unblocks a writer the copy stopped reading from.
            in.close();
            writer.join();
        }
        if (failed.get() != null) {
            throw failed.get();
        }
    }

    /** The context tar. Owners are root, modes are set here, and only files and directories pass. */
    static void writeContext(OutputStream out, Path payload, Recipe recipe) throws IOException {
        TarArchiveOutputStream tar = new TarArchiveOutputStream(out, StandardCharsets.UTF_8.name());
        tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
        tar.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
        tar.setAddPaxHeadersForNonAsciiNames(true);
        for (String dir : List.of("ctx/", "ctx/app/", "ctx/skald/", "df/")) {
            directory(tar, dir);
        }
        List<Path> entries;
        try (Stream<Path> walk = Files.walk(payload)) {
            entries = walk.filter(p -> !p.equals(payload)).sorted().toList();
        }
        for (Path p : entries) {
            String name = "ctx/app/" + payload.relativize(p).toString().replace(java.io.File.separatorChar, '/');
            BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (a.isDirectory()) {
                directory(tar, name + "/");
            } else if (a.isRegularFile()) {
                boolean exec = Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)
                        .contains(PosixFilePermission.OWNER_EXECUTE);
                TarArchiveEntry e = entry(name, exec ? 0755 : 0644);
                e.setSize(a.size());
                tar.putArchiveEntry(e);
                try (var in = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
                    long copied = in.transferTo(tar);
                    if (copied != a.size()) {
                        throw new IOException("the payload changed while it was staged: " + name);
                    }
                }
                tar.closeArchiveEntry();
            } else {
                // The extractor writes only files and directories; anything else here did not
                // come from it.
                throw new IOException("not a file or directory in the payload: " + name);
            }
        }
        for (Map.Entry<String, byte[]> f : recipe.files().entrySet()) {
            file(tar, "ctx/" + f.getKey(), f.getValue());
        }
        file(tar, "df/Dockerfile", recipe.dockerfile().getBytes(StandardCharsets.UTF_8));
        tar.finish();
    }

    private static TarArchiveEntry entry(String name, int mode) {
        TarArchiveEntry e = new TarArchiveEntry(name, true);
        e.setMode(mode);
        e.setIds(0, 0);
        e.setNames("root", "root");
        e.setModTime(0);
        return e;
    }

    private static void directory(TarArchiveOutputStream tar, String name) throws IOException {
        tar.putArchiveEntry(entry(name, 0755));
        tar.closeArchiveEntry();
    }

    private static void file(TarArchiveOutputStream tar, String name, byte[] bytes) throws IOException {
        TarArchiveEntry e = entry(name, 0644);
        e.setSize(bytes.length);
        tar.putArchiveEntry(e);
        tar.write(bytes);
        tar.closeArchiveEntry();
    }

    /**
     * The client's entrypoint: a shell that writes the credential and then runs its
     * arguments, so buildctl's argv ({@link #buildctl}) never passes through the shell's
     * parser.
     */
    static final List<String> CLIENT_ENTRYPOINT = List.of("sh", "-c",
            "umask 077 && mkdir /tmp/cfg && printf %s \"$SKALD_DOCKER_CONFIG\" > /tmp/cfg/config.json"
                    + " && unset SKALD_DOCKER_CONFIG && DOCKER_CONFIG=/tmp/cfg \"$@\" && cat " + METADATA,
            "sh");

    static List<String> buildctl(Push push) {
        return List.of("buildctl", "--addr", DockerWorkerLauncher.SOCKET_ADDRESS, "build",
                "--progress", "plain", "--frontend", "dockerfile.v0",
                "--local", "context=" + CONTEXT_MOUNT + "/ctx", "--local", "dockerfile=" + CONTEXT_MOUNT + "/df",
                "--output", "type=image,name=" + push.name() + ",push=true",
                "--metadata-file", METADATA);
    }

    static String dockerConfig(Push push) {
        String auth = Base64.getEncoder().encodeToString((push.credential().username() + ":"
                + push.credential().password()).getBytes(StandardCharsets.UTF_8));
        return JSON.createObjectNode().set("auths", JSON.createObjectNode().set(push.registryAddress(),
                JSON.createObjectNode().put("auth", auth))).toString();
    }

    /** Creates and starts the client; returns at once. The context must be staged. */
    public void start(Handle h, Push push) throws DockerException, InterruptedException {
        Map<String, String> labels = Map.of(DockerWorkerLauncher.ATTEMPT_LABEL, h.attemptId());
        HostConfig hc = HostConfig.builder()
                .networkMode("none")
                .binds(h.socketVolume() + ":" + DockerWorkerLauncher.SOCKET_MOUNT,
                        h.contextVolume() + ":" + CONTEXT_MOUNT + ":ro")
                .readonlyRootfs(true)
                .tmpfs(Map.of("/tmp", "rw,noexec,nosuid,nodev,size=1m,mode=1777"))
                .capDrop("ALL")
                .securityOpt("no-new-privileges")
                .memory(CLIENT_MEMORY)
                .memorySwap(CLIENT_MEMORY)
                .pidsLimit(64)
                .nanoCpus(1_000_000_000L)
                .privileged(false)
                // The build log is read from here; bounded so a chatty build cannot fill the
                // host's disk through the client's log file.
                .logConfig(LogConfig.create("json-file", Map.of("max-size", "16m", "max-file", "2")))
                .build();
        docker.createContainer(ContainerConfig.builder().image(images.worker())
                .user(DockerWorkerLauncher.WORKER_UID + ":" + DockerWorkerLauncher.WORKER_UID)
                .entrypoint(CLIENT_ENTRYPOINT)
                .cmd(buildctl(push))
                .env("SKALD_DOCKER_CONFIG=" + dockerConfig(push))
                .labels(labels).hostConfig(hc).build(), h.client());
        docker.startContainer(h.client());
    }

    /** The client's exit code once it has exited. */
    public Optional<Long> exitCode(Handle h) throws DockerException, InterruptedException {
        ContainerState s = docker.inspectContainer(h.client()).state();
        return s.running() ? Optional.empty() : Optional.ofNullable(s.exitCode());
    }

    /** The build log so far: the client's stderr. */
    public String log(Handle h) throws DockerException, InterruptedException {
        return read(h.client(), LogsParam.stderr());
    }

    /**
     * After a successful exit: the pushed image by digest, from the metadata file the client
     * printed. Anything else on stdout, or a digest that is not one, is refused.
     */
    public String pushed(Handle h, Push push) throws DockerException, InterruptedException {
        return push.byDigest(digestFrom(read(h.client(), LogsParam.stdout())));
    }

    /** The image digest in buildctl's metadata: the whole of stdout, one JSON object. */
    static String digestFrom(String stdout) {
        JsonNode meta;
        try {
            // Trailing tokens refused: stdout must be the metadata and nothing else.
            meta = JSON.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(stdout.strip());
        } catch (IOException e) {
            throw new IllegalStateException("the client did not print buildctl's metadata");
        }
        String digest = meta == null ? null : meta.path("containerimage.digest").asText(null);
        if (digest == null || !DIGEST.matcher(digest).matches()) {
            throw new IllegalStateException("buildctl's metadata names no image digest");
        }
        return digest;
    }

    private String read(String container, LogsParam which) throws DockerException, InterruptedException {
        LogStream stream = docker.logs(container, which);
        try {
            return stream.readFully();
        } finally {
            try {
                stream.close();
            } catch (IOException e) {
                // already read
            }
        }
    }
}
