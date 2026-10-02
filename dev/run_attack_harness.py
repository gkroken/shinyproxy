#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Harness for the RUN-step containment probes (t5-e5e3071-F6, part 2).

Decision 6's isolation table lists things build code must NOT be able to do, "repeated at
T5". Each is a containment property: the attempt is made from inside a real RUN step, under
the worker the shipping profile launches, and it must be refused. This module is only the
scaffolding -- the worker, an internal network, a registry reachable only through the
egress gateway, and one primitive that runs an attempt inside a RUN and hands back what it
saw. The attempts themselves, and the assertion that each was contained, live in
dev/run-attack-probe.py.

Nothing here weakens anything: the launch is dev/shipping_worker's, read from the profile;
the gateway is the same squid the launcher-contract probe uses.

SKALD_LAUNCHER=java launches the gateway and worker through the platform's own launcher
(publisher.worker.DockerWorkerLauncher, via dev/java_launcher.py) instead, so a probe's
SHIPPED matrix measures exactly what the build driver creates (T7 part 3c-2b; reviews
18553b8 N1, 543ed35 N2). The names below (INNER, GATEWAY, WORKER, SOCK, VOLUME) are then
repointed at that launch's objects. A self-test weakens or strips the launch to see a check
fail, and only the Python launch can be weakened, so Java mode refuses those calls rather
than quietly running them unweakened. The point is to demonstrate
the boundary holds, with an allow control beside each attempt so a probe cannot pass by the
attempt silently not happening.
"""

import json
import os
import pathlib
import shutil
import subprocess
import uuid

import egress_gateway
import java_launcher
import quota_volume
import shipping_worker as sw

JAVA = os.environ.get("SKALD_LAUNCHER") == "java"

INNER, OUTER = "skald-atk-inner", "skald-atk-outer"
# The outer network stands in for the internet, so it takes a public-looking range -- a
# documentation range, RFC 5737 TEST-NET-2, never routed -- rather than Docker's default
# private pool: the gateway refuses private destinations for public repository names, and
# with the default pool every stand-in "internet" host would be private. PRIVATE is the
# operator's own network, where a private mirror lives.
OUTER_SUBNET = "198.51.100.0/24"
PRIVATE, PRIVATE_SUBNET = "skald-atk-private", "10.250.250.0/24"
REGISTRY, GATEWAY = "skald-atk-registry", "skald-atk-gateway"
WORKER, VOLUME, SOCK = "skald-atk-worker", "skald-atk-ws", "skald-atk-sock"
# The harness's own names, before Java mode repoints INNER/GATEWAY/WORKER/SOCK/VOLUME at a
# launch's objects: teardown sweeps these as well, so nothing the harness ever made under
# them is left behind whichever mode made it (f5015b6-F1).
# VOLUME is not swept by name: it is loop-backed, and stop_worker() releases it with its
# device (removing only the volume would lose track of the device).
HARNESS_NAMES = {"networks": (INNER,), "containers": (GATEWAY, WORKER), "volumes": (SOCK,)}
REGISTRY_PORT = 15021
GATEWAY_IMAGE = "skald-atk-gateway:local"
# The registry requires a credential to read or write. The trusted client (the daemon's
# pulls and pushes) has it; build code does not, so build code's direct write gets 401
# rather than being merely unreachable (t5-e5e3071-F6, decision 6's "push another build's
# artifacts"). The registry here stands in for the operator's; T7 chooses that.
REG_USER, REG_PASS = "skald-launcher", "s3cr3t-launcher"

# The workspace is the loop-backed quota volume the profile ships (dev/quota_volume.py),
# nosuid,nodev. Its size is this probe's choice; T7 owns the production number.
QUOTA_MB = 768
docker = sw.docker
# What the current worker was started with, so a probe can restart it weakened for a
# self-test and teardown can release the loop device.
state = {"loop": None, "tmp": None, "profile": None, "toml": None, "attempt": None,
         "egress": {}, "java_left": None, "disposed_image": None}


def _java_relaunch(**egress):
    """Java mode: dispose of the current attempt (if any) and launch a new one with this
    egress, then point the module's names at the new objects."""
    global INNER, GATEWAY, WORKER, SOCK, VOLUME
    if state["attempt"]:
        state["java_left"] = java_launcher.dispose(state["attempt"])
        if state["java_left"]:
            raise SystemExit("the Java launcher left %s" % state["java_left"])
    state["egress"] = egress
    state["attempt"] = uuid.uuid4().hex[:16]
    handle = java_launcher.launch(state["attempt"], REGISTRY, outer_networks=[OUTER, PRIVATE],
                                  quota_mb=QUOTA_MB, **egress)
    INNER, GATEWAY, WORKER = handle["network"], handle["gateway"], handle["worker"]
    SOCK, VOLUME = handle["socketVolume"], handle["workspaceVolume"]
    found = docker(["volume", "inspect", "-f", "{{index .Options \"device\"}}", VOLUME])
    state["loop"] = found.stdout.strip() or None


def _java_only_shipped(what):
    raise SystemExit("%s is a self-test's weakened launch; the Java launcher ships one "
                     "launch and cannot be weakened. Run self-tests without SKALD_LAUNCHER=java."
                     % what)


def _backed_by(image):
    """Every loop device whose backing file names `image`, read on the host from sysfs --
    not from the launcher's report, so the launcher does not grade its own disposal."""
    found = []
    for f in pathlib.Path("/sys/block").glob("loop*/loop/backing_file"):
        try:
            if ("/" + image) in f.read_text():
                found.append(f.parts[3])
        except OSError:
            pass
    return found


def workspace_released(loop):
    """(still attached, volume gone) after stop_worker(), judged the way each launcher
    names its quota image: the Python one by quota_volume's file name, the Java one by the
    launch's quota image name, read from the host's sysfs (f5015b6 N1). In Java mode a
    disposal that could not list what it left also counts as not released."""
    if JAVA:
        left = state["java_left"] or []
        still = bool(_backed_by(state["disposed_image"])) or any(
            l.startswith(("quota", "could not list")) for l in left)
        return still, not any(l.startswith("volume") for l in left) and VOLUME not in docker(
            ["volume", "ls", "-q"]).stdout.split()
    return quota_volume.attached(loop, VOLUME), VOLUME not in docker(
        ["volume", "ls", "-q"]).stdout.split()


def _htpasswd(directory):
    line = docker(["run", "--rm", "httpd:2-alpine", "htpasswd", "-Bbn", REG_USER,
                   REG_PASS]).stdout.strip()
    (pathlib.Path(directory) / "htpasswd").write_text(line + "\n")


def _client_config(directory):
    """A docker config.json giving buildctl the registry credential, for the daemon's pulls
    and pushes. Build code never sees this: it is mounted only into the trusted client."""
    import base64
    auth = base64.b64encode(("%s:%s" % (REG_USER, REG_PASS)).encode()).decode()
    cfg = pathlib.Path(directory) / "clientcfg"
    cfg.mkdir(exist_ok=True)
    (cfg / "config.json").write_text(
        '{"auths":{"%s:5000":{"auth":"%s"}}}\n' % (REGISTRY, auth))
    return str(cfg)


def build_gateway(tmp):
    """The squid image; its configuration is dev/egress_gateway's, mounted at run time."""
    d = pathlib.Path(tmp) / "gateway-image"
    d.mkdir(parents=True, exist_ok=True)
    (d / "Dockerfile").write_text(egress_gateway.DOCKERFILE)
    if docker(["build", "-q", "-t", GATEWAY_IMAGE, str(d)], timeout=900).returncode != 0:
        raise SystemExit("could not build the gateway image")


def start_gateway(repos=(), weaken=None, add_hosts=(), resolver=None, private_mirrors=()):
    """(Re)starts the gateway with the shipped rule for these repository hosts. The
    registry is always allowed. `weaken`, `add_hosts` (name:ip entries in the gateway's
    /etc/hosts) and `resolver` (an IP the gateway uses as its only DNS server, standing in
    for the internet's DNS, where an attacker controls the reverse zone of an address the
    attacker owns) are for the egress probe; the defaults are what every probe runs."""
    if JAVA:
        if weaken:
            _java_only_shipped("start_gateway(weaken=%r)" % weaken)
        _java_relaunch(repos=list(repos), private_mirrors=list(private_mirrors),
                       add_hosts=list(add_hosts), dns=[resolver] if resolver else [])
        return
    docker(["rm", "-f", GATEWAY])
    conf_dir = pathlib.Path(state["tmp"]) / ("gateway-conf-%s" % (weaken or "shipped"))
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf = egress_gateway.write_conf(conf_dir, REGISTRY, list(repos), weaken,
                                     private_mirrors=list(private_mirrors))
    mounts = ["-v", "%s:/etc/squid/squid.conf:ro" % conf]
    if resolver:
        rc = conf_dir / "resolv.conf"
        rc.write_text("nameserver %s\n" % resolver)
        rc.chmod(0o644)
        mounts += ["-v", "%s:/etc/resolv.conf:ro" % rc]
    docker(["run", "-d", "--name", GATEWAY, "--network", INNER, "--network-alias", GATEWAY]
           + mounts + ["--add-host=%s" % h for h in add_hosts] + [GATEWAY_IMAGE])
    docker(["network", "connect", OUTER, GATEWAY])
    docker(["network", "connect", PRIVATE, GATEWAY])
    for _ in range(30):
        logs = sw.logs(GATEWAY)
        if "Accepting HTTP" in logs:
            return
        subprocess.run(["sleep", "1"])
    raise SystemExit("the gateway did not start: %s" % logs[-300:])


def setup(tmp):
    """The worker, its network, the registry behind the gateway, and a seeded base image.
    Returns the seccomp profile path the worker was started with."""
    import buildkit_worker_profile as worker_profile
    teardown()
    if JAVA:
        profile = None
        java_launcher.prepare()
    else:
        profile = worker_profile.write(tmp, worker_profile.fetch_default(tmp))
        if not sw.build_worker_image(pathlib.Path(tmp) / "image"):
            raise SystemExit("could not build the worker image")
        build_gateway(tmp)
    _htpasswd(tmp)
    cfg = _client_config(tmp)
    if not JAVA:
        # Java mode's inner network is the launch's own; creating this one leaked it.
        docker(["network", "create", "--internal", INNER])
    docker(["network", "create", "--subnet", OUTER_SUBNET, OUTER])
    docker(["network", "create", "--internal", "--subnet", PRIVATE_SUBNET, PRIVATE])
    docker(["run", "-d", "--name", REGISTRY, "--network", OUTER, "--network-alias",
            REGISTRY, "-p", "%d:5000" % REGISTRY_PORT,
            "-v", "%s/htpasswd:/auth/htpasswd:ro" % tmp,
            "-e", "REGISTRY_AUTH=htpasswd", "-e", "REGISTRY_AUTH_HTPASSWD_REALM=skald",
            "-e", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd", "registry:2"])
    state["tmp"] = tmp
    if not JAVA:
        start_gateway()
    subprocess.run(["sleep", "5"])
    # The launcher seeds a base image; the worker reaches it only through the gateway. The
    # seed push is authenticated, from the host side (docker login to the published port).
    docker(["pull", "-q", "alpine:3.20"], timeout=600)
    docker(["tag", "alpine:3.20", "localhost:%d/base/alpine:3.20" % REGISTRY_PORT])
    subprocess.run(["docker", "login", "-u", REG_USER, "--password-stdin",
                    "localhost:%d" % REGISTRY_PORT], input=REG_PASS, text=True,
                   capture_output=True)
    if docker(["push", "-q", "localhost:%d/base/alpine:3.20" % REGISTRY_PORT],
              timeout=600).returncode != 0:
        raise SystemExit("could not seed the base image")
    setup.client_config = cfg   # host stays logged in for the run; teardown logs out
    if JAVA:
        state.update(tmp=tmp, profile=None)
        _java_relaunch()
        return None
    if not sw.prepare_volume(SOCK):
        raise SystemExit("could not prepare the socket volume")
    # The registry speaks plain HTTP and is reachable only through the gateway, so the
    # worker must be told not to try HTTPS and to send registry traffic to the proxy --
    # the same buildkitd.toml + http_proxy the launcher-contract probe uses. Without it
    # BuildKit tries HTTPS to a name the internal network cannot resolve.
    toml = pathlib.Path(tmp) / "buildkitd.toml"
    toml.write_text('[registry."%s:5000"]\n  http = true\n' % REGISTRY)
    toml.chmod(0o644)
    state.update(tmp=tmp, profile=profile, toml=str(toml))
    start_worker()
    return profile


def start_worker(omit=(), extra=(), quota=True, volume_options=quota_volume.OPTIONS):
    """(Re)starts the worker on a fresh workspace. The defaults are the shipping launch.

    The parameters exist for self-tests, which must see a check fail when its defence is
    removed: `omit` drops profile arguments by prefix, `extra` adds docker run arguments
    (placed after the profile's, so a later --env overrides an earlier one), `quota=False`
    gives a plain Docker volume instead of the loop-backed one, and `volume_options`
    changes the quota volume's mount options."""
    if JAVA:
        if omit or extra or not quota or volume_options != quota_volume.OPTIONS:
            _java_only_shipped("start_worker(omit=%r, extra=%r, quota=%r)" % (omit, extra, quota))
        _java_relaunch(**state["egress"])
        return
    stop_worker()
    if quota:
        state["loop"] = quota_volume.create(VOLUME, state["tmp"], QUOTA_MB,
                                            owner=sw.WORKER_UID, options=volume_options)
    elif not sw.prepare_volume(VOLUME):
        raise SystemExit("could not prepare the workspace volume")
    # buildkitd.toml is mounted at /buildkitd.toml (parent / always exists, so the bind
    # mount overlays the read-only rootfs) and named with --config, because the rootless
    # image reads its config from $HOME/.config/buildkit and $HOME is on the tmpfs here.
    sw.start(WORKER, INNER, VOLUME, state["profile"], SOCK,
             extra=["--env=http_proxy=http://%s:8888" % GATEWAY,
                    "--env=HTTP_PROXY=http://%s:8888" % GATEWAY,
                    "--volume=%s:/buildkitd.toml:ro" % state["toml"]] + list(extra),
             omit=omit, daemon_extra=["--config", "/buildkitd.toml"])
    if not sw.wait_ready(WORKER):
        raise SystemExit("the worker did not become ready: %s"
                         % sw.logs(WORKER).strip()[-200:])


def stop_worker():
    """Removes the worker and its workspace, and releases the loop device."""
    if JAVA:
        if state["attempt"]:
            state["java_left"] = java_launcher.dispose(state["attempt"])
            state["disposed_image"] = "skald-quota-%s.img" % state["attempt"]
            state["attempt"] = None
        return
    docker(["rm", "-f", "-v", WORKER])
    quota_volume.destroy(VOLUME, state.get("loop"), state.get("tmp"))
    state["loop"] = None


# Every build passes --no-cache. The worker outlives a single attempt within a probe run,
# so an attempt whose script is byte-identical to an earlier one (a self-test re-running
# the same matrix against a weakened gateway) was otherwise answered from BuildKit's cache:
# the RUN never executed, and the report was the earlier run's. Measured: five gateway
# weakenings in a row reported exactly the first one's result.


def run_local_step(tmp, name, probe_script, stream=False):
    """Like run_probe_step, but the report comes back through the client's local export
    rather than a push and a pull: a second stage copies only /report, so nothing large
    crosses the registry and the step is much faster. Returns (report, client output).

    With stream=True the script's stdout goes to the build log instead of /report, and the
    script must write /report itself -- for an attempt whose subject IS the log."""
    ctx = pathlib.Path(tmp) / ("step-" + name)
    out = pathlib.Path(tmp) / ("out-" + name)
    shutil.rmtree(out, ignore_errors=True)
    ctx.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True)
    os.chmod(out, 0o777)
    (ctx / "probe.sh").write_text(probe_script)
    # A fresh nonce per build, appended to the report by the RUN itself: a report that does
    # not end with THIS build's nonce did not come from this build, and is refused.
    nonce = uuid.uuid4().hex
    (ctx / "nonce").write_text(nonce + "\n")
    tail = 'echo "skald_nonce=$(cat /nonce)" >> /report'
    run = ("RUN sh /probe.sh && %s" % tail if stream
           else "RUN (sh /probe.sh > /report 2>&1 || true) && %s" % tail)
    (ctx / "Dockerfile").write_text(
        "FROM %s:5000/base/alpine:3.20 AS run\n"
        "COPY nonce /nonce\n"
        "COPY probe.sh /probe.sh\n"
        "%s\n"
        "FROM scratch\n"
        "COPY --from=run /report /report\n" % (REGISTRY, run))
    build = docker(["run", "--rm", "--network", "none", "-v", "%s:/ctx:ro" % str(ctx),
                    "-v", "%s:/out" % str(out),
                    "-v", "%s:/cfg:ro" % setup.client_config, "-e", "DOCKER_CONFIG=/cfg"]
                   + sw.client_args(SOCK) + ["--entrypoint", "buildctl", sw.UPSTREAM_IMAGE,
                    "--addr", sw.SOCKET_ADDR, "build", "--progress", "plain",
                    "--no-cache", "--frontend", "dockerfile.v0", "--local", "context=/ctx",
                    "--local", "dockerfile=/ctx", "--output", "type=local,dest=/out"],
                   timeout=900)
    blob = build.stdout + build.stderr
    try:
        report = (out / "report").read_text(errors="replace")
    except OSError:
        report = ""
    lines = report.rstrip("\n").split("\n")
    if build.returncode != 0:
        return "", blob
    if not lines or lines[-1] != "skald_nonce=" + nonce:
        return "", blob + "\n(the report does not carry this build's nonce: stale, refused)"
    return "\n".join(lines[:-1]) + "\n", blob


def run_probe_step(tmp, name, probe_script):
    """Run one probe as a RUN step and return what it wrote to /report.

    `probe_script` is busybox shell. It runs FROM the seeded base, inside a real RUN under
    the worker, and writes its observations to /report; this returns that text (empty if
    the build itself failed, with the build log alongside). The script is the caller's --
    the harness only carries it in and carries the report out, so an attempt and its result
    are never confused with a step name.
    """
    ctx = pathlib.Path(tmp) / ("atk-" + name)
    ctx.mkdir(parents=True, exist_ok=True)
    (ctx / "probe.sh").write_text(probe_script)
    (ctx / "Dockerfile").write_text(
        "FROM %s:5000/base/alpine:3.20\n"
        "COPY probe.sh /probe.sh\n"
        "RUN sh /probe.sh > /report 2>&1 || true\n" % REGISTRY)
    tag = "%s:5000/attempt/%s:1" % (REGISTRY, name)
    build = docker(["run", "--rm", "--network", "none", "-v", "%s:/ctx:ro" % str(ctx),
                    "-v", "%s:/cfg:ro" % setup.client_config, "-e", "DOCKER_CONFIG=/cfg"]
                   + sw.client_args(SOCK) + ["--entrypoint", "buildctl", sw.UPSTREAM_IMAGE,
                    "--addr", sw.SOCKET_ADDR, "build",
                    "--no-cache", "--frontend", "dockerfile.v0", "--local", "context=/ctx",
                    "--local", "dockerfile=/ctx",
                    "--output", "type=image,name=%s,push=true" % tag], timeout=900)
    blob = build.stdout + build.stderr
    if build.returncode != 0:
        return "", blob
    local = "localhost:%d/attempt/%s:1" % (REGISTRY_PORT, name)
    docker(["rmi", "-f", local])
    # The host is logged in (setup), so this authenticated pull brings the result back.
    if docker(["pull", "-q", local], timeout=600).returncode != 0:
        return "", blob + "\n(could not pull the result image back)"
    report = docker(["run", "--rm", "--network", "none", "--entrypoint", "cat", local,
                     "/report"], timeout=300)
    docker(["rmi", "-f", local])
    return report.stdout, blob


def worker_ip_on_inner():
    """The worker's address on the internal network, for an attempt that needs to name it."""
    out = docker(["inspect", "-f",
                  "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % INNER, WORKER])
    return out.stdout.strip()


def gateway_ip_on_inner():
    """The gateway's address on the internal network. A RUN reaches the gateway by IP: it
    shares the worker's netns but does not resolve Docker network aliases."""
    out = docker(["inspect", "-f",
                  "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % INNER, GATEWAY])
    return out.stdout.strip()


def registry_catalog_via_host():
    """The registry's repository catalog, read with the credential from the trusted side."""
    out = docker(["run", "--rm", "--network", OUTER, "--entrypoint", "sh", "alpine:3.20",
                  "-c", "apk add --no-cache -q curl >/dev/null; "
                        "curl -s -u %s:%s http://%s:5000/v2/_catalog"
                        % (REG_USER, REG_PASS, REGISTRY)], timeout=300)
    try:
        return json.loads(out.stdout).get("repositories", [])
    except (json.JSONDecodeError, AttributeError):
        return []


def teardown():
    docker(["logout", "localhost:%d" % REGISTRY_PORT])
    stop_worker()
    for name in dict.fromkeys((GATEWAY, REGISTRY) + HARNESS_NAMES["containers"]):
        docker(["rm", "-f", "-v", name])
    for vol in dict.fromkeys((SOCK,) + HARNESS_NAMES["volumes"]):
        docker(["volume", "rm", vol])
    for net in dict.fromkeys((INNER,) + HARNESS_NAMES["networks"] + (OUTER, PRIVATE)):
        for name in docker(["network", "inspect", net, "-f",
                            "{{range .Containers}}{{.Name}} {{end}}"]).stdout.split():
            docker(["rm", "-f", "-v", name])
        docker(["network", "rm", net])
