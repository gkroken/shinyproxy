#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The launcher/worker contract, and trusted registry transport (T3).

Decision 6: "one disposable rootless BuildKit worker per attempt, no worker reused across
publishers; a trusted launcher controls its lifecycle. The launcher may use the platform's
existing Docker control-plane access, but that socket is never mounted into the worker or
exposed through a worker-callable Docker API proxy. Transfer inputs through a bounded
BuildKit session/stream, not a bind mount of the repository, platform temp directory or
home."

Every clause there is a property something can check, and this checks them against a real
build that pulls a base image and pushes a result.

**The shape.** The launcher -- this script, which holds Docker access -- starts one
rootless buildkitd per attempt on an `--internal` network. The worker has no Docker
socket, no context mount and no credentials. A separate client container holds the build
context and streams it over the BuildKit session; the worker's only route off its network
is the egress gateway, allowlisted to the registry alone.

**Why the context is streamed rather than mounted.** A bind mount of the context is the
obvious way to get sources into a builder, it is what dev/rootless-buildkit-probe.py does
for convenience, and decision 6 forbids it in terms. A mount is a live window into the
launcher's filesystem for the whole life of the build; a session is a bounded transfer
that ends. This probe asserts the worker has no such mount, by reading the container's
actual mount list rather than by trusting how it was started.

**The RUN and the push are asserted, end to end.** Until 2026-09-24 this probe asserted
only that the build reached its second stage, and recorded the nested RUN as an
unexplained, intermittent failure specific to this configuration. It was neither. Every
RUN failed, here and in dev/rootless-buildkit-probe.py alike; that probe reported success
because its marker was also in the step's name. The profile lacked the namespace calls a
nested runc makes, and keyctl answered EPERM where runc tolerates only ENOSYS -- see
dev/buildkit_worker_profile.py, which both probes now share. With it the RUN runs.

Two things then stood between the RUN and the registry, both fixed here:
  - `registry.insecure=true` on the client's output makes BuildKit try HTTPS first, direct
    to the registry by name, which no worker on an internal network can resolve. The
    worker's own buildkitd.toml already says the registry speaks plain HTTP; that is the
    one place it is said now.
  - tinyproxy intermittently broke the push: "http: server closed idle connection" on the
    blob-upload POST. A proxy that drops a pooled keep-alive connection costs a GET nothing
    (Go retries it) and fails a POST (Go may not replay one). Squid, with the same
    allow-one-host rule, does not. The gateway here is a stand-in for the operator's
    egress proxy (T7 chooses that); what this establishes for T7 is that the choice must be
    tested with a push, not a pull.

The proof of a RUN is not a string in buildctl's output. The launcher pulls each pushed
image back from the registry and reads the file its RUN wrote, whose content the shell
computed, so it appears in no step name. That one check covers the RUN, the push through
the gateway, and the image being readable by the trusted side.

Usage: python3 dev/launcher-contract-probe.py [--json]
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import buildkit_worker_profile as worker_profile

INNER, OUTER = "skald-lc-inner", "skald-lc-outer"
GATEWAY, REGISTRY = "skald-lc-gateway", "skald-lc-registry"
WORKER_PREFIX = "skald-lc-worker-"
BUILDKIT_IMAGE = os.environ.get("BUILDKIT_IMAGE", "moby/buildkit:rootless")
REGISTRY_PORT = 15001
ATTEMPTS = 2          # two attempts, so "one worker per attempt" is observable
BUILD_REPEATS = 2     # each build run twice, so an intermittent failure is a failure

results = []


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "ok": ok, "note": note})
    print("  %-6s %-36s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("         %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def cleanup():
    docker(["ps", "-aq", "--filter", "name=" + WORKER_PREFIX]).stdout.split()
    for cid in docker(["ps", "-aq", "--filter",
                       "name=" + WORKER_PREFIX]).stdout.split():
        docker(["rm", "-f", cid])
    for name in (GATEWAY, REGISTRY):
        docker(["rm", "-f", name])
    for net in (INNER, OUTER):
        for name in docker(["network", "inspect", net, "-f",
                            "{{range .Containers}}{{.Name}} {{end}}"]).stdout.split():
            docker(["rm", "-f", name])
        docker(["network", "rm", net])


def build_gateway(tmp):
    """Squid, allowing exactly the registry on its port. No cache: it forwards, and that is
    all it may do. Why squid and not tinyproxy is in the module docstring."""
    d = pathlib.Path(tmp)
    (d / "squid.conf").write_text(
        "http_port 8888\n"
        "acl registry dstdomain %s\n"
        "acl registry_port port 5000\n"
        "http_access allow registry registry_port\n"
        "http_access deny all\n"
        "cache deny all\n"
        "access_log stdio:/dev/stdout\n"
        "cache_log stdio:/dev/stderr\n"
        "pid_filename none\n"
        "coredump_dir /tmp\n" % REGISTRY)
    (d / "Dockerfile.gw").write_text(
        "FROM alpine:3.20\nRUN apk add --no-cache squid\n"
        "COPY squid.conf /etc/squid/squid.conf\nUSER squid\n"
        'CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]\n')
    if docker(["build", "-q", "-t", "skald-lc-gateway:local", "-f",
               str(d / "Dockerfile.gw"), tmp], timeout=900).returncode != 0:
        raise SystemExit("could not build the gateway image")


def start_worker(tmp, profile, index):
    """One disposable worker. No socket, no context, no credentials."""
    name = WORKER_PREFIX + str(index)
    docker(["rm", "-f", name])
    docker(["run", "-d", "--name", name, "--network", INNER, "--network-alias", name,
            "--security-opt", "seccomp=" + profile,
            "-e", "http_proxy=http://%s:8888" % GATEWAY,
            "-e", "HTTP_PROXY=http://%s:8888" % GATEWAY,
            "-v", "%s/buildkitd.toml:/home/user/.config/buildkit/buildkitd.toml:ro" % tmp,
            BUILDKIT_IMAGE, "--oci-worker-snapshotter=native",
            "--addr", "tcp://0.0.0.0:1234"], timeout=300)
    for _ in range(25):
        logs = docker(["logs", name]).stdout + docker(["logs", name]).stderr
        if "found worker" in logs:
            return name
        if docker(["inspect", "-f", "{{.State.Status}}",
                   name]).stdout.strip() != "running":
            break
        subprocess.run(["sleep", "1"])
    return None


def run_build(worker, ctx, tag):
    """The client holds the context and streams it; the worker never sees a mount."""
    out = docker(["run", "--rm", "--network", INNER, "-v", "%s:/ctx:ro" % ctx,
                  "--entrypoint", "buildctl", BUILDKIT_IMAGE,
                  "--addr", "tcp://%s:1234" % worker, "build",
                  "--frontend", "dockerfile.v0",
                  "--local", "context=/ctx", "--local", "dockerfile=/ctx",
                  "--output", "type=image,name=%s,push=true" % tag], timeout=900)
    return out.stdout + out.stderr


def main(argv):
    print("== the launcher/worker contract, and registry transport ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-lc-")
    try:
        profile = worker_profile.write(tmp, worker_profile.fetch_default(tmp))
        pathlib.Path(tmp + "/buildkitd.toml").write_text(
            '[registry."%s:5000"]\n  http = true\n' % REGISTRY)
        pathlib.Path(tmp + "/buildkitd.toml").chmod(0o644)

        cleanup()
        build_gateway(tmp)
        docker(["network", "create", "--internal", INNER])
        docker(["network", "create", OUTER])
        docker(["run", "-d", "--name", REGISTRY, "--network", OUTER,
                "--network-alias", REGISTRY, "-p", "%d:5000" % REGISTRY_PORT,
                "registry:2"])
        docker(["run", "-d", "--name", GATEWAY, "--network", INNER,
                "--network-alias", GATEWAY, "skald-lc-gateway:local"])
        docker(["network", "connect", OUTER, GATEWAY])
        subprocess.run(["sleep", "5"])

        # The LAUNCHER seeds the base image. It has Docker and egress; the worker has
        # neither, which is the division decision 6 describes.
        docker(["pull", "-q", "alpine:3.20"], timeout=600)
        docker(["tag", "alpine:3.20",
                "localhost:%d/base/alpine:3.20" % REGISTRY_PORT])
        if docker(["push", "-q", "localhost:%d/base/alpine:3.20" % REGISTRY_PORT],
                  timeout=600).returncode != 0:
            raise SystemExit("could not seed the base image; nothing below would build")

        workers, worker_ids, built, contained = [], [], [], []
        survivors_at_start, offenders, inspected = [], [], []
        for attempt in range(1, ATTEMPTS + 1):
            # Before this attempt starts, no PREVIOUS attempt's worker may still be
            # running. This is the disposability property: the launcher tears a worker
            # down as part of the attempt, so by the time the next one begins there is
            # nothing left. Checking after the probe's own `docker rm -f` would only
            # prove that force-removal works.
            survivors_at_start.append(docker(
                ["ps", "-q", "--filter", "name=" + WORKER_PREFIX]).stdout.split())
            ctx = pathlib.Path(tmp) / ("ctx%d" % attempt)
            ctx.mkdir()
            # The shell computes the 42, so the evidence is in no step name.
            evidence = "42-ATTEMPT-%d-RAN" % attempt
            # The same RUN also tries every namespace call the WORKER may make, and
            # records the result: build code must get none of them (98c00fb-F2).
            (ctx / "hostile.sh").write_text(worker_profile.HOSTILE_SCRIPT)
            (ctx / "Dockerfile").write_text(
                "FROM %s:5000/base/alpine:3.20\n"
                "COPY hostile.sh /h.sh\n"
                'RUN echo "$((6*7))-ATTEMPT-%d-RAN" > /o.txt && sh /h.sh > /hostile.txt\n'
                % (REGISTRY, attempt))
            worker = start_worker(tmp, profile, attempt)
            workers.append(worker)
            if not worker:
                worker_ids.append(None)
                continue
            # The daemon's OWN worker id, not a name this probe chose. Two names drawn
            # from a loop counter cannot collide, so comparing them proves nothing about
            # whether two distinct daemons ran.
            dbg = docker(["run", "--rm", "--network", INNER, "--entrypoint", "buildctl",
                          BUILDKIT_IMAGE, "--addr", "tcp://%s:1234" % worker,
                          "debug", "workers", "--format", "{{range .}}{{.ID}}\n{{end}}"],
                         timeout=180).stdout.strip().splitlines()
            worker_ids.append(dbg[0] if dbg else None)
            # Each build is pushed under its own tag and pulled back by the LAUNCHER, which
            # then reads the file the RUN wrote. The second build on a worker reuses the
            # cached RUN layer; it still has to push, and the file still has to be there.
            reached = 0
            for repeat in range(1, BUILD_REPEATS + 1):
                pushed_as = "built/attempt%d:%d" % (attempt, repeat)
                blob = run_build(worker, str(ctx), "%s:5000/%s" % (REGISTRY, pushed_as))
                local = "localhost:%d/%s" % (REGISTRY_PORT, pushed_as)
                docker(["rmi", "-f", local])
                pulled = docker(["pull", "-q", local], timeout=600).returncode == 0
                produced = docker(["run", "--rm", "--network", "none", "--entrypoint",
                                   "cat", local, "/o.txt"],
                                  timeout=300).stdout.strip() if pulled else ""
                hostile = docker(["run", "--rm", "--network", "none", "--entrypoint",
                                  "cat", local, "/hostile.txt"],
                                 timeout=300).stdout if pulled else ""
                docker(["rmi", "-f", local])
                contained.append(worker_profile.judge_hostile(hostile) if hostile
                                 else (False, "%s: no hostile result" % pushed_as))
                if produced == evidence:
                    reached += 1
                else:
                    err = next((l for l in blob.splitlines() if "ERROR" in l
                                or "not permitted" in l), blob.strip()[-200:])
                    print("     %s: %s" % (pushed_as, err[:200] if pulled
                                            else "not in the registry; " + err[:160]))
            built.append(reached == BUILD_REPEATS)

            # Inspected while the worker is ALIVE, because that is when the contract is
            # about it, and because the launcher disposes of it two lines below.
            mounts = json.loads(docker(["inspect", "-f", "{{json .Mounts}}",
                                        worker]).stdout or "[]")
            env = json.loads(docker(["inspect", "-f", "{{json .Config.Env}}",
                                     worker]).stdout or "[]")
            args = json.loads(docker(["inspect", "-f", "{{json .Args}}",
                                      worker]).stdout or "[]")
            if any("insecure-entitlement" in a for a in args):
                # It would let a build drop BuildKit's own RUN profile (98c00fb-F2).
                offenders.append("%s: an insecure entitlement is allowed" % worker)
            for m in mounts:
                src, dst = m.get("Source", ""), m.get("Destination", "")
                if "docker.sock" in src or "docker.sock" in dst:
                    offenders.append("%s: docker socket at %s" % (worker, dst))
                if dst.startswith("/ctx") or "ctx" in pathlib.Path(src).name:
                    offenders.append("%s: context bind mount at %s" % (worker, dst))
            for var in env:
                key = var.split("=", 1)[0].upper()
                if any(k in key for k in ("AWS", "SECRET", "TOKEN", "PASSWORD",
                                          "REGISTRY_")):
                    offenders.append("%s: credential-shaped env %s" % (worker, key))
            inspected.append(worker)

            # The launcher disposes of the worker as part of the attempt, which is what
            # the next iteration's survivors check then observes.
            docker(["rm", "-f", worker])

        known = [i for i in worker_ids if i]
        record("one daemon per attempt, not reused",
               "%d attempts report %d distinct BuildKit worker ids" % (ATTEMPTS, ATTEMPTS),
               ", ".join(i[:12] for i in known) if known else "no worker id readable",
               len(known) == ATTEMPTS and len(set(known)) == ATTEMPTS,
               "" if len(known) == ATTEMPTS else "the id comes from the daemon itself; "
                                                 "without it this only compares names "
                                                 "this probe chose")

        record("the RUN ran and its image was pushed",
               "every build's image comes back from the registry holding its RUN's "
               "file, %d/%d per worker" % (BUILD_REPEATS, BUILD_REPEATS),
               "every image, every time" if built and all(built)
               else "%d of %d worker(s) fell short" % (built.count(False), len(built)),
               len(built) == ATTEMPTS and all(built),
               "" if built and all(built) else "the context, the base pull, the RUN or "
                                                "the push failed; the lines above say which")

        failed = [d for ok, d in contained if not ok]
        record("build code gets none of it",
               "in every build, a RUN trying unshare/mount/setns/pivot_root/sethostname "
               "is denied each, under two seccomp filters",
               contained[0][1] if contained and not failed
               else ("; ".join(failed)[:160] if failed else "no build was judged"),
               bool(contained) and not failed
               and len(contained) == ATTEMPTS * BUILD_REPEATS)

        record("nothing forbidden reaches the worker",
               "no docker socket, no context mount, no credentials, no insecure "
               "entitlement",
               "clean across %d inspected worker(s)" % len(inspected)
               if not offenders else "; ".join(offenders),
               not offenders and len(inspected) == ATTEMPTS,
               "" if len(inspected) == ATTEMPTS else "a worker was never inspected, so "
                                                     "this examined fewer than it claims")

        # The registry is reachable from the gateway's side and holds the seeded base,
        # which is what makes the pull above a pull THROUGH the gateway rather than a
        # cached layer. The built images are asserted above, by pulling them back.
        tags = docker(["run", "--rm", "--network", OUTER, "--entrypoint", "sh",
                       "alpine:3.20", "-c",
                       "apk add --no-cache -q curl >/dev/null; "
                       "curl -s http://%s:5000/v2/_catalog" % REGISTRY],
                      timeout=300).stdout
        record("the base came from the registry",
               "the registry holds the base the build resolved",
               tags.strip()[:80] if tags.strip() else "catalog unreadable",
               "base/alpine" in tags)

        # The gateway's rule, asserted here too: dev/egress-probe.py proves allow/deny on
        # tinyproxy, and this probe now uses squid, so without a check of its own the two
        # could drift apart (98c00fb review, nonblocking). From the worker's network, via
        # the proxy: the registry is allowed (the control), anything else is refused.
        def via_gateway(url):
            got = docker(["run", "--rm", "--network", INNER, "-e",
                          "http_proxy=http://%s:8888" % GATEWAY, "alpine:3.20", "sh", "-c",
                          "wget -S -q -O /dev/null -T 20 %s 2>&1 | head -1" % url],
                         timeout=120).stdout.strip()
            return got or "no response"
        allowed = via_gateway("http://%s:5000/v2/" % REGISTRY)
        refused = via_gateway("http://example.com/")
        record("the gateway allows the registry only",
               "registry via the gateway 200; example.com via the gateway 403",
               "registry: %s; example.com: %s" % (allowed[-24:], refused[-24:]),
               " 200" in allowed and " 403" in refused)

        # Disposability, observed rather than arranged: at the start of every attempt
        # after the first, no earlier worker was still running.
        lingered = [n for n, s in enumerate(survivors_at_start[1:], start=2) if s]
        record("no worker outlives its attempt",
               "each attempt begins with no previous worker running",
               "clean at the start of every attempt" if not lingered
               else "attempt(s) %s began with a previous worker still up"
                    % ", ".join(map(str, lingered)),
               not lingered and len(survivors_at_start) == ATTEMPTS)
    finally:
        cleanup()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["ok"]]
    print()
    print("  %d check(s), %d failed" % (len(results), len(bad)))
    print()
    print("RESULT:", "the launcher/worker contract holds against a real build"
          if not bad else "%d check(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
