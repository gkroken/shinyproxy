#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The Java build-worker launcher (publisher.worker.DockerWorkerLauncher), driven from the
probes (WORKPLAN-BUNDLES.md T7, part 3c-2b; reviews 18553b8 N1 and 543ed35 N2).

The RUN-step probes measured a worker and gateway the PYTHON harness launched. The driver
ships the Java launcher. With SKALD_LAUNCHER=java, dev/run_attack_harness.py launches and
disposes through this module instead, so the attack, bounds and egress matrices run
against the objects the driver actually creates: its internal network, its hardened gateway
reading the conf GatewayConfig wrote, its loop-backed workspace, its worker.

There is no JDK on the host, so the launcher's CLI (LauncherCli, test scope) runs in the
Maven image that builds the project, with the Docker socket, like `make test`. The worker
and gateway images are built from images/ under the same tags make test uses.
"""

import json
import os
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKER_IMAGE = "skald-buildkit-worker:test"
GATEWAY_IMAGE = "skald-egress-gateway:test"
CLASSPATH_FILE = "target/launcher-cli.cp"
MAIN = "eu.openanalytics.shinyproxy.publisher.worker.LauncherCli"
_prepared = {"done": False}


def _maven_image():
    m = re.search(r"^MAVEN_IMAGE\s*:?=\s*(\S+)", (REPO / "Makefile").read_text(), re.M)
    if not m:
        raise SystemExit("no MAVEN_IMAGE in the Makefile")
    return m.group(1)


def _container(args, docker_socket=False, timeout=1800):
    home = pathlib.Path.home()
    m2, m2home = home / ".cache/skald/m2", home / ".cache/skald/m2home"
    cmd = ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()),
           "-e", "HOME=/m2home", "-v", "%s:/ws" % REPO, "-v", "%s:/m2" % m2,
           "-v", "%s:/m2home" % m2home, "-w", "/ws"]
    if docker_socket:
        gid = os.stat("/var/run/docker.sock").st_gid
        cmd += ["--group-add", str(gid), "-v", "/var/run/docker.sock:/var/run/docker.sock"]
    return subprocess.run(cmd + [_maven_image()] + args, capture_output=True, text=True,
                          timeout=timeout)


def prepare():
    """Builds the images and compiles the launcher with its classpath, once per process."""
    if _prepared["done"]:
        return
    for tag, d in ((WORKER_IMAGE, "images/buildkit-worker"), (GATEWAY_IMAGE, "images/egress-gateway")):
        if subprocess.run(["docker", "build", "-q", "-t", tag, str(REPO / d)],
                          capture_output=True, text=True, timeout=1800).returncode != 0:
            raise SystemExit("could not build %s" % tag)
    built = _container(["mvn", "-B", "-q", "-Dmaven.repo.local=/m2", "-Dlicense.skip=true",
                        "test-compile", "dependency:build-classpath",
                        "-Dmdep.outputFile=" + CLASSPATH_FILE, "-Dmdep.includeScope=test"])
    if built.returncode != 0:
        raise SystemExit("could not compile the launcher: %s" % (built.stdout + built.stderr)[-500:])
    _prepared["done"] = True


def _cli(args):
    cp = "target/classes:target/test-classes:" + (REPO / CLASSPATH_FILE).read_text().strip()
    out = _container(["java", "-cp", cp, MAIN] + args
                     + ["--worker", WORKER_IMAGE, "--gateway", GATEWAY_IMAGE], docker_socket=True)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    if not lines:
        raise SystemExit("the launcher printed nothing (exit %d): %s"
                         % (out.returncode, out.stderr.strip()[-600:]))
    return out.returncode, json.loads(lines[-1])


def launch(attempt, registry, repos=(), private_mirrors=(), outer_networks=(), dns=(),
           add_hosts=(), quota_mb=768):
    """Launches through the Java launcher; returns its handle (a dict of object names)."""
    prepare()
    args = ["launch", "--attempt", attempt, "--registry", registry, "--quota-mb", str(quota_mb)]
    for flag, values in (("--repo", repos), ("--private-mirror", private_mirrors),
                         ("--outer-network", outer_networks), ("--dns", dns),
                         ("--add-host", add_hosts)):
        for v in values:
            args += [flag, v]
    code, handle = _cli(args)
    if code != 0 or not isinstance(handle, dict):
        raise SystemExit("the Java launch failed: %s" % handle)
    return handle


def dispose(attempt):
    """Disposes through the Java launcher; returns what it reports was left (empty = clean)."""
    _, left = _cli(["dispose", "--attempt", attempt])
    return left
