#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The build worker exactly as the isolation profile ships it -- the launch, one definition.

Gate finding t5-e5e3071-F6: every earlier probe started the rootless worker with only the
seccomp profile, a network and a config mount. None used the profile's other launch
arguments (--cpus, --memory, --pids-limit, no-new-privileges, --read-only, the sized tmpfs,
the workspace volume), so whether rootless BuildKit even runs under them had never been
tried. This module builds the worker's argv FROM spec/isolation-profile-v1.json, so a probe
cannot test a launch line that differs from the one T7's driver will read.

What running it under the profile took, measured 2026-09-26 (logs in ~/.cache/skald/f6/):
  - --read-only: rootlesskit writes its state under $HOME and buildkitd under
    ~/.local/share. HOME, TMPDIR and XDG_RUNTIME_DIR point into the /tmp tmpfs the profile
    already mounts, and buildkitd's --root is /workspace/buildkit, the profile's volume.
    No new mount, no widened bound.
  - /workspace must be owned by the worker's uid (WORKER_UID below; it was
    upstream's 1000 when this was first measured). The launcher prepares the volume.
  - --security-opt=no-new-privileges cannot be met: rootlesskit's newuidmap needs its file
    capability to write the uid map, and no-new-privileges disables file capabilities
    ("newuidmap: Could not set caps"). The user signed off on 2026-09-26 on waiving it for
    runc-rootless, replaced by three probe-enforced checks. The waiver and its replacements
    are in the spec (runtimes.runc-rootless.waived), and this module reads them from there.
    It does not hard-code a dropped flag. The alternatives, measured or weighed and not
    taken: a single-uid user namespace (keeps no-new-privileges, but cannot even unpack
    alpine: /etc/shadow is gid 42), and dockerd userns-remap (a host-wide daemon change).

The values filling the profile's placeholders are this probe's choices, not the product's.
T7 owns the production numbers.
"""

import json
import pathlib
import subprocess

import worker_disposal

REPO = pathlib.Path(__file__).resolve().parent.parent
SPEC = REPO / "spec/isolation-profile-v1.json"
# The upstream image, pinned (buildkitd v0.33.0), and the worker image derived from it.
UPSTREAM_IMAGE = ("moby/buildkit@sha256:"
                  "80b15f0735e87bab7bf59ec4d695dfb4a7cfb25521cf56dc75d6f256285b63ef")
BUILDKIT_IMAGE = "skald-buildkit-worker:probe"
# With no-new-privileges waived, every setuid, setgid or file-capability binary in the
# worker's own filesystem is a way to gain privilege. The upstream image carries two
# beyond the uid-map helpers: usr/bin/fusermount3 setuid ROOT and usr/sbin/unix_chkpwd
# setgid shadow. Measured 2026-09-26 by the scan in dev/shipping-worker-probe.py. The
# derived image clears both. FUSE is only for the fuse-overlayfs snapshotter, and this
# worker runs the native one. newuidmap/newgidmap keep their file capabilities, which is
# the single privilege the waiver exists for.
PRIVILEGED_HELPERS = {"usr/bin/newuidmap", "usr/bin/newgidmap"}
STRIP = ["usr/bin/fusermount3", "usr/sbin/unix_chkpwd"]
# A static busybox, so a build can run FROM scratch with no registry and no network.
BUSYBOX_IMAGE = ("busybox@sha256:"
                 "ea2b9914a16a4ac1981994af97b318f7c7d4db76b580c56177f08bf76f4a0be8")
# A dedicated identity. Upstream runs the worker as uid 1000 with subordinate ids
# 100000-165535; on a rootful Docker host without userns-remap those ARE host ids, and on
# the machine this was measured on they are the login user's own uid and subuid range. So
# an escape from the worker would land on a real person's files. 2401 and 3000000+ are
# chosen to be unassigned, and the probe checks that against the host's own /etc/passwd
# and /etc/subuid rather than trusting this comment.
WORKER_UID = 2401
SUBID_START, SUBID_COUNT = 3000000, 65536
RUNTIME = "runc-rootless"
PLACEHOLDER_VALUES = {"cpu_quota": "2", "memory_limit": "2g", "pid_limit": "512",
                      "tmpfs_size": "256m",
                      # BuildKit's own defaults, pinned so an upstream change cannot lift
                      # them unnoticed (dev/run-bounds-probe.py measures both).
                      "step_log_max_bytes": "2097152",
                      "step_log_max_bytes_per_second": "204800"}


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def build_worker_image(directory, strip=tuple(STRIP), tag=BUILDKIT_IMAGE):
    """The derived worker image. `strip` is a parameter so a self-test can build one that
    keeps a setuid binary and require the scan to notice it."""
    lines = ["FROM %s" % UPSTREAM_IMAGE, "USER root",
             "RUN addgroup -g %d skaldbuild && adduser -D -H -u %d -G skaldbuild skaldbuild"
             " && echo skaldbuild:%d:%d > /etc/subuid && echo skaldbuild:%d:%d > /etc/subgid"
             % (WORKER_UID, WORKER_UID, SUBID_START, SUBID_COUNT, SUBID_START, SUBID_COUNT)]
    if strip:
        lines.append("RUN chmod u-s,g-s %s" % " ".join("/" + s for s in strip))
    lines.append("USER %d:%d" % (WORKER_UID, WORKER_UID))
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    (d / "Dockerfile").write_text("\n".join(lines) + "\n")
    return docker(["build", "-q", "-t", tag, str(d)], timeout=900).returncode == 0


def spec():
    return json.loads(SPEC.read_text())


def waived(runtime=RUNTIME):
    """The profile bounds this runtime waives, name -> the waiver as the spec records it."""
    return spec()["seam"]["runtimes"][runtime].get("waived") or {}


def profile_arguments(values, runtime=RUNTIME, include_waived=False):
    """The build-worker profile's literal arguments with the placeholders filled.

    `values` supplies the per-launch placeholders (egress_network, quota_volume,
    seccomp_profile) on top of PLACEHOLDER_VALUES. Waived bounds are left out unless
    include_waived, which is how a probe shows the waiver is still needed."""
    fill = dict(PLACEHOLDER_VALUES, **values)
    skip = set() if include_waived else set(waived(runtime))
    args = []
    profile = spec()["profiles"]["build-worker"]
    # daemon_bounds are enforced by buildkitd whatever the runtime, and are passed to it
    # as launch arguments like the rest.
    every = dict(profile["bounds"], **profile.get("daemon_bounds", {}))
    for name, bound in sorted(every.items()):
        if name in skip:
            continue
        arg = bound["argument"]
        for placeholder in bound["placeholders"]:
            arg = arg.replace("<%s>" % placeholder, fill[placeholder])
        args.append(arg)
    return args


# What the read-only root needs, and nothing the profile does not already mount.
ENVIRONMENT = ["--env=HOME=/tmp/home", "--env=TMPDIR=/tmp",
               "--env=XDG_RUNTIME_DIR=/tmp/run"]
# The daemon listens on a unix socket in a volume shared only with the trusted client, not
# a TCP port (user decision 2026-09-26, gate finding t5-e5e3071-F6): a RUN shares the
# worker's network and reached a TCP port, but never gets this volume, and there is no port.
SOCKET_MOUNT = "/skald-sock"
SOCKET_ADDR = "unix://" + SOCKET_MOUNT + "/bk.sock"
DAEMON_ARGS = ["--oci-worker-snapshotter=native", "--root", "/workspace/buildkit",
               "--addr", SOCKET_ADDR]


def prepare_volume(name):
    """A per-attempt volume owned by the worker's uid. (T7 replaces the workspace one with
    the loop-backed quota volume; the ownership requirement is the same.)"""
    docker(["volume", "create", name])
    return docker(["run", "--rm", "--network=none", "-v", "%s:/w" % name, BUSYBOX_IMAGE,
                   "chown", "%d:%d" % (WORKER_UID, WORKER_UID), "/w"]).returncode == 0


def client_args(socket_volume):
    """What a trusted buildctl client needs to reach the worker over the shared socket: the
    socket volume, and the worker's uid so it may open a 0660 socket the worker owns. Build
    code gets neither -- it has no such volume and runs in its own mounts."""
    return ["-v", "%s:%s" % (socket_volume, SOCKET_MOUNT),
            "--user", "%d:%d" % (WORKER_UID, WORKER_UID)]


def start(name, network, volume, seccomp_profile, socket_volume, extra=(),
          include_waived=False, omit=(), daemon_extra=()):
    """Starts the worker; returns the argv used. `socket_volume` carries the daemon's unix
    socket to the trusted client. `omit` drops profile arguments by prefix, for self-tests
    that must see a check fail when a bound is missing. `daemon_extra` is passed to
    buildkitd, after DAEMON_ARGS -- e.g. a --config for a probe's registry."""
    args = profile_arguments({"egress_network": network, "quota_volume": volume,
                              "seccomp_profile": seccomp_profile},
                             include_waived=include_waived)
    args = [a for a in args if not any(a.startswith(o) for o in omit)]
    extra = list(extra) + ["-v", "%s:%s" % (socket_volume, SOCKET_MOUNT)]
    argv = (["run", "-d", "--name", name, "--network-alias", name] + args + ENVIRONMENT
            + list(extra) + [BUILDKIT_IMAGE] + DAEMON_ARGS + list(daemon_extra))
    docker(argv, timeout=300)
    return argv


def wait_ready(name, seconds=30):
    """True once the daemon reports a worker; False if it exits or never does."""
    for _ in range(seconds):
        logs = docker(["logs", name])
        if "found worker" in logs.stdout + logs.stderr:
            return True
        if docker(["inspect", "-f", "{{.State.Status}}", name]).stdout.strip() != "running":
            return False
        subprocess.run(["sleep", "1"])
    return False


def logs(name):
    out = docker(["logs", name])
    return out.stdout + out.stderr


def dispose(name, *volumes):
    """The launcher's teardown: the worker, its anonymous volumes (t5-e5e3071-F7) and every
    named per-attempt volume it was given (the workspace, and the socket volume). `docker rm
    -v` never removes a NAMED volume, so each needs its own removal -- measured the first
    time this probe ran, when the container went and the workspace stayed. Returns (volumes
    held, volumes still present), judged on the host's volume list after both steps."""
    held, _ = worker_disposal.dispose(name)
    for volume in volumes:
        docker(["volume", "rm", volume])
    return held, worker_disposal.surviving(held)
