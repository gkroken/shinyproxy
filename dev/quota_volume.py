#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The build worker's workspace as the profile ships it: a loop-backed ext4 volume.

The workspace bound (spec/isolation-profile-v1.json, bounds.workspace) is a real disk
quota: an ext4 filesystem on a sparse image, attached to a loop device, handed to the
worker as a named Docker volume. Making the filesystem and attaching the device takes
privilege, and that privilege is the trusted LAUNCHER's: two one-off --privileged setup
containers here, exactly as dev/sandbox-probe.py's loop probe does. The worker gets the
volume and never the device.

Mounted nosuid,nodev (18368a9 review N2, 7fa81f9 review N2). BuildKit keeps every snapshot
build code writes under this volume, and with no-new-privileges waived for runc-rootless a
setuid file in a snapshot is otherwise one more thing the worker could execute with a
changed identity. Measured 2026-09-26: the options reach the RUN's own root mount (a bind
from the volume inherits them), and a RUN still builds.

Usage from a probe: create(...) -> the loop device; destroy(name, loop) in a finally.
"""

import os
import pathlib
import shutil
import subprocess

SETUP_IMAGE = "debian:12-slim"
OPTIONS = "nosuid,nodev"


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def create(name, directory, size_mb, owner=None, options=OPTIONS):
    """Makes a size_mb ext4 image under `directory`, attaches it, and creates volume `name`
    on it with `options` (None or "" for none -- a self-test's weakened volume). Chowns the
    volume root to `owner` (uid) when given. Returns the loop device, or raises."""
    d = pathlib.Path(directory) / ("quota-" + name)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o755)
    image = _image_name(name)
    with open(d / image, "wb") as fh:
        fh.truncate(size_mb * 1024 * 1024)
    made = docker(["run", "--rm", "--privileged", "--network", "none", "-v", "%s:/s" % d,
                   SETUP_IMAGE, "sh", "-c",
                   "mkfs.ext4 -q -F /s/%s && losetup --find --show /s/%s" % (image, image)],
                  timeout=300)
    loop = (made.stdout.strip().splitlines() or [""])[-1]
    if made.returncode != 0 or not loop.startswith("/dev/loop"):
        raise SystemExit("could not make and attach the quota image: %s"
                         % (made.stderr.strip()[-200:] or made.stdout.strip()[-200:]))
    docker(["volume", "rm", "-f", name])
    args = ["volume", "create", "--driver", "local", "--opt", "type=ext4",
            "--opt", "device=%s" % loop]
    if options:
        args += ["--opt", "o=%s" % options]
    if docker(args + [name]).returncode != 0:
        detach(loop, name)
        raise SystemExit("could not create the quota volume on %s" % loop)
    if owner is not None:
        chown = docker(["run", "--rm", "--network=none", "-v", "%s:/w" % name,
                        SETUP_IMAGE, "chown", "%d:%d" % (owner, owner), "/w"])
        if chown.returncode != 0:
            destroy(name, loop, directory)
            raise SystemExit("could not chown the quota volume: %s" % chown.stderr[-200:])
    return loop


def _image_name(name):
    """The image's FILE name carries the volume name, because that is the only part of
    the path the kernel keeps recognisably: once the setup container exits, the loop
    device's backing_file reads relative to the bind mount it was attached through
    ("/<file> (deleted)"), not the host path. A guard matching the host directory never
    matched, and the first full run leaked four loop devices that way."""
    return "skald-quota-%s.img" % name


def detach(loop, name):
    """Detaches `loop` only if its backing file is this volume's image. A device number
    read back from a stale volume may since have been reused by something else, and
    detaching that is not this probe's to do. Returns True if it is detached afterwards."""
    if not loop:
        return True
    dev = loop.rsplit("/", 1)[-1]
    docker(["run", "--rm", "--privileged", "--network", "none", SETUP_IMAGE, "sh", "-c",
            'case "$(cat /sys/block/%s/loop/backing_file 2>/dev/null)" in '
            '*/%s|*/%s" (deleted)") losetup -d %s ;; esac'
            % (dev, _image_name(name), _image_name(name), loop)])
    return not attached(loop, name)


def attached(loop, name):
    """Is `loop` still backed by this volume's image? Read on the host, from sysfs."""
    try:
        backing = pathlib.Path("/sys/block/%s/loop/backing_file"
                               % loop.rsplit("/", 1)[-1]).read_text()
    except OSError:
        return False
    return _image_name(name) in backing


def destroy(name, loop, directory=None):
    """Removes the volume, detaches the device and deletes the image. Safe to repeat.

    With no `loop` (a run that crashed and lost track of it), the device is read from the
    volume's own options, so a leftover volume does not leave its loop device attached."""
    if not loop:
        found = docker(["volume", "inspect", "-f", "{{index .Options \"device\"}}", name])
        dev = found.stdout.strip()
        loop = dev if found.returncode == 0 and dev.startswith("/dev/loop") else None
    docker(["volume", "rm", "-f", name])
    detach(loop, name)
    if directory:
        shutil.rmtree(pathlib.Path(directory) / ("quota-" + name), ignore_errors=True)
