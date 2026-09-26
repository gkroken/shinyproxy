#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Disposing of a worker means its state too -- one definition, two probes.

Decision 6: "one disposable rootless BuildKit worker per attempt", and the isolation table
requires no previous build's files or cache to be reachable. moby/buildkit:rootless
declares `VOLUME /home/user/.local/share/buildkit`, so every worker gets an anonymous
volume holding buildkitd.lock, cache.db, history.db and the snapshots it built (up to
96 MiB each, measured by the T5 gate). `docker rm -f` removes the container and leaves
that volume behind. Both probes removed workers that way, and the check "no worker
outlives its attempt" looked only at containers, so it passed while every attempt's build
cache stayed on the host (finding t5-e5e3071-F7; about 260 such volumes had built up
from the T3 probe days).

`dispose` is the launcher's teardown: it reads the volumes the container actually holds,
removes the container with its anonymous volumes (`-v`), and returns every one of them
that still exists afterwards. It returns what it finds on the host, so the check does not
trust the command it ran: drop the `-v`, or mount a named volume that `-v` does not
remove, and the result is non-empty.

Usage: python3 dev/worker_disposal.py --self-test
"""

import json
import os
import subprocess
import sys

BUILDKIT_IMAGE = os.environ.get("BUILDKIT_IMAGE", "moby/buildkit:rootless")


def _docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def volumes_of(container):
    """The names of the volumes mounted in `container`, named or anonymous."""
    out = _docker(["inspect", "-f", "{{json .Mounts}}", container])
    if out.returncode != 0:
        return []
    return [m["Name"] for m in json.loads(out.stdout or "[]")
            if m.get("Type") == "volume" and m.get("Name")]


def surviving(volumes):
    """Those of `volumes` that still exist on the host."""
    return [v for v in volumes
            if _docker(["volume", "inspect", v]).returncode == 0]


def dispose(container):
    """Remove `container` and its state. Returns (volumes it held, volumes still present).

    A container that does not exist held nothing and leaves nothing."""
    held = volumes_of(container)
    _docker(["rm", "-f", "-v", container])
    return held, surviving(held)


def self_test():
    """The leak this module exists to prevent must be visible to it.

    A real worker container is created (creating it is what makes its state volume), then
    removed the way both probes used to remove workers, with no `-v`. The volume must be
    reported. The positive control removes a second one with `dispose` and must report
    nothing, so a check that reports every volume as surviving fails too."""
    print("== self-test: a disposal that leaves the worker's state must be caught ==")
    missed = []
    names = ("skald-disposal-selftest-old", "skald-disposal-selftest-new")
    for name in names:
        _docker(["rm", "-f", "-v", name])
        if _docker(["create", "--name", name, BUILDKIT_IMAGE]).returncode != 0:
            print("RESULT: self-test could not create %s from %s" % (name, BUILDKIT_IMAGE))
            return 1

    held = volumes_of(names[0])
    _docker(["rm", "-f", names[0]])          # the pre-F7 teardown, verbatim
    left = surviving(held)
    if held and left == held:
        print("  ok   `docker rm -f` without -v leaves %d volume(s), and it is reported"
              % len(left))
    else:
        print("  FAIL the old teardown was not caught (held %s, reported %s)" % (held, left))
        missed.append("rm without -v")
    for v in left:                            # this self-test's own volume, nobody else's
        _docker(["volume", "rm", v])

    held, left = dispose(names[1])
    if held and not left:
        print("  ok   dispose() leaves none of the %d volume(s) the worker held" % len(held))
    else:
        print("  FAIL dispose() %s" % ("examined no volume, so it showed nothing"
                                       if not held else "left %s" % left))
        missed.append("positive control")

    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- a worker's state outliving it is detected")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        print(__doc__.strip().splitlines()[-1])
        sys.exit(2)
    sys.exit(self_test())
