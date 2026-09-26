#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Rootless BuildKit under a real seccomp profile, and what it actually costs (T3).

T3: "Pin a rootless BuildKit candidate and prototype only the launcher/worker contract...
If it requires a weakened invariant, stop and present the failed probe and alternatives
for Q2 sign-off." This is that measurement.

**What the documentation prescribes, and why this does not do it.** BuildKit's own
rootless guide runs the container with `--security-opt seccomp=unconfined
--security-opt apparmor=unconfined`, and the common workaround for nested builds is
`--oci-worker-no-process-sandbox`. Decision 6 rejects all three by name, and
`--security-opt=seccomp=unconfined` is in the profile's own forbidden_arguments. So the
question this probe answers is not "does rootless BuildKit run" but "does it run without
the things we have already refused".

**It does, under a named profile**: Docker's default, plus the namespace-management calls
a nested runc needs, with keyctl still denied. The profile and the reason for each member
are in dev/buildkit_worker_profile.py, which the launcher probe shares.

**What "builds" means here, and the defect that taught it.** Until 2026-09-24 this probe
counted a build as done when its marker string appeared in buildctl's output. The marker
was also in the Dockerfile, and BuildKit prints each step's command as the step's name
whether or not the step runs, so "[2/2] RUN echo BUILD-RAN-ROOTLESS ..." satisfied the
check while the step failed with "failed to unshare remaining namespaces". The RUN step
never completed under the old two-syscall profile, and every claim built on it inherited a
check that could not fail: that two syscalls sufficed, that the host was fine because this
passed 5/5, that the full configuration's failure was intermittent and peculiar to it.

Now the RUN writes a file whose content the shell computes, the build exports it, and the
probe reads it back. The expected text appears nowhere in the Dockerfile, so no step name
can supply it, and `--self-test` runs a RUN that writes the file and then fails, which
must not count as built.

**A real build is the test, not a running daemon.** Without sethostname the daemon starts
and reports a healthy worker, and every RUN still fails. Anything measuring startup would
ship a profile that cannot build -- which, through the check above, is what happened.

Usage: python3 dev/rootless-buildkit-probe.py [--json] [--self-test]
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import buildkit_worker_profile as worker_profile
import worker_disposal

BUILDKIT_IMAGE = os.environ.get("BUILDKIT_IMAGE", "moby/buildkit:rootless")
SOCKET = "unix:///run/user/1000/buildkit/buildkitd.sock"
CONTAINER = "skald-rootless-buildkit"
OUT = "/home/user/out"

# What the RUN step writes. The shell computes the 42, so this exact text is in no step
# name and no command line: only in a file the step produced.
EVIDENCE = "42-BUILD-RAN-ROOTLESS"
DOCKERFILE = 'FROM alpine:3.20\nRUN echo "$((6*7))-BUILD-RAN-ROOTLESS" > /out.txt\n'
# The negative control: writes the evidence and then fails. A check that counted this as
# built would be the check this probe used to have.
FAILING_DOCKERFILE = ('FROM alpine:3.20\n'
                      'RUN echo "$((6*7))-BUILD-RAN-ROOTLESS" > /out.txt && exit 1\n')
# The build's own code, trying every namespace call the WORKER is allowed (98c00fb-F2).
HOSTILE_DOCKERFILE = 'FROM alpine:3.20\nCOPY hostile.sh /h.sh\nRUN sh /h.sh > /out.txt\n'
# The negative control for it: the same RUN with BuildKit's inner profile dropped, which is
# what the security.insecure entitlement does. Self-test only, and forbidden on every
# ordinary launch below. Needs the labs frontend, fetched from Docker Hub like the base.
# The other half of the success check: the RUN succeeds but writes the wrong thing. The
# failing control above cannot tell "rc == 0" from "the content matches", because a failed
# build exports nothing; this one can.
WRONG_DOCKERFILE = 'FROM alpine:3.20\nRUN echo "$((6*6))-BUILD-RAN-ROOTLESS" > /out.txt\n'
INSECURE_DOCKERFILE = ('# syntax=docker/dockerfile:1-labs\nFROM alpine:3.20\n'
                       'COPY hostile.sh /h.sh\nRUN --security=insecure sh /h.sh > /out.txt\n')
INSECURE_WORKER = ("--allow-insecure-entitlement", "security.insecure")
INSECURE_CLIENT = ("--allow", "security.insecure")

# Removed in the main run's minimality check: the last call runc makes, so the daemon
# starts, reports a worker, and only the RUN fails -- the case a startup check misses.
RUN_STAGE_SYSCALL = "sethostname"

# Decision 6 rejects each of these by name; none may appear in the launch arguments.
FORBIDDEN = ["--privileged", "seccomp=unconfined", "apparmor=unconfined",
             "--oci-worker-no-process-sandbox", "/var/run/docker.sock",
             # Lets a build drop BuildKit's own RUN profile, which is what keeps build code
             # from the worker's wider one (98c00fb-F2).
             "--allow-insecure-entitlement"]

results = []
# Every `docker run` argv this probe actually issued. Check 4 scans THESE rather than a
# string it composes for itself: the first version examined only
# `" ".join(["--security-opt", "seccomp=" + path])`, which cannot contain a flag passed
# through try_build's `extra`, so mounting the Docker socket into the worker passed as
# "clean" (finding d3d68e4-F1).
launches = []
held_volumes, leaked_volumes = [], []   # every volume a disposed worker held / left behind


def dispose():
    """Tear the worker down with its state volume (t5-e5e3071-F7), and keep the evidence."""
    held, left = worker_disposal.dispose(CONTAINER)
    held_volumes.extend(held)
    leaked_volumes.extend(left)


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "ok": ok, "note": note})
    print("  %-6s %-34s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("         %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def make_context(tmp, name, dockerfile):
    ctx = pathlib.Path(tmp) / name
    ctx.mkdir()
    (ctx / "Dockerfile").write_text(dockerfile)
    (ctx / "hostile.sh").write_text(worker_profile.HOSTILE_SCRIPT)
    assert EVIDENCE not in dockerfile, "the evidence must not be spelled in the Dockerfile"
    return str(ctx)


def try_build(profile_path, context, extra=(), client_extra=(), produced_out=None,
              daemon_extra=()):
    """Start rootless buildkitd under `profile_path` and run one real build.

    Returns (started, process_mode, built, detail). `built` means the RUN step's own file
    came back out of the build with the computed content, and nothing less. If
    `produced_out` is a list, what the RUN wrote is appended to it, for a caller judging
    something other than the evidence string.
    """
    dispose()
    args = ["run", "-d", "--name", CONTAINER]
    if profile_path:
        args += ["--security-opt", "seccomp=" + profile_path]
    # `extra` is docker's (before the image); `daemon_extra` is buildkitd's (after it).
    args += list(extra) + ["-v", "%s:/ctx:ro" % context, BUILDKIT_IMAGE,
                           "--oci-worker-snapshotter=native"] + list(daemon_extra)
    launches.append(list(args))
    docker(args, timeout=300)
    # buildkitd needs a moment; a probe that races it measures the race.
    started = False
    for _ in range(20):
        state = docker(["inspect", "-f", "{{.State.Status}}", CONTAINER]).stdout.strip()
        logs = docker(["logs", CONTAINER]).stdout + docker(["logs", CONTAINER]).stderr
        if "found worker" in logs:
            started = True
            break
        if state != "running":
            break
        subprocess.run(["sleep", "1"])
    logs = docker(["logs", CONTAINER]).stdout + docker(["logs", CONTAINER]).stderr
    mode = ""
    for token in logs.split():
        if token.startswith("org.mobyproject.buildkit.worker.oci.process-mode:"):
            mode = token.split(":", 1)[1]
    built, detail = False, ""
    if started:
        out = docker(["exec", CONTAINER, "buildctl", "--addr", SOCKET, "build",
                      "--frontend", "dockerfile.v0", "--local", "context=/ctx",
                      "--local", "dockerfile=/ctx",
                      "--output", "type=local,dest=" + OUT] + list(client_extra),
                     timeout=1200)
        blob = out.stdout + out.stderr
        produced = docker(["exec", CONTAINER, "cat", OUT + "/out.txt"]).stdout.strip()
        built = out.returncode == 0 and produced == EVIDENCE
        if produced_out is not None and out.returncode == 0:
            produced_out.append(docker(["exec", CONTAINER, "cat",
                                        OUT + "/out.txt"]).stdout)
        detail = next((l for l in blob.splitlines()
                       if "not permitted" in l or "ERROR" in l), "")
    else:
        detail = next((l for l in logs.splitlines() if "not permitted" in l), "")
    dispose()
    return started, mode, built, detail.strip()[:140]


def main(argv):
    print("== rootless BuildKit, without the relaxations decision 6 rejects ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-rootless-")
    try:
        base = worker_profile.fetch_default(tmp)
        ctx = make_context(tmp, "ctx", DOCKERFILE)

        if "--self-test" in argv:
            return self_test(tmp, base, ctx)

        # 1. Docker's default ALONE must fail. If it did not, adding syscalls would be
        #    unjustified -- a relaxation nobody needs is one nobody should grant.
        started, mode, built, detail = try_build(
            worker_profile.write(tmp, base, allowed=[], enosys=[]), ctx)
        record("unmodified default is refused",
               "rootlesskit cannot start under deny-by-default",
               "refused: %s" % (detail or "did not start"), not started,
               "" if not started else "the default profile already allows this, so the "
                                      "addition below needs no justification and should "
                                      "not be made")

        # 2. The profile of record: a real build whose RUN step demonstrably ran.
        started, mode, built, detail = try_build(worker_profile.write(tmp, base), ctx)
        record("the RUN step runs",
               "default + %s, keyctl -> ENOSYS: the RUN's file comes back"
               % ",".join(worker_profile.ALLOWED),
               "ran" if built else "FAILED: %s" % (detail or "no build"), built)

        # 3. The process sandbox is the thing decision 6 refused to trade away.
        record("process sandbox intact",
               "the worker runs process-mode=sandbox",
               mode or "unknown", mode == "sandbox",
               "" if mode == "sandbox" else "no-process-sandbox is what the common "
                                            "workaround turns on, and decision 6 rejects "
                                            "it for weakening process separation and "
                                            "cleanup")

        # 4. Minimality at the stage that matters: without the last call runc makes, the
        #    daemon still starts and reports a worker, and the RUN must fail. The whole
        #    set is checked one member at a time by --self-test.
        reduced = [s for s in worker_profile.ALLOWED if s != RUN_STAGE_SYSCALL]
        started, _, still, _ = try_build(worker_profile.write(tmp, base, allowed=reduced),
                                         ctx)
        record("a RUN-stage call is load-bearing",
               "without %s the daemon starts and the RUN fails" % RUN_STAGE_SYSCALL,
               "RUN failed, daemon up, as required" if started and not still
               else ("the daemon did not start, so this measured startup instead"
                     if not started else "STILL RAN without %s" % RUN_STAGE_SYSCALL),
               started and not still)

        # 5. The build's own code gets none of what check 2 gave the worker. BuildKit puts
        #    each RUN under its own profile as well, and that second filter is what makes
        #    the wider worker profile acceptable -- so it is demonstrated, not assumed.
        produced = []
        try_build(worker_profile.write(tmp, base), make_context(tmp, "hostile",
                                                                 HOSTILE_DOCKERFILE),
                  produced_out=produced)
        denied, detail = (worker_profile.judge_hostile(produced[0]) if produced
                          else (False, "the hostile RUN produced nothing"))
        record("build code gets none of it",
               "a RUN trying unshare/mount/setns/pivot_root/sethostname is denied each, "
               "under two seccomp filters", detail, denied)

        # 6. No worker's state outlives it. Each launch above is a worker, and the image
        #    declares a VOLUME for BuildKit's state; `docker rm -f` alone left it, and its
        #    build cache, on the host after every case (t5-e5e3071-F7). Judged by the host's
        #    volume list after disposal, and it must have examined one volume per launch.
        record("no worker's state outlives it",
               "every volume a worker held is gone once it is disposed of",
               "%d volume(s) held, none left" % len(held_volumes) if not leaked_volumes
               else "%d of %d volume(s) survived: %s"
                    % (len(leaked_volumes), len(held_volumes),
                       ", ".join(v[:12] for v in leaked_volumes)),
               not leaked_volumes and len(held_volumes) >= len(launches) > 0)

        # 7. Nothing forbidden was used to get here -- checked against the argv actually
        #    issued, every launch of it, not against a string this function writes. Last,
        #    so it covers every launch above (it used to run before the two checks above).
        offenders = forbidden_in_launches()
        record("no forbidden argument used",
               "none of decision 6's rejected flags appear in any launch",
               "clean across %d launch(es)" % len(launches) if not offenders
               else "USED: %s" % ", ".join(offenders),
               not offenders and bool(launches),
               "" if launches else "no launch was recorded, so this check examined "
                                   "nothing")
    finally:
        dispose()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["ok"]]
    print()
    print("  %d check(s), %d failed" % (len(results), len(bad)))
    print()
    print("RESULT:", "rootless BuildKit runs a RUN step under a named profile, sandbox "
                     "intact" if not bad else "%d check(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


def forbidden_in_launches():
    return sorted({f for argv in launches for a in argv for f in FORBIDDEN if f in a})


def self_test(tmp, base, ctx):
    """The success check must see a failure; every profile member must be needed."""
    print("== self-test: each claim must fail when its premise is removed ==")
    missed = []
    full = worker_profile.write(tmp, base)

    # The success check first, because it is the one that certified this probe's headline
    # claim while being unable to fail. A RUN that writes the evidence and then exits
    # non-zero must not count.
    failing = make_context(tmp, "failing", FAILING_DOCKERFILE)
    started, _, built, _ = try_build(full, failing)
    if started and not built:
        print("  ok   a RUN that fails is not counted as built")
    else:
        print("  FAIL a failing RUN was counted as built (or the daemon did not start)")
        missed.append("failing RUN")
    started, _, built, _ = try_build(full, make_context(tmp, "wrong", WRONG_DOCKERFILE))
    if started and not built:
        print("  ok   a RUN that succeeds with the wrong content is not counted as built")
    else:
        print("  FAIL a RUN that wrote the wrong content was counted as built")
        missed.append("wrong content")

    # The judge's per-call half, offline: two filters present and one call reached must
    # still fail. The live control below drops the inner profile, which fails BOTH halves,
    # so on its own it cannot show this half works (117dbc9 review, nonblocking).
    two_filters_one_reached = ("\n".join("%s=x: Operation not permitted" % c
                                          for c in worker_profile.HOSTILE_CALLS
                                          if c != "mount")
                               + "\nmount=ok\nSeccomp:2\nSeccomp_filters:2\n")
    if not worker_profile.judge_hostile(two_filters_one_reached)[0]:
        print("  ok   two filters with one call reached is not judged contained")
    else:
        print("  FAIL two filters with one call reached was judged contained")
        missed.append("per-call half of the judge")

    # The build-code check next, for the same reason: it has to be able to fail. With
    # BuildKit's inner profile dropped, the same hostile RUN must be judged NOT contained.
    produced = []
    try_build(full, make_context(tmp, "insecure", INSECURE_DOCKERFILE),
              daemon_extra=INSECURE_WORKER, client_extra=INSECURE_CLIENT,
              produced_out=produced)
    if produced and not worker_profile.judge_hostile(produced[0])[0]:
        print("  ok   build code without BuildKit's inner profile is caught: %s"
              % worker_profile.judge_hostile(produced[0])[1][:100])
    else:
        print("  FAIL build code without the inner profile was %s" % (
            "judged contained" if produced else "never run, so nothing was shown"))
        missed.append("inner profile dropped")

    # The forbidden-argument check. Each flag must be SEEN when it is actually passed to
    # docker.
    for label, extra, expect in (
            ("the Docker socket is mounted",
             ("-v", "/var/run/docker.sock:/var/run/docker.sock"), "/var/run/docker.sock"),
            ("--privileged is used", ("--privileged",), "--privileged"),
            ("apparmor is unconfined",
             ("--security-opt", "apparmor=unconfined"), "apparmor=unconfined"),
            ("the insecure entitlement is allowed", INSECURE_WORKER,
             "--allow-insecure-entitlement"),
    ):
        launches.clear()
        if extra == INSECURE_WORKER:   # buildkitd's flag, so where the daemon takes it
            try_build(full, ctx, daemon_extra=extra)
        else:
            try_build(full, ctx, extra=extra)
        seen = forbidden_in_launches()
        if expect in seen:
            print("  ok   forbidden flag detected: %s" % label)
        else:
            print("  FAIL NOT detected: %s (saw %s)" % (label, seen or "nothing"))
            missed.append(label)
    launches.clear()

    # The positive control for the loop below: with nothing removed the RUN runs, so a
    # failure below is the removal and not a broken setup.
    if not try_build(full, ctx)[2]:
        print("  FAIL the full profile does not run the RUN; nothing below means anything")
        missed.append("positive control")

    # Every member, one at a time, against the RUN -- not against startup.
    for syscall in worker_profile.ALLOWED:
        reduced = [s for s in worker_profile.ALLOWED if s != syscall]
        started, _, built, detail = try_build(
            worker_profile.write(tmp, base, allowed=reduced), ctx)
        if built:
            print("  FAIL %s is NOT required; the RUN ran without it" % syscall)
            missed.append(syscall)
        else:
            print("  ok   %s is required: %s" % (
                syscall, "the RUN fails" if started else "the daemon cannot start"))
    for syscall in worker_profile.ENOSYS:
        reduced = [s for s in worker_profile.ENOSYS if s != syscall]
        started, _, built, _ = try_build(
            worker_profile.write(tmp, base, enosys=reduced), ctx)
        if built:
            print("  FAIL %s -> ENOSYS is NOT required; the RUN ran with EPERM" % syscall)
            missed.append(syscall + " -> ENOSYS")
        else:
            print("  ok   %s -> ENOSYS is required: with EPERM the RUN fails" % syscall)

    # The disposal check's own premise: a teardown without -v must be caught.
    if worker_disposal.self_test() != 0:
        missed.append("worker state outliving disposal")

    # There was a case here that reported the worker's process-mode and printed "ok"
    # whatever it read -- including "unknown". It is removed rather than reworded: a
    # self-test case that cannot fail is the defect this whole suite exists to refuse, and
    # the main run already asserts process-mode == sandbox against a real worker.

    dispose()
    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- the success check can fail, and every member of "
          "the profile is load-bearing")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
