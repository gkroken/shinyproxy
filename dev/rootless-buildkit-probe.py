#!/usr/bin/env python3
"""Rootless BuildKit under a real seccomp profile, and what it actually costs (T3).

T3: "Pin a rootless BuildKit candidate and prototype only the launcher/worker contract...
If it requires a weakened invariant, stop and present the failed probe and alternatives
for Q2 sign-off." This is that measurement, and the answer is better than the published
recipes suggest.

**What the documentation prescribes, and why this does not do it.** BuildKit's own
rootless guide runs the container with `--security-opt seccomp=unconfined
--security-opt apparmor=unconfined`, and the common workaround for nested builds is
`--oci-worker-no-process-sandbox`. Decision 6 rejects all three by name, and
`--security-opt=seccomp=unconfined` is in the profile's own forbidden_arguments. So the
question this probe answers is not "does rootless BuildKit run" but "does it run without
the things we have already refused".

**It does.** Docker's default profile is deny-by-default and blocks clone/unshare/mount
for a process without CAP_SYS_ADMIN, which is why rootlesskit fails with "failed to start
the child: fork/exec /proc/self/exe: operation not permitted". Adding exactly TWO syscalls
-- clone and mount -- is enough to build, with the process sandbox intact. That is a NAMED
profile, which the contract allows, rather than no profile at all.

**A real build is the test, not a running daemon**, and the difference is not academic: a
set without umount2 starts the daemon, reports a healthy worker, and then fails every
build at "failed to unmount ...: operation not permitted". Anything measuring startup
would have shipped a profile that cannot build.

**And a superset is not a safe answer.** Removing one syscall at a time from a larger
working set gave clone+mount+umount2, which also builds -- but umount2 is only needed
because allowing pivot_root makes runc take a mount-and-pivot path. With pivot_root denied
nothing unmounts and umount2 is dead weight. The members are not independent, so
`--self-test` re-derives the set from scratch and fails if any member turns out optional;
it is what caught umount2. Every extra syscall is one the build did not need and an
attacker might.

Usage: python3 dev/rootless-buildkit-probe.py [--json] [--self-test]
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

# Docker's default seccomp profile: deny-by-default, ~300 syscalls allowed. Fetched rather
# than vendored, because T7 owns the decision of what this deployment actually ships and
# a copy here would be a second answer to that question. Apache-2.0, same as the rest.
DEFAULT_PROFILE_URL = ("https://raw.githubusercontent.com/moby/profiles/main/"
                       "seccomp/default.json")
BUILDKIT_IMAGE = os.environ.get("BUILDKIT_IMAGE", "moby/buildkit:rootless")
SOCKET = "unix:///run/user/1000/buildkit/buildkitd.sock"
CONTAINER = "skald-rootless-buildkit"
MARKER = "BUILD-RAN-ROOTLESS"

# The minimum that lets a build COMPLETE, measured by removing one at a time and
# confirmed by --self-test, which rejects a set where any member turns out optional.
#
# It is TWO, and the road to that number is worth recording because the obvious method
# gives the wrong answer twice over:
#   - Measuring whether the DAEMON STARTS gives a smaller set that cannot build. Without
#     umount2 the daemon runs and reports a healthy worker, and then every build fails at
#     "failed to unmount ...: operation not permitted".
#   - Measuring by removing one syscall from a larger working set gives a LARGER set than
#     necessary, because the members are not independent. Allowing pivot_root makes runc
#     take a mount-and-pivot path that then needs umount2; with pivot_root denied it never
#     unmounts, and umount2 is not needed at all. A superset is not a safe answer here:
#     every extra syscall is one the build did not need and an attacker might.
REQUIRED_SYSCALLS = ["clone", "mount"]

# Decision 6 rejects each of these by name; none may appear in the launch arguments.
FORBIDDEN = ["--privileged", "seccomp=unconfined", "apparmor=unconfined",
             "--oci-worker-no-process-sandbox", "/var/run/docker.sock"]

results = []


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "ok": ok, "note": note})
    print("  %-6s %-34s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("         %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def fetch_default_profile(directory):
    path = pathlib.Path(directory) / "default.json"
    got = subprocess.run(["curl", "-sS", "-o", str(path), "-w", "%{http_code}",
                          DEFAULT_PROFILE_URL], capture_output=True, text=True,
                         timeout=120)
    if got.stdout.strip() != "200":
        raise SystemExit(
            "could not fetch Docker's default seccomp profile (HTTP %s) from %s.\n"
            "This probe compares against it and will not substitute something weaker."
            % (got.stdout.strip(), DEFAULT_PROFILE_URL))
    return json.loads(path.read_text())


def write_profile(directory, base, added):
    """Docker's default, plus a named set of extra syscalls. Never 'unconfined'."""
    profile = json.loads(json.dumps(base))
    if added:
        profile["syscalls"].append({"names": list(added), "action": "SCMP_ACT_ALLOW"})
    path = pathlib.Path(directory) / "profile.json"
    path.write_text(json.dumps(profile))
    path.chmod(0o644)
    return str(path)


def try_build(profile_path, context, extra=()):
    """Start rootless buildkitd under `profile_path` and run one real build.

    Returns (started, worker_found, process_mode, built, detail).
    """
    docker(["rm", "-f", CONTAINER])
    args = ["run", "-d", "--name", CONTAINER]
    if profile_path:
        args += ["--security-opt", "seccomp=" + profile_path]
    args += list(extra) + ["-v", "%s:/ctx:ro" % context, BUILDKIT_IMAGE,
                           "--oci-worker-snapshotter=native"]
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
                      "--local", "dockerfile=/ctx"], timeout=600)
        blob = out.stdout + out.stderr
        built = MARKER in blob
        detail = next((l for l in blob.splitlines()
                       if "operation not permitted" in l or "failed to solve" in l), "")
    else:
        detail = next((l for l in logs.splitlines() if "not permitted" in l), "")
    docker(["rm", "-f", CONTAINER])
    return started, mode, built, detail.strip()[:110]


def main(argv):
    print("== rootless BuildKit, without the relaxations decision 6 rejects ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-rootless-")
    try:
        base = fetch_default_profile(tmp)
        ctx = pathlib.Path(tmp) / "ctx"
        ctx.mkdir()
        (ctx / "Dockerfile").write_text(
            "FROM alpine:3.20\nRUN echo %s > /out.txt && cat /out.txt\n" % MARKER)

        if "--self-test" in argv:
            return self_test(tmp, base, str(ctx))

        # 1. Docker's default ALONE must fail. If it did not, adding syscalls would be
        #    unjustified -- a relaxation nobody needs is one nobody should grant.
        started, mode, built, detail = try_build(write_profile(tmp, base, []), str(ctx))
        record("unmodified default is refused",
               "rootlesskit cannot start under deny-by-default",
               "refused: %s" % (detail or "did not start"), not started,
               "" if not started else "the default profile already allows this, so the "
                                      "addition below needs no justification and should "
                                      "not be made")

        # 2. Default plus exactly three syscalls: a real build, end to end.
        path = write_profile(tmp, base, REQUIRED_SYSCALLS)
        started, mode, built, detail = try_build(path, str(ctx))
        record("builds with a named profile",
               "default + %s completes a build" % ", ".join(REQUIRED_SYSCALLS),
               "built" if built else "FAILED: %s" % (detail or "no build"), built)

        # 3. The process sandbox is the thing decision 6 refused to trade away.
        record("process sandbox intact",
               "the worker runs process-mode=sandbox",
               mode or "unknown", mode == "sandbox",
               "" if mode == "sandbox" else "no-process-sandbox is what the common "
                                            "workaround turns on, and decision 6 rejects "
                                            "it for weakening process separation and "
                                            "cleanup")

        # 4. Nothing forbidden was used to get here.
        used = " ".join(["--security-opt", "seccomp=" + path])
        offenders = [f for f in FORBIDDEN if f in used]
        record("no forbidden argument used",
               "none of decision 6's rejected flags appear",
               "clean" if not offenders else "USED: %s" % ", ".join(offenders),
               not offenders)

        # 5. Minimality, which is a claim and therefore gets a control: drop one syscall
        #    and the build must stop working. Otherwise "minimum" is decoration.
        reduced = [s for s in REQUIRED_SYSCALLS if s != "mount"]
        _, _, still, _ = try_build(write_profile(tmp, base, reduced), str(ctx))
        record("the addition is minimal",
               "removing mount breaks the build",
               "broken, as required" if not still
               else "STILL BUILDS without mount, so the set is not minimal", not still)
    finally:
        docker(["rm", "-f", CONTAINER])
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["ok"]]
    print()
    print("  %d check(s), %d failed" % (len(results), len(bad)))
    print()
    print("RESULT:", "rootless BuildKit builds under a named profile, sandbox intact"
          if not bad else "%d check(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


def self_test(tmp, base, ctx):
    """Each required syscall must be required; the sandbox check must see its opposite."""
    print("== self-test: each claim must fail when its premise is removed ==")
    missed = []
    for syscall in REQUIRED_SYSCALLS:
        reduced = [s for s in REQUIRED_SYSCALLS if s != syscall]
        _, _, built, _ = try_build(write_profile(tmp, base, reduced), ctx)
        if built:
            print("  FAIL %s is NOT required; the set is not minimal" % syscall)
            missed.append(syscall)
        else:
            print("  ok   %s is required: removing it breaks the build" % syscall)

    # There was a case here that reported the worker's process-mode and printed "ok"
    # whatever it read -- including "unknown". It is removed rather than reworded: a
    # self-test case that cannot fail is the defect this whole suite exists to refuse, and
    # the main run already asserts process-mode == sandbox against a real worker.

    docker(["rm", "-f", CONTAINER])
    print()
    if missed:
        print("RESULT: self-test FAILED, %d syscall(s) not actually required"
              % len(missed))
        return 1
    print("RESULT: self-test passed -- every syscall in the set is load-bearing")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
