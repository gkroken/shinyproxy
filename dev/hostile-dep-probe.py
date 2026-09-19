#!/usr/bin/env python3
"""Hostile code in a REAL dependency-install hook, against the profile of record (T3).

T3's Pass line asks to "exercise malicious code in a real dependency-install hook, not
merely a sibling test container". Everything dev/sandbox-probe.py measures is the platform
testing its own bounds with cooperative code: a container asked to allocate too much, or to
fork too often, doing exactly that and being stopped. This runs code that is trying to get
out, in the place a real attack lives.

**Why an install hook and not a RUN line.** `setup.py` executes at install time with the
privileges of the build. A publisher who depends on a package -- or who is depended on by
one -- runs whatever that package's author wrote. That is the supply-chain vector, it needs
no exploit, and it is the one thing a lockfile does not defend against: the hash pins WHICH
code runs, never what it does.

**The profile is read from spec/isolation-profile-v1.json**, not written out here. A probe
that hand-copies the launch arguments proves containment for a profile nobody ships. Any
placeholder is filled from CONCRETE below, and an argument this script cannot fill is a
failure rather than a silent omission.

**Every attack must prove it RAN.** An attack that fails because the hook never executed is
indistinguishable from an attack that was contained, and the second is the only one worth
anything. The hook writes its evidence to a file in the workspace and the file is read back
afterwards; a run with no evidence file is reported as inconclusive, never as contained.

Printing it was the obvious choice and it was wrong, in a way worth recording: pip shows a
setup.py's stdout only when the build FAILS. While the seccomp profile was breaking the
install the marker came through and the probe looked fine; the moment the install started
succeeding, pip swallowed the output and the same probe reported NO MARKER. A channel that
works only on failure is no way to prove something happened.

**And the attacks must be able to detect.** Eight attempts that all report "contained" is
the same output an attack suite that does nothing produces. `--self-test` deliberately
weakens the profile one bound at a time -- mounts the Docker socket, drops --read-only,
gives it a network, mounts a sibling's workspace, removes seccomp, removes
no-new-privileges, injects a credential -- and requires the matching attack to FIND it.
An attack that cannot see its own hole is removed or fixed, not shipped.

Usage: python3 dev/hostile-dep-probe.py [--json] [--self-test]
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
PROFILE = REPO / "spec/isolation-profile-v1.json"
BASE_IMAGE = os.environ.get("HOSTILE_PROBE_IMAGE", "python:3.12-slim")
# Built once, with network, BEFORE the worker starts. That is not a convenience: Q3 settled
# that "System packages are the administrator's, installed into the base images", and a
# worker with no egress cannot fetch a build backend. The first run of this probe proved
# the point by failing -- pip could not import setuptools.build_meta, the hook never ran,
# and the probe reported INCONCLUSIVE rather than contained.
PROBE_IMAGE = "skald-hostile-probe-base:local"
SETUP_IMAGE = os.environ.get("SANDBOX_SETUP_IMAGE", "debian:12-slim")
VOLUME = "skald-hostile-probe"
SIBLING_VOLUME = "skald-hostile-canary"

# Concrete values for the profile's placeholders. Deliberately small: a build that needs
# more is a configuration change, and a probe that needs more is measuring something else.
CONCRETE = {
    "cpu_quota": "1",
    "memory_limit": "512m",
    "pid_limit": "128",
    "tmpfs_size": "64m",
    "quota_volume": VOLUME,
    "egress_network": "none",
    "seccomp_profile": None,  # filled at runtime with a written profile path
}

MARKER = "HOOK-EXECUTED"
results = []


def record(name, attack, observed, contained, ran, note=""):
    """A containment result. `ran` is what separates 'contained' from 'never happened'."""
    results.append({"name": name, "attack": attack, "observed": observed,
                    "contained": contained, "ran": ran, "note": note})
    if not ran:
        prefix = "????"
    elif contained:
        prefix = "ok"
    else:
        prefix = "ESCAPED"
    print("  %-7s %-28s %s" % (prefix, name, observed))
    if note:
        print("          %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def profile_arguments(seccomp_path):
    """The launch arguments this profile specifies, with placeholders filled."""
    spec = json.loads(PROFILE.read_text(encoding="utf-8"))
    bounds = spec["profiles"]["build-worker"]["bounds"]
    concrete = dict(CONCRETE, seccomp_profile=seccomp_path)
    args = []
    for name in sorted(bounds):
        argument = bounds[name]["argument"]
        for placeholder in re.findall(r"<([a-z_]+)>", argument):
            if concrete.get(placeholder) is None:
                raise SystemExit(
                    "no concrete value for <%s> in bound %s; this probe would otherwise "
                    "launch with a different profile from the one it claims to test"
                    % (placeholder, name))
            argument = argument.replace("<%s>" % placeholder, str(concrete[placeholder]))
        args.append(argument)
    return args


# Syscalls a dependency install never needs and an attacker wants. Chosen by what breaks
# nothing, which is not a free choice: the first version of this probe denied the chmod
# family -- convenient, because it is easy to observe -- and every install failed, because
# setuptools chmods the egg-info files it writes. "error: [Errno 1] Operation not
# permitted: .../good.egg-info/tmp2nn2e8ya" is what a too-clever seccomp profile looks
# like from a publisher's side, and it would have been indistinguishable from a broken
# package. A profile that blocks legitimate builds does not get deployed, so it protects
# nobody.
DENIED_SYSCALLS = [
    "ptrace",        # reading another process's memory
    "mount", "umount2", "pivot_root",   # rearranging the filesystem view
    "bpf",           # loading kernel programs
    "kexec_load", "kexec_file_load",    # replacing the running kernel
    "init_module", "finit_module", "delete_module",  # loading kernel modules
    "perf_event_open",   # side channels and kernel introspection
]


def write_seccomp(directory):
    """The same shape spec/isolation-profile-v1.json names: a configured profile."""
    path = pathlib.Path(directory) / "seccomp.json"
    path.write_text(json.dumps({
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [{"names": DENIED_SYSCALLS, "action": "SCMP_ACT_ERRNO",
                      "errnoRet": 1}],
    }))
    path.chmod(0o644)
    return str(path)


HOSTILE_SETUP = '''
import os, socket, subprocess, sys

# Written to the workspace, not printed: pip hides a successful setup.py's stdout.
EVIDENCE = "/workspace/hook-evidence.txt"
findings = []

# 1. The Docker socket: the single worst thing a build could reach, because it is a
#    root-equivalent API on the host.
for sock in ("/var/run/docker.sock", "/run/docker.sock"):
    if os.path.exists(sock):
        findings.append("docker socket present at " + sock)
        try:
            s = socket.socket(socket.AF_UNIX); s.connect(sock)
            findings.append("CONNECTED to " + sock)
        except OSError:
            pass

# 2. The host filesystem, by the paths a careless bind mount would use.
for path in ("/host", "/hostfs", "/mnt/host", "/ws", "/workspace/../etc/shadow"):
    try:
        if os.path.exists(path) and os.path.isdir(path) and os.listdir(path):
            findings.append("readable host-ish path " + path)
    except OSError:
        pass

# 3. Credentials of any kind, which the profile says never reach the worker.
for var in os.environ:
    if any(k in var.upper() for k in ("AWS", "SECRET", "TOKEN", "PASSWORD", "REGISTRY")):
        findings.append("credential-shaped env var " + var)
for path in ("/root/.aws", "/root/.docker/config.json", "/workspace/.aws"):
    if os.path.exists(path):
        findings.append("credential file " + path)

# 4. Writing outside the two writable mounts.
for path in ("/evil", "/usr/local/lib/evil", "/etc/evil"):
    try:
        open(path, "w").write("x")
        findings.append("WROTE " + path)
    except OSError:
        pass

# 5. Escalating. no-new-privileges must make a setuid binary useless.
with open("/proc/self/status") as fh:
    if "NoNewPrivs:\\t1" not in fh.read():
        findings.append("NoNewPrivs is not set")

# 6. Egress. A miner needs the network before it needs anything else.
try:
    socket.create_connection(("1.1.1.1", 53), 2)
    findings.append("REACHED the network")
except OSError:
    pass

# 7. Another attempt's workspace.
for path in ("/canary", "/workspace/../canary"):
    try:
        if os.path.exists(path):
            findings.append("sibling workspace visible at " + path)
    except OSError:
        pass

# 8. The seccomp filter is actually loaded, read from the kernel rather than assumed.
with open("/proc/self/status") as fh:
    if "Seccomp:\t2" not in fh.read():
        findings.append("no seccomp filter is loaded")

# 9. A denied syscall, behaviourally. ptrace is the one an attacker reaches for to read
#    another process's memory, no dependency install has ever needed it, and it is the
#    one that DISCRIMINATES: unconfined it succeeds here, confined the filter refuses it.
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
if libc.syscall(101, 0, 0, 0, 0) == 0:           # SYS_ptrace on x86-64
    findings.append("ptrace SUCCEEDED despite the seccomp profile")

# There is deliberately no finit_module check here. It was tried and removed: loading a
# kernel module needs CAP_SYS_MODULE, which this container never has, so the call fails
# with EPERM whether or not seccomp is loaded -- and the filter's own errnoRet is EPERM
# too. Its "succeeded" branch is unreachable, which makes it a check that cannot fire.
# The stricter self-test matcher is what exposed it; under an `any` match it sat unnoticed
# behind ptrace. The module-loading family stays DENIED in the profile, because defence
# does not depend on being observable.

with open(EVIDENCE, "w") as fh:
    fh.write("%s\\n" + "|".join(findings) + "\\n")
''' % MARKER


def build_base_image(directory):
    """A base image with a build backend already in it, as an administrator would ship."""
    path = pathlib.Path(directory) / "Dockerfile"
    path.write_text("FROM %s\nRUN pip install --quiet --no-cache-dir "
                    "'setuptools>=69' 'wheel'\n" % BASE_IMAGE)
    built = docker(["build", "-q", "-t", PROBE_IMAGE, "-f", str(path), directory],
                   timeout=900)
    if built.returncode != 0:
        raise SystemExit("could not build the probe base image, so the install hook could "
                         "never run:\n" + built.stdout + built.stderr)


def build_package(directory):
    """A source distribution whose install hook is the attack."""
    pkg = pathlib.Path(directory) / "evil"
    pkg.mkdir()
    (pkg / "setup.py").write_text(
        "from setuptools import setup\n" + HOSTILE_SETUP
        + "\nsetup(name='evil', version='1.0', py_modules=['evil'])\n")
    (pkg / "evil.py").write_text("")
    return pkg


def run_install(args, mount_dir, extra=()):
    """pip install the hostile package inside the profile."""
    return docker(["run", "--rm"] + list(args) + list(extra)
                  + ["-v", "%s:/pkg:ro" % mount_dir,
                     "-e", "TMPDIR=/tmp", "-e", "HOME=/tmp",
                     PROBE_IMAGE, "sh", "-c",
                     # Copied into the writable workspace first, which is what a real
                     # build does: the extractor puts the bundle there and dependencies
                     # install from it. pip builds the wheel IN the source tree, so a
                     # read-only source is refused before setup.py ever runs -- the second
                     # way this probe reported INCONCLUSIVE rather than a false green.
                     # NOT piped through tail. setup.py prints its marker and findings
                     # during metadata preparation, near the START of pip's output, so a
                     # `tail -5` discarded both and the probe reported NO MARKER for a
                     # hook that had run perfectly. Truncating the evidence is its own way
                     # of making a test say the wrong thing.
                     "cp -r /pkg/evil /workspace/src && "
                     "pip install --no-index --no-build-isolation "
                     "--target=/workspace/site /workspace/src 2>&1"],
                 timeout=300)


def attack_findings(args, pkg_parent, extra=(), prepare=None):
    """Run the hostile install and return (ran, findings)."""
    # Everything, not just the two obvious paths: a case that plants a credential file
    # in the workspace would otherwise leave it there for the next case to find.
    docker(["run", "--rm", "-v", "%s:/workspace" % VOLUME, SETUP_IMAGE,
            "sh", "-c", "rm -rf /workspace/..?* /workspace/.[!.]* /workspace/*"],
           timeout=120)
    if prepare is not None:
        prepare()
    run_install(args, pkg_parent, extra)
    evidence = docker(["run", "--rm", "-v", "%s:/workspace:ro" % VOLUME, SETUP_IMAGE,
                       "sh", "-c", "cat /workspace/hook-evidence.txt 2>/dev/null"],
                      timeout=120).stdout
    ran = MARKER in evidence
    lines = evidence.split("\n")
    return ran, [f for f in (lines[1].split("|") if ran and len(lines) > 1 else []) if f]


def plant_credential():
    """Leaves a credential file where the hook looks, for the case that needs one."""
    docker(["run", "--rm", "-v", "%s:/workspace" % VOLUME, SETUP_IMAGE,
            "sh", "-c", "mkdir -p /workspace/.aws && echo 'key' > /workspace/.aws/creds"],
           timeout=120)


def self_test(args, pkg_parent):
    """Weaken one bound at a time; the matching attack must notice.

    Every expectation is a LIST and all of it must appear. `any` was the first shape and
    it hid two detections behind their neighbours: the Docker-socket case passed on the
    stat-based finding alone, so the connect() half could break unnoticed, and the seccomp
    case passed on ptrace alone, so finit_module could. A case that passes without
    exercising the thing it is named for is the defect this suite exists to refuse
    (finding 66a59e9-F1).
    """
    print("== self-test: each attack must detect its own hole ==")
    without = lambda flag: [a for a in args if not a.startswith(flag)]
    cases = [
        # Both halves required: presence AND a successful connect, since the socket being
        # visible and the socket being usable are different failures.
        ("the Docker socket is mounted", args,
         ("-v", "/var/run/docker.sock:/var/run/docker.sock"), None,
         ["docker socket present", "CONNECTED to"]),
        ("the root filesystem is writable", without("--read-only"), (), None, ["WROTE "]),
        ("the worker is given a network", without("--network"), (), None,
         ["REACHED the network"]),
        ("a sibling workspace is mounted", args,
         ("-v", "%s:/canary" % SIBLING_VOLUME), None, ["sibling workspace visible"]),
        # Both denied syscalls required, or one can rot behind the other.
        ("seccomp is unconfined", without("--security-opt=seccomp"),
         ("--security-opt", "seccomp=unconfined"), None,
         ["ptrace SUCCEEDED", "no seccomp filter is loaded"]),
        ("no-new-privileges is dropped", without("--security-opt=no-new-privileges"), (),
         None, ["NoNewPrivs is not set"]),
        ("a credential is injected", args,
         ("-e", "AWS_SECRET_ACCESS_KEY=leaked"), None,
         ["credential-shaped env var"]),
        # The two the reviewer showed could be killed silently: nothing exercised the
        # host-path list or the credential-FILE list at all.
        ("a host directory is mounted", args, ("-v", "/etc:/host:ro"), None,
         ["readable host-ish path /host"]),
        ("a credential file is left in the workspace", args, (), plant_credential,
         ["credential file /workspace/.aws"]),
    ]
    missed = []
    for label, case_args, extra, prepare, expected in cases:
        ran, findings = attack_findings(case_args, pkg_parent, extra, prepare)
        absent = [e for e in expected if not any(e in f for f in findings)]
        if not ran:
            print("  FAIL hook did not run: %s" % label)
            missed.append(label)
        elif absent:
            print("  FAIL not fully detected: %s" % label)
            print("       missing finding(s) containing: %s" % ", ".join(map(repr, absent)))
            print("       got: %s" % (findings or "nothing"))
            missed.append(label)
        else:
            print("  ok   detected (%d finding(s)): %s" % (len(expected), label))
    print()
    if missed:
        print("RESULT: self-test FAILED, %d of %d hole(s) undetected"
              % (len(missed), len(cases)))
        return 1
    print("RESULT: self-test passed -- all %d attacks detect their own hole" % len(cases))
    return 0


def main(argv):
    print("== hostile code in a real dependency-install hook ==")
    print("   profile: spec/isolation-profile-v1.json, placeholders filled locally")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-hostile-")
    made_volumes = []
    try:
        build_base_image(tmp)
        seccomp = write_seccomp(tmp)
        args = profile_arguments(seccomp)
        print("   launching with: %s" % " ".join(args))
        print()
        for volume in (VOLUME, SIBLING_VOLUME):
            docker(["volume", "rm", "-f", volume])
            docker(["volume", "create", volume])
            made_volumes.append(volume)
        # Something worth stealing in the sibling's workspace.
        docker(["run", "--rm", "-v", "%s:/canary" % SIBLING_VOLUME, SETUP_IMAGE,
                "sh", "-c", "echo 'another build private data' > /canary/secret"])

        pkg_dir = build_package(tmp)
        os.chmod(tmp, 0o755)
        for path in pathlib.Path(tmp).rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)

        if "--self-test" in argv:
            return self_test(args, str(pkg_dir.parent))

        result = run_install(args, str(pkg_dir.parent))
        # Read the evidence out of the workspace volume with a second container, since the
        # worker is gone and its stdout is not a reliable channel.
        evidence = docker(["run", "--rm", "-v", "%s:/workspace:ro" % VOLUME, SETUP_IMAGE,
                           "sh", "-c", "cat /workspace/hook-evidence.txt 2>/dev/null"],
                          timeout=120).stdout
        ran = MARKER in evidence
        findings = [f for f in evidence.split("\n")[1].split("|")
                    if f] if ran and len(evidence.split("\n")) > 1 else []

        record("install hook executed", "the hostile setup.py runs at all",
               "evidence file written by the hook" if ran
               else "NO EVIDENCE; pip said: %s"
                    % (result.stdout + result.stderr).strip()[-1500:],
               ran, ran,
               "" if ran else "every result below is inconclusive, not contained: an "
                              "attack that never ran proves nothing")

        record("containment", "eight escape attempts from inside the install hook",
               "no finding" if not findings else "; ".join(findings),
               not findings, ran,
               "" if not findings else "the hook reached something the profile says it "
                                       "cannot")

        # Positive control: the same install, same profile, without the hostile body.
        clean = pathlib.Path(tmp) / "clean"
        clean.mkdir()
        (clean / "good").mkdir()
        (clean / "good" / "setup.py").write_text(
            "from setuptools import setup\nsetup(name='good', version='1.0', "
            "py_modules=['good'])\n")
        (clean / "good" / "good.py").write_text("")
        clean.chmod(0o755)
        for path in clean.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        ok = docker(["run", "--rm"] + args + ["-v", "%s:/pkg:ro" % clean,
                                              "-e", "TMPDIR=/tmp", "-e", "HOME=/tmp",
                                              PROBE_IMAGE, "sh", "-c",
                                              "cp -r /pkg/good /workspace/good && "
                                              "pip install --no-index "
                                              "--no-build-isolation --quiet "
                                              "--target=/workspace/site2 "
                                              "/workspace/good 2>&1 "
                                              "&& echo INSTALLED"], timeout=300)
        installed = "INSTALLED" in ok.stdout
        record("allowed install still works", "a benign package installs in the profile",
               "installed" if installed else "FAILED: %s"
               % (ok.stdout + ok.stderr).strip()[-900:], installed, True,
               "" if installed else "the profile refuses everything, so the containment "
                                    "above measures nothing")
    finally:
        for volume in made_volumes:
            docker(["volume", "rm", "-f", volume])
        shutil.rmtree(tmp, ignore_errors=True)

    inconclusive = [r for r in results if not r["ran"]]
    escaped = [r for r in results if r["ran"] and not r["contained"]]
    print()
    print("  %d attempt(s), %d escaped, %d inconclusive"
          % (len(results), len(escaped), len(inconclusive)))
    print()
    if inconclusive:
        print("RESULT: INCONCLUSIVE -- the hook did not run, so nothing was tested")
    elif escaped:
        print("RESULT: %d escape(s) from a dependency-install hook" % len(escaped))
    else:
        print("RESULT: hostile install-time code is contained by the profile of record")
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not escaped and not inconclusive else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
