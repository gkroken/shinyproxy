#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The build worker as the isolation profile ships it: does it run, and what does it hold?

Gate finding t5-e5e3071-F6 (P1): the isolation probes of the configuration that ships had
never been run. This is the first part: the launch itself, under every argument
spec/isolation-profile-v1.json gives the build-worker profile, read from that file by
dev/shipping_worker.py. The RUN-side attacks and the resource bounds come next, from
inside a RUN step under this same launch.

Checks, each with an allow control:
  1. the worker runs under the profile: the container's ACTUAL HostConfig, read back
     with docker inspect, carries every bound (not the argv this script wrote)
  2. a RUN builds under it: a file whose content the shell computed comes back out
  3. no-new-privileges is still impossible: the same launch plus the waived flag must
     fail on newuidmap. If it ever starts, the waiver is no longer needed and this fails,
     so the waiver cannot outlive its reason
  4-6. the waiver's three replacements, signed off by the user 2026-09-26:
     4. only newuidmap and newgidmap can gain privilege in the worker image (setuid,
        setgid and file capabilities, scanned from the image's own tar)
     5. a RUN's ids map to unprivileged host ids: not system ids, not any host account,
        not any host subuid/subgid range, per the host's own files
     6. the worker holds no capabilities (PID 1's CapEff and CapPrm are 0)
  7. the root filesystem is read-only, and the tmpfs and the workspace are writable
  8. no worker's state outlives it (the workspace volume included)

Usage: python3 dev/shipping-worker-probe.py [--json] [--self-test]
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

import buildkit_worker_profile as worker_profile
import shipping_worker as sw
import worker_disposal

NET = "skald-sw-net"
WORKER = "skald-sw-worker"
VOLUME = "skald-sw-ws"
SOCK = "skald-sw-sock"
EVIDENCE = "42-RAN"

results = []


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "ok": ok, "note": note})
    print("  %-6s %-44s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("         %s" % note)


docker = sw.docker


# ------------------------------------------------------------------ judges (pure)

def judge_hostconfig(inspected, expected):
    """(ok, detail): does the container's own configuration carry every bound?"""
    host = inspected.get("HostConfig") or {}
    problems = []

    def want(label, got, value):
        if got != value:
            problems.append("%s is %r, not %r" % (label, got, value))

    want("ReadonlyRootfs", host.get("ReadonlyRootfs"), True)
    want("NanoCpus", host.get("NanoCpus"), expected["nano_cpus"])
    want("Memory", host.get("Memory"), expected["memory"])
    want("PidsLimit", host.get("PidsLimit"), expected["pids"])
    want("Tmpfs", host.get("Tmpfs"), {"/tmp": expected["tmpfs"]})
    want("NetworkMode", host.get("NetworkMode"), expected["network"])
    want("Privileged", host.get("Privileged"), False)
    want("CapAdd", host.get("CapAdd") or [], [])
    want("User", (inspected.get("Config") or {}).get("User"), expected["user"])
    opts = host.get("SecurityOpt") or []
    # THE shipped profile, not merely some seccomp= option (7fa81f9 N3). The CLI reads the
    # file and the daemon keeps its content, so SecurityOpt carries the JSON itself; it must
    # equal the profile the launch was given, compared as parsed JSON.
    applied = [o[len("seccomp="):] for o in opts if o.startswith("seccomp=")]
    if not applied:
        problems.append("no seccomp profile in SecurityOpt")
    else:
        try:
            same = json.loads(applied[0]) == expected["seccomp"]
        except ValueError:
            same = False
        if len(applied) != 1 or not same:
            problems.append("the seccomp profile in SecurityOpt is not the shipped one")
    if any("unconfined" in o for o in opts):
        problems.append("an unconfined security option")
    mounts = inspected.get("Mounts") or []
    if not any(m.get("Destination") == "/workspace" and m.get("Type") == "volume"
               and m.get("Name") == expected["volume"] for m in mounts):
        problems.append("no volume %r at /workspace" % expected["volume"])
    if any("docker.sock" in (m.get("Source") or "") for m in mounts):
        problems.append("the Docker socket is mounted")
    return not problems, "; ".join(problems) or "every bound present"


def judge_privilege_files(found, allowed):
    """(ok, detail): found is [(path, why)] from scan_image. Only the allowed helpers may
    gain privilege, and they by file capability, not by a setuid bit."""
    names = {p for p, _ in found}
    extra = sorted(names - allowed)
    missing = sorted(allowed - names)
    setuid_helpers = sorted(p for p, why in found if p in allowed and "setuid" in why)
    if extra:
        return False, "also privileged: %s" % ", ".join(
            "%s (%s)" % (p, w) for p, w in found if p in extra)
    if setuid_helpers:
        return False, "setuid rather than a file capability: %s" % ", ".join(setuid_helpers)
    if missing:
        return False, "the scan did not see %s; it cannot have examined the image" % \
            ", ".join(missing)
    return True, "only %s, by file capability" % ", ".join(sorted(allowed))


def judge_id_map(text, accounts, subranges):
    """(ok, detail): every host id this map reaches must be outside the system range
    (< 1000), outside every host account and outside every host subordinate range."""
    ranges = []
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) != 3:
            return False, "unreadable map line %r" % line
        _, outside, count = (int(p) for p in parts)
        ranges.append((outside, outside + count))
    if not ranges:
        return False, "an empty map; nothing was examined"
    for lo, hi in ranges:
        if lo < 1000:
            return False, "host ids %d-%d include system ids" % (lo, hi - 1)
        taken = sorted(a for a in accounts if lo <= a < hi)
        if taken:
            return False, "host ids %d-%d include host account id(s) %s" % (
                lo, hi - 1, ", ".join(map(str, taken[:5])))
        for slo, shi in subranges:
            if lo < shi and slo < hi:
                return False, "host ids %d-%d overlap a host subordinate range %d-%d" % (
                    lo, hi - 1, slo, shi - 1)
    return True, ", ".join("%d-%d" % (lo, hi - 1) for lo, hi in ranges)


def judge_caps(status):
    """(ok, detail) for a /proc/<pid>/status text: CapEff and CapPrm must both be 0."""
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    eff, prm = fields.get("CapEff", "").strip(), fields.get("CapPrm", "").strip()
    if not eff or not prm:
        return False, "no capability lines were read"
    ok = int(eff, 16) == 0 and int(prm, 16) == 0
    return ok, "CapEff %s, CapPrm %s" % (eff, prm)


# ------------------------------------------------------------------ observations

def scan_image(image):
    """Every file in the image that can gain privilege: [(path, why)]."""
    cid = docker(["create", image]).stdout.strip()
    found = []
    try:
        proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for m in tar:
                why = []
                if m.isreg() and m.mode & 0o4000:
                    why.append("setuid")
                if m.isreg() and m.mode & 0o2000:
                    why.append("setgid")
                if "SCHILY.xattr.security.capability" in (m.pax_headers or {}):
                    why.append("file capability")
                if why:
                    found.append((m.name, "+".join(why)))
        proc.wait()
    finally:
        docker(["rm", "-v", cid])
    return found


def host_ids():
    """Host account ids (users and groups) and subordinate ranges, from the host's files."""
    accounts, subranges = set(), []
    for path in ("/etc/passwd", "/etc/group"):
        for line in pathlib.Path(path).read_text().splitlines():
            parts = line.split(":")
            if len(parts) > 2 and parts[2].isdigit():
                accounts.add(int(parts[2]))
    for path in ("/etc/subuid", "/etc/subgid"):
        p = pathlib.Path(path)
        if p.exists():
            for line in p.read_text().splitlines():
                parts = line.split(":")
                if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                    subranges.append((int(parts[1]), int(parts[1]) + int(parts[2])))
    return accounts, subranges


def make_context(tmp, name, run):
    """FROM scratch plus a static busybox: no registry, no network, no base to trust."""
    ctx = pathlib.Path(tmp) / name
    ctx.mkdir()
    cid = docker(["create", sw.BUSYBOX_IMAGE]).stdout.strip()
    docker(["cp", "%s:/bin/busybox" % cid, str(ctx / "busybox")])
    docker(["rm", "-v", cid])
    (ctx / "Dockerfile").write_text(
        "FROM scratch\nCOPY busybox /bin/busybox\n"
        'RUN ["/bin/busybox", "sh", "-c", %s]\n' % json.dumps(run))
    assert EVIDENCE not in run, "the evidence must not be spelled in the Dockerfile"
    return str(ctx)


RUN_REPORT = ("B=/bin/busybox; echo $((6*7))-RAN > /o.txt; $B cat /proc/self/uid_map > /uid_map; "
              "$B cat /proc/self/gid_map > /gid_map")


def run_build(ctx, out):
    """The client holds the context and streams it over the shared socket; the output comes
    back to `out`. It runs as the worker's uid to open the socket, so `out` must be writable
    by that uid."""
    os.makedirs(out, exist_ok=True)
    os.chmod(out, 0o777)
    got = docker(["run", "--rm", "--network", "none",
                  "-v", "%s:/ctx:ro" % ctx, "-v", "%s:/out" % out]
                 + sw.client_args(SOCK) + ["--entrypoint", "buildctl", sw.UPSTREAM_IMAGE,
                  "--addr", sw.SOCKET_ADDR, "build",
                  "--frontend", "dockerfile.v0", "--local", "context=/ctx",
                  "--local", "dockerfile=/ctx", "--output", "type=local,dest=/out"],
                 timeout=900)
    return got.returncode, (got.stdout + got.stderr)


def read(path):
    try:
        return pathlib.Path(path).read_text()
    except OSError:
        return ""


def expected_config(profile):
    return {"seccomp": json.loads(pathlib.Path(profile).read_text()),
            "nano_cpus": int(float(sw.PLACEHOLDER_VALUES["cpu_quota"]) * 1e9),
            "memory": 2 * 1024 ** 3, "pids": int(sw.PLACEHOLDER_VALUES["pid_limit"]),
            "tmpfs": "rw,noexec,nosuid,nodev,size=%s" % sw.PLACEHOLDER_VALUES["tmpfs_size"],
            "network": NET, "volume": VOLUME,
            "user": "%d:%d" % (sw.WORKER_UID, sw.WORKER_UID)}


def launch(tmp, profile, name=WORKER, **kw):
    kw.setdefault("socket_volume", SOCK)
    sw.dispose(name)
    socket_volume = kw.pop("socket_volume")
    return sw.start(name, NET, VOLUME, profile, socket_volume, **kw)


def cleanup():
    for name in (WORKER, WORKER + "-nnp"):
        sw.dispose(name)
    docker(["volume", "rm", VOLUME, SOCK])
    docker(["network", "rm", NET])


# ------------------------------------------------------------------ the run

def main(argv):
    print("== the build worker under the profile it ships with ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-sw-")
    try:
        profile = worker_profile.write(tmp, worker_profile.fetch_default(tmp))
        cleanup()
        if not sw.build_worker_image(pathlib.Path(tmp) / "image"):
            raise SystemExit("could not build the derived worker image")
        docker(["network", "create", "--internal", NET])
        if not sw.prepare_volume(SOCK):
            raise SystemExit("could not prepare the socket volume")
        if not sw.prepare_volume(VOLUME):
            raise SystemExit("could not prepare the workspace volume")

        if "--self-test" in argv:
            return self_test(tmp, profile)

        # 1. The launch, read back from the container.
        launch(tmp, profile)
        ready = sw.wait_ready(WORKER)
        inspected = json.loads(docker(["inspect", WORKER]).stdout or "[{}]")[0]
        ok, detail = judge_hostconfig(inspected, expected_config(profile))
        record("the worker runs under the profile",
               "it starts, and docker inspect shows every bound of the profile",
               detail if ready else "did not start: %s" % sw.logs(WORKER).strip()[-160:],
               ready and ok)

        # 2. A real RUN under it.
        out = pathlib.Path(tmp) / "out"
        rc, blob = run_build(make_context(tmp, "ctx", RUN_REPORT), str(out))
        produced = read(out / "o.txt").strip()
        record("a RUN builds under it",
               "the RUN's computed file comes back: %s" % EVIDENCE,
               "ran" if rc == 0 and produced == EVIDENCE
               else "FAILED rc=%d: %s" % (rc, blob.strip()[-160:]),
               rc == 0 and produced == EVIDENCE)

        # 5. The RUN's ids, and whether they are the worker's own user namespace.
        accounts, subranges = host_ids()
        maps_ok, maps_detail = [], []
        for kind in ("uid_map", "gid_map"):
            ok, detail = judge_id_map(read(out / kind), accounts, subranges)
            maps_ok.append(ok)
            maps_detail.append("%s %s" % (kind, detail))
        daemon_map = docker(["exec", WORKER, "sh", "-c",
                             "cat /proc/$(pgrep -x buildkitd)/uid_map"]).stdout
        same_ns = daemon_map.split() == read(out / "uid_map").split() and bool(daemon_map)
        record("a RUN's ids map to unprivileged host ids",
               "no system id, no host account, no host subordinate range; the RUN is in "
               "the worker's own user namespace",
               "; ".join(maps_detail) + ("" if same_ns else "; NOT the daemon's namespace"),
               all(maps_ok) and same_ns)

        # 6. The worker's own process.
        status = docker(["exec", WORKER, "cat", "/proc/1/status"]).stdout
        ok, detail = judge_caps(status)
        uid_line = next((l.split()[1] for l in status.splitlines()
                         if l.startswith("Uid:")), "?")
        record("the worker holds no capabilities",
               "PID 1: CapEff 0, CapPrm 0, running as uid %d" % sw.WORKER_UID,
               "%s, uid %s" % (detail, uid_line),
               ok and uid_line == str(sw.WORKER_UID))

        # 7. Read-only root, writable scratch and workspace.
        writes = {path: docker(["exec", WORKER, "touch", path])
                  for path in ("/home/probe", "/tmp/probe", "/workspace/probe")}
        root_refused = "Read-only file system" in writes["/home/probe"].stderr
        scratch_ok = writes["/tmp/probe"].returncode == 0
        workspace_ok = writes["/workspace/probe"].returncode == 0
        record("the root filesystem is read-only",
               "a write to / is refused (EROFS); /tmp and /workspace take writes",
               "root: %s; /tmp: %s; /workspace: %s" % (
                   "refused" if root_refused else "WRITABLE",
                   "ok" if scratch_ok else "refused", "ok" if workspace_ok else "refused"),
               root_refused and scratch_ok and workspace_ok)

        # 4. The image the worker runs.
        ok, detail = judge_privilege_files(scan_image(sw.BUILDKIT_IMAGE),
                                           sw.PRIVILEGED_HELPERS)
        record("only newuidmap and newgidmap can gain privilege",
               "no other setuid, setgid or file-capability binary in the worker image",
               detail, ok)

        # 3. The waiver's reason, still true?
        launch(tmp, profile, name=WORKER + "-nnp", include_waived=True)
        started = sw.wait_ready(WORKER + "-nnp", seconds=15)
        caps_error = "Could not set caps" in sw.logs(WORKER + "-nnp")
        record("no-new-privileges is still impossible",
               "with the waived flag added, rootlesskit fails on newuidmap",
               "fails: newuidmap could not set caps" if caps_error and not started
               else ("STARTED: the waiver is no longer needed, remove it" if started
                     else "failed for another reason: %s"
                     % sw.logs(WORKER + "-nnp").strip()[-120:]),
               caps_error and not started)
        sw.dispose(WORKER + "-nnp")

        # 8. Disposal, the workspace and socket volumes included.
        held, left = sw.dispose(WORKER, VOLUME, SOCK)
        record("no worker's state outlives it",
               "every volume the worker held, workspace and socket, is gone",
               "%d volume(s) held, none left" % len(held) if not left
               else "left: %s" % ", ".join(left),
               not left and VOLUME in held)
    finally:
        cleanup()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["ok"]]
    print()
    print("  %d check(s), %d failed" % (len(results), len(bad)))
    print()
    print("RESULT:", "the worker runs under its shipping profile, with the waiver's "
                     "replacements holding" if not bad else "%d check(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


def self_test(tmp, profile):
    """Each check must fail when what it protects is taken away."""
    print("== self-test: each check must fail when its defence is removed ==")
    missed = []

    def expect_fail(label, ok_detail):
        ok, detail = ok_detail
        if ok:
            print("  FAIL NOT caught: %s (%s)" % (label, detail))
            missed.append(label)
        else:
            print("  ok   caught: %s -- %s" % (label, detail[:110]))

    # The judges, offline, on the inputs a weakened configuration would produce.
    accounts, subranges = {0, 1000}, [(100000, 165536)]
    expect_fail("a map reaching host root", judge_id_map("0 0 1", accounts, subranges))
    expect_fail("a map reaching a host account",
                judge_id_map("0 1000 1", accounts, subranges))
    expect_fail("a map into a host subuid range",
                judge_id_map("0 2401 1\n1 100000 65536", accounts, subranges))
    ok, _ = judge_id_map("0 2401 1\n1 3000000 65536", accounts, subranges)
    if not ok:
        print("  FAIL the shipped map is refused, so the map check refuses everything")
        missed.append("map control")
    expect_fail("a capability held", judge_caps("CapEff:\t0000000000000400\n"
                                                "CapPrm:\t0000000000000400\n"))
    expect_fail("no capability lines at all", judge_caps("Name: x\n"))
    expect_fail("a setuid helper", judge_privilege_files(
        [("usr/bin/newuidmap", "setuid"), ("usr/bin/newgidmap", "file capability")],
        sw.PRIVILEGED_HELPERS))
    expect_fail("a scan that saw nothing", judge_privilege_files([], sw.PRIVILEGED_HELPERS))

    # The configuration check against THE shipped seccomp profile (7fa81f9 N3): a container
    # carrying every bound, then the same with a profile missing its added entries, and with
    # the profile's path instead of its content.
    exp = expected_config(profile)
    shipped = json.dumps(exp["seccomp"])
    def conforming(seccomp_opt):
        return {"HostConfig": {"ReadonlyRootfs": True, "NanoCpus": exp["nano_cpus"],
                               "Memory": exp["memory"], "PidsLimit": exp["pids"],
                               "Tmpfs": {"/tmp": exp["tmpfs"]}, "NetworkMode": exp["network"],
                               "Privileged": False, "CapAdd": None,
                               "SecurityOpt": [seccomp_opt]},
                "Config": {"User": exp["user"]},
                "Mounts": [{"Destination": "/workspace", "Type": "volume",
                            "Name": exp["volume"]}]}
    ok, detail = judge_hostconfig(conforming("seccomp=" + shipped), exp)
    if not ok:
        print("  FAIL the shipped configuration is refused (%s)" % detail)
        missed.append("hostconfig control")
    weaker = json.loads(shipped)
    weaker["syscalls"] = weaker["syscalls"][:-2]
    expect_fail("a different seccomp profile",
                judge_hostconfig(conforming("seccomp=" + json.dumps(weaker)), exp))
    expect_fail("a seccomp option that is a path, not the profile",
                judge_hostconfig(conforming("seccomp=/elsewhere/profile.json"), exp))

    # Live: the upstream image, which carries setuid-root fusermount3 and setgid
    # unix_chkpwd. The scan must see both on the real image, not only on a fixture.
    expect_fail("the upstream image's extra privileged binaries",
                judge_privilege_files(scan_image(sw.UPSTREAM_IMAGE), sw.PRIVILEGED_HELPERS))

    # Live: the worker launched without --read-only. The configuration check and the
    # write check must both notice.
    launch(tmp, profile, omit=["--read-only"])
    if sw.wait_ready(WORKER):
        inspected = json.loads(docker(["inspect", WORKER]).stdout or "[{}]")[0]
        expect_fail("the launch without --read-only",
                    judge_hostconfig(inspected, expected_config(profile)))
        # The write check keys on EROFS, not on any refusal: the dedicated uid does not
        # own /home, so without --read-only the write is still refused, for permissions.
        # What must disappear is the read-only refusal itself.
        attempt = docker(["exec", WORKER, "touch", "/home/probe"])
        if "Read-only file system" not in attempt.stderr:
            print("  ok   caught: without --read-only the write is no longer refused as "
                  "read-only (%s)" % (attempt.stderr.strip()[-60:] or "it succeeded"))
        else:
            print("  FAIL the root still reports read-only without --read-only")
            missed.append("read-only control")
        # And a RUN that writes the evidence and then fails must not count as built.
        out = pathlib.Path(tmp) / "out-failing"
        rc, _ = run_build(make_context(tmp, "failing", RUN_REPORT + "; exit 3"), str(out))
        if rc != 0:
            print("  ok   caught: a RUN that fails is not counted (rc=%d)" % rc)
        else:
            print("  FAIL a failing RUN was counted as built")
            missed.append("failing RUN")
    else:
        print("  FAIL the worker did not start without --read-only; nothing was shown")
        missed.append("live launch")
    # Disposal that forgets the workspace volume -- what the first run of this probe did.
    held, left = sw.dispose(WORKER)
    if VOLUME in held and VOLUME in left:
        print("  ok   caught: a teardown that keeps the workspace volume leaves %s" % VOLUME)
    else:
        print("  FAIL a teardown without the volume removal was not seen (held %s, left %s)"
              % (held, left))
        missed.append("volume disposal")

    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- every check fails when its defence is removed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
