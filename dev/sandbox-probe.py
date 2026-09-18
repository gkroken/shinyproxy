"""What this Docker host can actually enforce on a worker (WORKPLAN-BUNDLES.md T3).

T3's Pass line is "measured containment and cleanup plus the exact deployment profile",
and T0 recorded two host facts that constrain it. This measures rather than asserts: every
bound the isolation contract requires is exercised against a container that tries to
exceed it, and a bound that is not demonstrably enforced FAILS this suite. A probe that
reports "enforced" without a number is the kind of check this project keeps deleting.

A probe is either a BOUND -- something the isolation contract requires, which must be
demonstrated against a container that tries to exceed it -- or a FACT about what the host
offers, which is recorded and cannot fail. The two are counted separately, because
"apparmor is not available" is not an enforced bound however prominently the detail line
says so.

Each probe prints what it claims, what it measured, and a verdict. Where "enforced" could
be confused with "the workload never got that far", there is a positive control: the CPU
quota is measured against an unrestricted run of the same busy loop, and no-new-privileges
is read back both with and without the flag.

Unlike the other dev suites this runs on the HOST and drives docker directly, because the
host is the subject. It creates only `--rm` containers, one named volume and at most one
loop device, and removes all of them, including on failure.

Usage: python3 dev/sandbox-probe.py [--keep-going]
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

IMAGE = os.environ.get("SANDBOX_PROBE_IMAGE", "python:3.12-slim")
SETUP_IMAGE = os.environ.get("SANDBOX_SETUP_IMAGE", "debian:12-slim")
VOLUME = "skald-sandbox-probe"

results = []


def record(name, claim, measured, ok, note="", kind="bound"):
    """A bound is enforced or it is not. A fact is recorded and cannot fail.

    Two of these probes report what the host offers rather than testing a bound the
    contract requires, and one of them reports a MISSING capability. Printing "ok" beside
    "apparmor ... = N" and rolling it into "11 of 11 enforced" made a recorded limitation
    read as an enforced bound, and the headline is what gets quoted into a sign-off
    (finding 7b6e931-F2). Facts are counted separately and never affect the exit code.
    """
    results.append({"name": name, "claim": claim, "measured": measured, "ok": ok,
                    "note": note, "kind": kind})
    prefix = "note" if kind == "fact" else ("ok" if ok else "FAIL")
    print("  %-4s %-34s %s" % (prefix, name, measured))
    if note:
        print("       %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def run_in(args, script, image=IMAGE):
    """A throwaway container running `script`, always --rm and always without a network."""
    return docker(["run", "--rm", "--network", "none"] + args + [image, "sh", "-c", script],
                  timeout=300)


SPIN = r"""python -c "
import os, time
for _ in range(4):
    if os.fork() == 0:
        end = time.time() + 3
        while time.time() < end: pass
        os._exit(0)
for _ in range(4): os.wait()
t = os.times(); print('%.2f' % (t.children_user + t.children_system))
" """


def probe_cpu():
    """A quota is only meaningful next to a run without one."""
    seen = {}
    for label, args in (("0.5", ["--cpus=0.5"]), ("2.0", ["--cpus=2"]),
                        ("none", [])):
        r = run_in(args, SPIN)
        try:
            seen[label] = float(r.stdout.strip().splitlines()[-1]) / 3.0
        except (ValueError, IndexError):
            record("cpu quota", "--cpus bounds CPU", "probe did not run: %s"
                   % (r.stderr.strip()[-80:] or r.stdout.strip()[-80:]), False)
            return
    ok = (seen["0.5"] < 0.75 < seen["2.0"] < 2.5 < seen["none"])
    record("cpu quota", "--cpus bounds CPU",
           "0.5 -> %.2f cores, 2.0 -> %.2f cores, unrestricted -> %.2f cores"
           % (seen["0.5"], seen["2.0"], seen["none"]), ok,
           "" if ok else "the quota did not scale, so what was measured is not the quota")


def probe_memory():
    r = run_in(["--memory=64m"], "python -c \"b=bytearray()\n"
                                 "for _ in range(256): b += bytes(1<<20)\n"
                                 "print('allocated 256 MiB unbounded')\"")
    killed = r.returncode == 137
    record("memory limit", "--memory OOM-kills an overrun",
           "allocating 256 MiB under a 64 MiB limit exited %d%s"
           % (r.returncode, " (SIGKILL)" if killed else ""), killed,
           "" if killed else "the allocation succeeded, so memory is not bounded")


def probe_pids():
    r = run_in(["--pids-limit=32"], "python -c \"import os\nn=0\n"
                                    "try:\n"
                                    "    for _ in range(100):\n"
                                    "        if os.fork()==0: os._exit(0)\n"
                                    "        n+=1\n"
                                    "except BlockingIOError: print('blocked at %d' % n)\n"
                                    "else: print('forked all 100')\"")
    out = r.stdout.strip()
    m = re.search(r"blocked at (\d+)", out)
    ok = bool(m) and int(m.group(1)) <= 32
    record("pid limit", "--pids-limit blocks fork",
           "%s against a limit of 32" % (out or "no output"), ok)


def probe_no_new_privs():
    with_flag = run_in(["--security-opt", "no-new-privileges"],
                       "grep NoNewPrivs /proc/self/status").stdout.strip()
    without = run_in([], "grep NoNewPrivs /proc/self/status").stdout.strip()
    ok = with_flag.endswith("1") and without.endswith("0")
    record("no-new-privileges", "the flag sets NoNewPrivs",
           "with the flag %r, without it %r" % (with_flag, without), ok,
           "" if ok else "without the contrast this reads the same whether or not the "
                         "flag did anything")


def probe_read_only_rootfs():
    # Both streams: a shell reports a failed redirection on ITS stderr, not on the
    # stdout of the command that never ran, so reading stdout alone saw nothing and
    # called an enforced bound a failure.
    r = run_in(["--read-only"], "echo x > /root/f; echo x > /tmp/f; true")
    both = r.stdout + r.stderr
    refused = both.count("Read-only file system") >= 2
    record("read-only rootfs", "--read-only refuses every write",
           "writes to /root and /tmp both refused" if refused
           else "a write succeeded: %r" % both.strip()[:70], refused)


def probe_tmpfs_size():
    r = run_in(["--read-only", "--tmpfs", "/scratch:rw,size=64m"],
               "dd if=/dev/zero of=/scratch/f bs=1M count=200 2>/dev/null; "
               "stat -c %s /scratch/f")
    try:
        written = int(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        written = -1
    ok = 0 < written <= 64 * 1024 * 1024
    record("sized tmpfs", "a tmpfs with size= caps writes",
           "asked for 200 MiB, wrote %d bytes" % written, ok,
           "tmpfs is RAM, so this bounds a small scratch and not a 10 GiB one")


def probe_storage_opt():
    """Recorded as a limitation, not a failure: it is why the loop probe exists."""
    r = run_in(["--storage-opt", "size=64m"], "true")
    supported = r.returncode == 0
    driver = docker(["info", "--format", "{{.Driver}}"]).stdout.strip()
    backing = docker(["info", "--format",
                      '{{range .DriverStatus}}{{if eq (index . 0) "Backing Filesystem"}}'
                      '{{index . 1}}{{end}}{{end}}']).stdout.strip()
    record("--storage-opt size", "a per-container disk quota",
           "%s on %s: %s" % (driver, backing,
                             "supported" if supported else "REFUSED by the daemon"),
           True, kind="fact",
           note="" if supported else "not a failure of the host, but it is why a bounded "
                                     "workspace needs the loop-backed volume below")


def probe_loop_volume():
    """A real disk quota with no bind mount and no xfs.

    The image is made and attached by one-off PRIVILEGED setup containers. That privilege
    belongs to the trusted launcher, never to a worker: the worker gets the volume, not
    the device, and runs with a read-only rootfs.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="skald-sandbox-"))
    img, loop = tmp / "scratch.img", None
    try:
        with open(img, "wb") as fh:
            fh.truncate(64 * 1024 * 1024)
        os.chmod(tmp, 0o755)
        mk = docker(["run", "--rm", "--privileged", "-v", "%s:/s" % tmp, "--network",
                     "none", SETUP_IMAGE, "sh", "-c", "mkfs.ext4 -q -F /s/scratch.img"])
        if mk.returncode != 0:
            record("loop-backed volume", "a real disk quota",
                   "could not make a filesystem: %s" % mk.stderr.strip()[-70:], False)
            return
        att = docker(["run", "--rm", "--privileged", "-v", "%s:/s" % tmp, "--network",
                      "none", SETUP_IMAGE, "sh", "-c",
                      "losetup --find --show /s/scratch.img"])
        loop = att.stdout.strip().splitlines()[-1] if att.returncode == 0 else None
        if not loop or not loop.startswith("/dev/loop"):
            record("loop-backed volume", "a real disk quota",
                   "could not attach a loop device: %s" % att.stderr.strip()[-70:], False)
            return
        docker(["volume", "rm", "-f", VOLUME])
        cv = docker(["volume", "create", "--driver", "local", "--opt", "type=ext4",
                     "--opt", "device=%s" % loop, VOLUME])
        if cv.returncode != 0:
            record("loop-backed volume", "a real disk quota",
                   "volume create failed: %s" % cv.stderr.strip()[-70:], False)
            return
        r = run_in(["--read-only", "-v", "%s:/scratch" % VOLUME],
                   "dd if=/dev/zero of=/scratch/f bs=1M count=200 2>/dev/null; "
                   "stat -c %s /scratch/f")
        try:
            written = int(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            written = -1
        ok = 0 < written <= 64 * 1024 * 1024
        record("loop-backed volume", "a real disk quota, no bind mount, no xfs",
               "asked for 200 MiB into a 64 MiB volume, wrote %d bytes" % written, ok,
               "the loop device is attached by a one-off privileged setup container; "
               "the worker gets the volume, never the device")
    finally:
        docker(["volume", "rm", "-f", VOLUME])
        if loop:
            docker(["run", "--rm", "--privileged", "--network", "none", SETUP_IMAGE,
                    "losetup", "-d", loop])
        shutil.rmtree(tmp, ignore_errors=True)


def probe_confinement():
    """What the host offers, recorded rather than claimed."""
    enabled = pathlib.Path("/sys/module/apparmor/parameters/enabled")
    apparmor = enabled.read_text().strip() if enabled.exists() else "absent"
    opts = docker(["info", "--format",
                   "{{range .SecurityOptions}}{{println .}}{{end}}"]).stdout.split()
    seccomp = any("seccomp" in o for o in opts)
    record("apparmor", "AppArmor confinement is available",
           "/sys/module/apparmor/parameters/enabled = %s" % apparmor, True, kind="fact",
           note="" if apparmor == "Y" else "NOT available here, so no profile may claim "
                                           "it; confinement rests on userns + seccomp + "
                                           "cgroups")
    record("seccomp", "the daemon applies a seccomp profile",
           ", ".join(opts) or "none reported", seccomp)


def probe_network_none():
    r = run_in([], "python -c \"import socket;"
                   "socket.create_connection(('1.1.1.1',53),2)\" 2>&1; true")
    isolated = "Network is unreachable" in r.stdout or "timed out" in r.stdout
    record("network none", "--network none has no egress",
           "outbound connect %s" % ("refused" if isolated else "SUCCEEDED: " +
                                    r.stdout.strip()[-50:]), isolated)


def main(argv):
    print("== what this host can enforce on a worker ==")
    print("   docker %s, %s" % (docker(["info", "--format", "{{.ServerVersion}}"]
                                        ).stdout.strip(),
                                subprocess.run(["uname", "-r"], capture_output=True,
                                               text=True).stdout.strip()))
    print()
    for probe in (probe_cpu, probe_memory, probe_pids, probe_no_new_privs,
                  probe_read_only_rootfs, probe_tmpfs_size, probe_storage_opt,
                  probe_loop_volume, probe_confinement, probe_network_none):
        try:
            probe()
        except Exception as e:
            record(probe.__name__, "-", "the probe itself failed: %s: %s"
                   % (type(e).__name__, str(e)[:60]), False)
    bounds = [r for r in results if r["kind"] == "bound"]
    facts = [r for r in results if r["kind"] == "fact"]
    bad = [r for r in bounds if not r["ok"]]
    print()
    print("  %d of %d bounds enforced; %d fact(s) recorded"
          % (len(bounds) - len(bad), len(bounds), len(facts)))
    print()
    print("RESULT:", "this host can bound a worker as the contract requires"
          if not bad else "%d required bound(s) NOT enforced" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
