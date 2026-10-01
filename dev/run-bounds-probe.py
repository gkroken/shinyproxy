#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""What build code cannot consume from a RUN step (t5-e5e3071-F6, part 3; decision 6).

Decision 6 bounds CPU, memory, PIDs, disk and logs. dev/sandbox-probe.py measured those
bounds on a plain container under the rootful daemon (T3(a)); it never ran BuildKit, so it
never showed that a bound set on the WORKER reaches the build code the worker runs, three
layers down: rootlesskit, buildkitd, runc, the RUN's own process tree. Here each bound is
attacked from inside a real RUN step, under the worker the shipping profile launches
(dev/run_attack_harness, workspace on the loop-backed quota volume), and must hold.

Every check has an allow control in the same RUN -- the same mechanism doing a legitimate
amount successfully -- so a check cannot pass because the attempt quietly did not run. And
--self-test restarts the worker with the defences removed and requires every check to go
red, because a probe that passes against an unbounded worker proves nothing.

The attempts observe and report; the judging is in Python, on the report.

Usage: python3 dev/run-bounds-probe.py [--json] [--self-test]
"""

import json
import shutil
import sys
import tempfile

import quota_volume
import run_attack_harness as h
import shipping_worker as sw

# The runtime this probe measures, read statically by dev/schema-fixture-check.py: a
# runtime's proofs in spec/isolation-profile-v1.json may cite only probes that measure THAT
# runtime (gate finding t5-f4f5f32-F2).
MEASURES_RUNTIME = "runc-rootless"

docker = h.docker
results = []

# The limits the shipping launch applies, from the same values it is started with.
MEMORY_MB = 2048                                    # memory_limit "2g"
PID_LIMIT = int(sw.PLACEHOLDER_VALUES["pid_limit"])
CPU_QUOTA = float(sw.PLACEHOLDER_VALUES["cpu_quota"])
LOG_SIZE = int(sw.PLACEHOLDER_VALUES["step_log_max_bytes"])
LOG_SPEED = int(sw.PLACEHOLDER_VALUES["step_log_max_bytes_per_second"])
QUOTA_BYTES = h.QUOTA_MB * 1024 * 1024
assert sw.PLACEHOLDER_VALUES["memory_limit"] == "2g", "MEMORY_MB follows memory_limit"

# The attempt sizes: each well past its limit, so "held" is not a near miss.
MEMORY_TARGET_MB = MEMORY_MB + 512
FORK_TARGET = 1000
BURN_LOOPS = 4
DISK_TARGET_MB = h.QUOTA_MB + 256
FLOOD_BYTES = 16 * 1024 * 1024


def record(name, expectation, observed, held, note="", kind="check", args=None):
    """kind='bound' marks the proof of a daemon bound in spec/isolation-profile-v1.json,
    with the literal argument it ran; dev/schema-fixture-check.py requires the two to
    agree. The other checks re-measure bounds sandbox-probe.py already proves, from a RUN."""
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "held": held, "note": note, "kind": kind, "args": args})
    print("  %-6s %-34s %s" % ("ok" if held else "FAIL", name, observed))
    if note:
        print("         %s" % note)


# ------------------------------------------------------------------ the attempts (shell)

MOUNTS = r"""
# The RUN's own root is a snapshot on the workspace volume; its mount options are the
# kernel's statement of what applies, read from inside.
echo "run_root_opts=$(awk '$5=="/"{print $6}' /proc/self/mountinfo | head -1)"
"""

MEMORY = r"""
# Grow an awk array 1 MiB at a time, writing the size reached every 16 MiB. The control
# grows to 256 MiB and must finish; the attempt grows past the worker's limit and must be
# killed at or below it.
grow() {
  awk -v n="$1" -v f="$2" 'BEGIN { s = sprintf("%%1048576s", "")
    for (i = 1; i <= n; i++) { a[i] = s "" i; if (i %% 16 == 0) { print i > f; close(f) } } }'
}
grow 256 /tmp/ctl; echo "control_rc=$?"; echo "control_mb=$(cat /tmp/ctl 2>/dev/null)"
grow %(target)d /tmp/mb; echo "attempt_rc=$?"; echo "attempt_mb=$(cat /tmp/mb 2>/dev/null)"
"""

PIDS = r"""
# Fork short-lived sleeps in a subshell, recording the count after each. busybox ash dies on
# a failed fork, so the subshell's last recorded count is how far it got; the outer shell
# uses only builtins afterwards (read, echo), because it cannot fork either until the
# sleeps end. The control forks 50 first and waits for them.
( n=0; while [ $n -lt 50 ]; do sleep 1 & n=$((n+1)); echo $n > /tmp/c; done; wait )
read c < /tmp/c; echo "control_forked=$c"
( n=0; while [ $n -lt %(target)d ]; do sleep 4 & n=$((n+1)); echo $n > /tmp/n; done )
echo "attempt_rc=$?"
read n < /tmp/n; echo "attempt_forked=$n"
"""

CPU = r"""
# Busy loops for 5 s, summing their utime+stime ticks from /proc. The control runs one loop
# (it must get about one core, which also calibrates the tick rate); the attempt runs more
# loops than the quota and must be held to it. nproc says whether the host could have given
# more, which is what makes "held" mean the quota and not the machine.
burn() {
  i=0; while [ $i -lt $1 ]; do ( while :; do :; done ) & i=$((i+1)); done
  sleep 5; T=0
  for p in $(jobs -p); do T=$((T + $(awk '{print $14 + $15}' /proc/$p/stat))); done
  kill $(jobs -p); wait 2>/dev/null
}
echo "cpus_visible=$(nproc)"
burn 1; echo "control_ticks=$T"
burn %(loops)d; echo "attempt_ticks=$T"
"""

# Streamed: stdout IS the subject, so it goes to the build log and the script writes its
# own /report. A marker first (the allow control: output does reach the client), then the
# flood, then an end marker that clipping must swallow.
FLOOD_BURST = r"""
echo SKALD-LOG-START
yes AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | head -c %(bytes)d
echo SKALD-LOG-END
echo done > /report
"""

# Paced under the rate bound (about 100 KiB/s against 200 KiB/s), so the rate bound does
# not trip and what stops it is the size bound.
FLOOD_PACED = r"""
echo SKALD-LOG-START
i=0
while [ $i -lt %(seconds)d ]; do
  head -c 102400 /dev/zero | tr '\0' B | fold -w 100; echo; sleep 1; i=$((i+1))
done
echo SKALD-LOG-END
echo done > /report
"""

DISK = r"""
# Write past the quota. The control writes 32 MiB and must succeed. The attempt must stop
# with ENOSPC at or below the quota. Both files are removed afterwards so the step can still
# export its report -- a full volume would otherwise fail the build, not the attempt.
dd if=/dev/zero of=/ctl bs=1M count=32 2>/dev/null
echo "control_bytes=$(stat -c %%s /ctl 2>/dev/null)"; rm -f /ctl
dd if=/dev/zero of=/big bs=1M count=%(target)d 2>/tmp/dd; echo "attempt_rc=$?"
echo "attempt_bytes=$(stat -c %%s /big 2>/dev/null)"
echo "attempt_enospc=$(grep -c 'No space left on device' /tmp/dd)"
rm -f /big
"""

ALIVE = r"""
echo "alive=yes"
"""


# ------------------------------------------------------------------ judges (pure)

def _value(report, key):
    for line in report:
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return ""


def _int(text, default=-1):
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


def judge_mounts(report, workspace_opts):
    """nosuid,nodev on the worker's /workspace and, inherited, on the RUN's own root."""
    run_opts = _value(report, "run_root_opts").split(",")
    ws = (workspace_opts or "").split(",")
    need = ("nosuid", "nodev")
    ok = all(o in run_opts for o in need) and all(o in ws for o in need)
    return ok, "worker /workspace: %s; RUN root: %s" % (
        workspace_opts or "not read", _value(report, "run_root_opts") or "not read")


def judge_memory(report, limit_mb=MEMORY_MB):
    c_rc, c_mb = _value(report, "control_rc"), _int(_value(report, "control_mb"))
    a_rc, a_mb = _value(report, "attempt_rc"), _int(_value(report, "attempt_mb"))
    control = c_rc == "0" and c_mb == 256
    held = a_rc == "137" and 0 < a_mb <= limit_mb
    note = "" if control else "  <- inconclusive: the 256 MiB control did not complete"
    return control and held, ("control 256 MiB: rc %s at %s MiB; attempt %d MiB: rc %s at "
                              "%s MiB (limit %d)%s" % (c_rc, c_mb, MEMORY_TARGET_MB, a_rc,
                                                       a_mb, limit_mb, note))


def judge_pids(report, limit=PID_LIMIT, target=FORK_TARGET):
    control = _int(_value(report, "control_forked")) == 50
    forked = _int(_value(report, "attempt_forked"))
    rc = _value(report, "attempt_rc")
    # Blocked (the subshell died on a failed fork, rc != 0) before the target, and below
    # the limit -- the worker's own processes share it, so the count is strictly less.
    held = rc not in ("0", "") and 0 < forked < limit
    note = "" if control else "  <- inconclusive: the 50-fork control did not complete"
    return control and held, ("control forked %s of 50; attempt forked %s of %d before "
                              "being refused (rc %s, limit %d)%s"
                              % (_value(report, "control_forked") or "?", forked, target,
                                 rc or "?", limit, note))


def judge_cpu(report, quota=CPU_QUOTA, loops=BURN_LOOPS, seconds=5, hz=100):
    visible = _int(_value(report, "cpus_visible"))
    control = _int(_value(report, "control_ticks")) / float(seconds * hz)
    attempt = _int(_value(report, "attempt_ticks")) / float(seconds * hz)
    # The control must show about one core: that calibrates the tick rate and shows the
    # measurement measures. The host must have more cores than the quota, or a held
    # attempt says nothing about the quota. Then the attempt must sit at the quota.
    calibrated = 0.8 <= control <= 1.2
    room = visible >= loops > quota
    held = 0 < attempt <= quota * 1.15
    why = ""
    if not calibrated:
        why = "  <- inconclusive: one loop did not measure as about one core"
    elif not room:
        why = "  <- inconclusive: %d visible cores cannot exceed a quota of %.1f" % (
            visible, quota)
    return calibrated and room and held, (
        "1 loop -> %.2f cores; %d loops -> %.2f cores (quota %.1f, %d visible)%s"
        % (control, loops, attempt, quota, visible, why))


def _flood_received(blob, char):
    """How many flood bytes reached the client, and whether it saw a clip notice."""
    received = sum(line.count(char) for line in blob.splitlines()
                   if char * 20 in line)
    clipped = [l for l in blob.splitlines() if "output clipped" in l]
    return received, clipped


def judge_log_speed(blob, report_ok, worker_log_growth, speed=LOG_SPEED):
    received, clipped = _flood_received(blob, "A")
    start = "SKALD-LOG-START" in blob
    rate_clip = any("/s reached" in l for l in clipped)
    # Held: a rate clip notice, the end marker never delivered, and the flood delivered
    # nowhere near its size. Control: the start marker arrived, and the step finished.
    held = (rate_clip and "SKALD-LOG-END" not in blob
            and received <= max(4 * speed, 1 << 20) and worker_log_growth < 65536)
    control = start and report_ok
    note = "" if control else "  <- inconclusive: the log never reached the client"
    return control and held, ("%d of %d flood bytes reached the client; clip: %s; worker's "
                              "own log grew %d bytes%s"
                              % (received, FLOOD_BYTES,
                                 (clipped[0].split("[", 1)[-1] if clipped else "none"),
                                 worker_log_growth, note))


def judge_log_size(blob, report_ok, size=LOG_SIZE):
    received, clipped = _flood_received(blob, "B")
    size_clip = any("reached" in l and "/s reached" not in l for l in clipped)
    # Held: a size clip notice (not the rate one: the flood was paced under the rate), and
    # no more than the size limit delivered. Control: the paced output was being delivered
    # -- at least half the limit arrived before the clip -- so the rate bound was not what
    # stopped it.
    held = size_clip and received <= size + 65536 and "SKALD-LOG-END" not in blob
    control = report_ok and received >= size // 2
    note = "" if control else "  <- inconclusive: the paced output was not being delivered"
    return control and held, ("%d paced bytes reached the client (limit %d); clip: %s%s"
                              % (received, size,
                                 (clipped[0].split("[", 1)[-1] if clipped else "none"),
                                 note))


def judge_disk(report, quota=QUOTA_BYTES):
    control = _int(_value(report, "control_bytes")) == 32 * 1024 * 1024
    written = _int(_value(report, "attempt_bytes"))
    enospc = _int(_value(report, "attempt_enospc"), 0) > 0
    held = _value(report, "attempt_rc") not in ("0", "") and enospc and 0 < written <= quota
    note = "" if control else "  <- inconclusive: the 32 MiB control write did not complete"
    return control and held, ("control 32 MiB: %s; attempt %d MiB: wrote %d bytes, ENOSPC %s "
                              "(quota %d)%s" % ("ok" if control else "failed", DISK_TARGET_MB,
                                                written, "yes" if enospc else "no", quota,
                                                note))


# ------------------------------------------------------------------ the run

def step(tmp, name, script, **fill):
    report, blob = h.run_local_step(tmp, name, script % fill if fill else script)
    lines = [l.strip() for l in report.strip().splitlines() if l.strip()]
    return lines, blob


def workspace_options():
    out = docker(["exec", h.WORKER, "awk", '$2=="/workspace"{print $4}', "/proc/mounts"])
    return out.stdout.strip()


def worker_env():
    out = docker(["inspect", "-f", "{{json .Config.Env}}", h.WORKER])
    try:
        return json.loads(out.stdout)
    except ValueError:
        return []


def run_all(tmp, label=""):
    """Every attempt against the worker as it is currently started. Returns name -> (held,
    detail). Disk goes last: it is the one attempt that can leave the worker unable to
    build if its cleanup fails."""
    out = {}

    def check(name, judged):
        out[name] = judged

    report, blob = step(tmp, "mounts" + label, MOUNTS)
    check("mounts", judge_mounts(report, workspace_options()) if report
          else (False, "no report: %s" % blob.strip()[-160:]))

    report, _ = step(tmp, "memory" + label, MEMORY, target=MEMORY_TARGET_MB)
    check("memory", judge_memory(report))

    report, _ = step(tmp, "pids" + label, PIDS, target=FORK_TARGET)
    check("pids", judge_pids(report))

    report, _ = step(tmp, "cpu" + label, CPU, loops=BURN_LOOPS)
    check("cpu", judge_cpu(report))

    before = len(sw.logs(h.WORKER))
    report, blob = h.run_local_step(tmp, "flood" + label,
                                    FLOOD_BURST % {"bytes": FLOOD_BYTES}, stream=True)
    growth = len(sw.logs(h.WORKER)) - before
    check("log speed", judge_log_speed(blob, bool(report.strip()), growth))

    seconds = (LOG_SIZE * 3 // 2) // 102400 + 1
    report, blob = h.run_local_step(tmp, "paced" + label,
                                    FLOOD_PACED % {"seconds": seconds}, stream=True)
    check("log size", judge_log_size(blob, bool(report.strip())))

    report, _ = step(tmp, "disk" + label, DISK, target=DISK_TARGET_MB)
    check("disk", judge_disk(report))

    report, blob = step(tmp, "alive" + label, ALIVE)
    running = docker(["inspect", "-f", "{{.State.Running}}", h.WORKER]).stdout.strip()
    check("alive", (running == "true" and _value(report, "alive") == "yes",
                    "worker running: %s; a step after every attempt: %s"
                    % (running, "built" if report else "FAILED " + blob.strip()[-120:])))
    return out


def main(argv):
    print("== what build code cannot consume from a RUN step ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-bounds-")
    try:
        h.setup(tmp)
        if "--self-test" in argv:
            return self_test(tmp)
        env = worker_env()
        size_arg = "--env=BUILDKIT_STEP_LOG_MAX_SIZE=%s" % LOG_SIZE
        speed_arg = "--env=BUILDKIT_STEP_LOG_MAX_SPEED=%s" % LOG_SPEED
        # The daemon bounds' proof must be the argument the worker actually carries.
        launched = {a[len("--env="):] for a in (size_arg, speed_arg)} <= set(env)
        got = run_all(tmp)

        ok, detail = got["mounts"]
        record("the workspace is nosuid,nodev",
               "the quota volume's options, on the worker and on the RUN's root", detail, ok)
        ok, detail = got["memory"]
        record("memory is bounded from a RUN",
               "growth past the limit is OOM-killed at or below it", detail, ok)
        ok, detail = got["pids"]
        record("fork is bounded from a RUN", "a fork bomb is refused below the limit",
               detail, ok)
        ok, detail = got["cpu"]
        record("cpu is bounded from a RUN", "more busy loops than the quota get the quota",
               detail, ok)
        ok, detail = got["log speed"]
        record("step log speed", "a burst flood is clipped at the rate bound",
               detail if launched else detail + "  <- the worker does not carry the "
                                                 "argument this records", ok and launched,
               kind="bound", args="--env=BUILDKIT_STEP_LOG_MAX_SPEED=%s" % LOG_SPEED)
        ok, detail = got["log size"]
        record("step log size", "a paced flood is clipped at the size bound",
               detail if launched else detail + "  <- the worker does not carry the "
                                                 "argument this records", ok and launched,
               kind="bound", args="--env=BUILDKIT_STEP_LOG_MAX_SIZE=%s" % LOG_SIZE)
        ok, detail = got["disk"]
        record("disk is bounded from a RUN", "writes past the quota stop with ENOSPC",
               detail, ok)
        ok, detail = got["alive"]
        record("the worker survives every attempt", "it is running and still builds",
               detail, ok)
        # The launcher's teardown releases what it attached. A guard that never matched
        # leaked a loop device per run until this check existed.
        loop = h.state["loop"]
        h.stop_worker()
        still = quota_volume.attached(loop, h.VOLUME)
        gone = h.VOLUME not in docker(["volume", "ls", "-q"]).stdout.split()
        record("the workspace's loop device is released",
               "teardown detaches the device and removes the volume",
               "%s: %s; volume %s" % (loop, "STILL ATTACHED" if still else "detached",
                                      "removed" if gone else "STILL PRESENT"),
               bool(loop) and not still and gone)
    finally:
        h.teardown()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["held"]]
    print()
    print("  %d check(s), %d not held" % (len(results), len(bad)))
    print()
    print("RESULT:", "every resource bound holds against build code in a RUN"
          if not bad else "%d bound(s) NOT held" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


def self_test(tmp):
    """Each check must go red when its defence is removed, and each judge must refuse an
    inconclusive control."""
    print("== self-test: each check must fail when its defence is removed ==")
    missed = []

    def expect(label, judged, want):
        ok, detail = judged
        if ok != want:
            print("  FAIL %s: judged held=%s (%s)" % (label, ok, detail))
            missed.append(label)
        else:
            print("  ok   %s" % label)

    # Offline: the controls. A check whose control failed must not pass, however the
    # attempt looked.
    expect("memory with a failed control",
           judge_memory(["control_rc=137", "control_mb=128", "attempt_rc=137",
                         "attempt_mb=2000"]), False)
    expect("memory that completed its growth",
           judge_memory(["control_rc=0", "control_mb=256", "attempt_rc=0",
                         "attempt_mb=2560"]), False)
    expect("memory killed above the limit",
           judge_memory(["control_rc=0", "control_mb=256", "attempt_rc=137",
                         "attempt_mb=3968"]), False)
    expect("memory held", judge_memory(["control_rc=0", "control_mb=256", "attempt_rc=137",
                                        "attempt_mb=1984"]), True)
    expect("pids with a failed control",
           judge_pids(["control_forked=12", "attempt_rc=2", "attempt_forked=474"]), False)
    expect("pids that reached the target",
           judge_pids(["control_forked=50", "attempt_rc=0", "attempt_forked=1000"]), False)
    expect("pids held", judge_pids(["control_forked=50", "attempt_rc=2",
                                    "attempt_forked=474"]), True)
    expect("cpu on a host with no more cores than the quota",
           judge_cpu(["cpus_visible=2", "control_ticks=500", "attempt_ticks=1000"]), False)
    expect("cpu with an uncalibrated control",
           judge_cpu(["cpus_visible=16", "control_ticks=50", "attempt_ticks=1000"]), False)
    expect("cpu past the quota",
           judge_cpu(["cpus_visible=16", "control_ticks=500", "attempt_ticks=2000"]), False)
    expect("cpu held", judge_cpu(["cpus_visible=16", "control_ticks=500",
                                  "attempt_ticks=1000"]), True)
    expect("disk with a failed control",
           judge_disk(["control_bytes=0", "attempt_rc=1", "attempt_bytes=700000000",
                       "attempt_enospc=1"]), False)
    expect("disk written in full",
           judge_disk(["control_bytes=33554432", "attempt_rc=0",
                       "attempt_bytes=1073741824", "attempt_enospc=0"]), False)
    expect("disk held", judge_disk(["control_bytes=33554432", "attempt_rc=1",
                                    "attempt_bytes=700000000", "attempt_enospc=1"]), True)
    expect("mounts without nosuid",
           judge_mounts(["run_root_opts=rw,nodev,relatime"], "rw,nodev,relatime"), False)
    expect("mounts held", judge_mounts(["run_root_opts=rw,nosuid,nodev,relatime"],
                                       "rw,nosuid,nodev,relatime"), True)
    flood = "#8 1.0 SKALD-LOG-START\n" + ("#8 1.0 " + "A" * 63 + "\n") * 100
    expect("a log that never reached the client",
           judge_log_speed("#8 [output clipped, log limit 200KiB/s reached]", True, 0),
           False)
    expect("a flood with no clip notice",
           judge_log_speed(flood + "#8 1.0 SKALD-LOG-END\n", True, 0), False)
    expect("a flood that landed in the worker's own log",
           judge_log_speed(flood + "#8 [output clipped, log limit 200KiB/s reached]\n",
                           True, 1 << 20), False)
    expect("log speed held",
           judge_log_speed(flood + "#8 [output clipped, log limit 200KiB/s reached]\n",
                           True, 0), True)

    # Live: the release check must see a device a teardown forgot to detach.
    probe_dir = tempfile.mkdtemp(prefix="skald-quota-st-")
    name = "skald-bounds-selftest"
    loop = quota_volume.create(name, probe_dir, 64)
    docker(["volume", "rm", "-f", name])          # the volume, and NOT the device
    if quota_volume.attached(loop, name):
        print("  ok   caught: a teardown that removes the volume but not the device")
    else:
        print("  FAIL a forgotten loop device was not seen as attached")
        missed.append("loop release")
    quota_volume.destroy(name, loop, probe_dir)
    if quota_volume.attached(loop, name):
        print("  FAIL destroy() left %s attached" % loop)
        missed.append("loop destroy")
    else:
        print("  ok   destroy() detaches it")
    shutil.rmtree(probe_dir, ignore_errors=True)

    # Live, launch 1: every in-worker defence removed at once -- the SWAP bound (the
    # memory limit stays, so the memory check going red shows --memory-swap specifically
    # is what holds it: Docker's default swap lets the growth finish), pids, cpus, the log
    # bounds (set to unlimited) -- and the quota volume without its options. Each check
    # must go red on its own evidence.
    print()
    print("  -- live: a worker without --memory-swap, --pids-limit, --cpus, the log "
          "bounds, and nosuid,nodev")
    h.start_worker(omit=("--memory-swap", "--pids-limit", "--cpus",
                         "--env=BUILDKIT_STEP_LOG_MAX"),
                   extra=["--env=BUILDKIT_STEP_LOG_MAX_SIZE=-1",
                          "--env=BUILDKIT_STEP_LOG_MAX_SPEED=-1"],
                   volume_options="")
    got = run_all(tmp, "-weak")
    for name in ("mounts", "memory", "pids", "cpu", "log speed", "log size"):
        ok, detail = got[name]
        if ok:
            print("  FAIL NOT caught without its defence: %s (%s)" % (name, detail))
            missed.append("live " + name)
        else:
            print("  ok   caught: %s -- %s" % (name, detail[:150]))

    # Live, launch 2: a plain Docker volume instead of the quota volume.
    print()
    print("  -- live: a worker on a plain volume instead of the quota volume")
    h.start_worker(quota=False)
    report, _ = step(tmp, "disk-plain", DISK, target=DISK_TARGET_MB)
    ok, detail = judge_disk(report)
    if ok:
        print("  FAIL NOT caught without the quota: disk (%s)" % detail)
        missed.append("live disk")
    else:
        print("  ok   caught: disk -- %s" % detail[:150])

    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- every check fails without its defence, and no "
          "failed control passes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
