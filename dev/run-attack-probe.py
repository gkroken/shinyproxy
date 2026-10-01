#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""What build code cannot do from a RUN step (t5-e5e3071-F6, part 2; decision 6).

Decision 6's isolation table, "repeated at T5", lists things a publisher's build code must
not be able to do. Each is a containment property, and this asserts it the only way that
means anything: the attempt is made from inside a real RUN step, under the worker the
shipping profile launches (dev/run_attack_harness), and it must be refused. Every check has
an allow control -- a legitimate actor doing the same thing successfully -- so a check
cannot pass because the attempt quietly did not happen.

The attempts here observe and report; the judging is in Python. None of this is an exploit
kit: it is the evidence that the boundary holds, and where it does not, the commit that adds
it also adds the fix and shows the attempt refused afterwards.

The table covered here (bounded resources -- memory, fork, CPU, disk, log flood -- are
part 3, and the egress deny matrix is part 4):
  1. reach the build daemon's control API
  2. write to the build registry (push or overwrite another build's image)
  3. see or signal the daemon, or any process outside the RUN
  4. leave a process behind that outlives the RUN
  5. read credentials or another build's data

Usage: python3 dev/run-attack-probe.py [--json] [--self-test]
"""

import json
import sys
import tempfile
import shutil

import run_attack_harness as h

# The runtime this probe measures, read statically by dev/schema-fixture-check.py: a
# runtime's proofs in spec/isolation-profile-v1.json may cite only probes that measure THAT
# runtime (gate finding t5-f4f5f32-F2).
MEASURES_RUNTIME = "runc-rootless"

docker = h.docker
results = []


def record(name, expectation, observed, contained, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "contained": contained, "note": note})
    print("  %-6s %-34s %s" % ("ok" if contained else "FAIL", name, observed))
    if note:
        print("         %s" % note)


# ------------------------------------------------------------------ the attempts (shell)
#
# Each is busybox shell, run inside a RUN step. It writes one or more "key=value" lines to
# stdout (the harness captures them as /report). GATE is the egress gateway's address, so an
# attempt that legitimately needs the proxy (the registry one) can reach it the same way a
# pull does. WORKER is the worker's own address on the internal network.

REACH_DAEMON = r"""
# Can build code reach buildkitd's control endpoint? The daemon listens on a unix socket in
# a volume the trusted client shares, not a TCP port (user decision 2026-09-26). A RUN
# shares the worker's network namespace, so it still tries the old TCP port on both the
# loopback and the worker's own address -- there must be nothing listening -- and it looks
# for the socket, which is not in its mounts. A connect or a present socket is an escape.
# The allow control, in the same RUN with the same tool: the gateway's port must answer,
# or a "refused" below proves only that nc could not connect to anything (7b1a2d1-F1).
if nc -w 3 %(gate_ip)s 8888 </dev/null >/dev/null 2>&1; then
  echo "control_gateway=CONNECTED"
else
  echo "control_gateway=refused"
fi
for addr in 127.0.0.1 %(worker)s; do
  if nc -w 3 "$addr" 1234 </dev/null >/dev/null 2>&1; then
    echo "daemon_tcp_$addr=CONNECTED"
  else
    echo "daemon_tcp_$addr=refused"
  fi
done
echo "socket_present=$([ -S /skald-sock/bk.sock ] && echo yes || echo no)"
# Abstract unix sockets are scoped to the network namespace, which the RUN shares with the
# worker, so they are the way past a filesystem boundary. There must be none; the RUN reads
# the list itself so an empty answer is distinguishable from an unreadable one.
if [ -r /proc/net/unix ]; then
  echo "abstract_sockets=$(awk 'NR>1 && $8 ~ /^@/' /proc/net/unix | wc -l)"
else
  echo "abstract_sockets=unreadable"
fi
"""

WRITE_REGISTRY = r"""
# Can build code write to the build registry? It reaches the registry only through the
# egress gateway (the one route off the worker's network), as a pull does, so the attempt
# uses that proxy. It POSTs to begin a blob upload for a repository it does not own. The
# registry requires a credential build code does not have, so the answer must be 401 (or
# 403); a 2xx/202 would mean build code can start writing and poison another build's image.
# The gateway is reached by IP (a RUN shares the worker's netns but does not resolve
# Docker aliases); the proxy resolves the registry name in the URL.
export http_proxy="http://%(gate_ip)s:8888"
wget -S -O /dev/null --post-data='x' \
  "http://%(registry)s:5000/v2/attacker-forged/blobs/uploads/" > /tmp/w 2>&1 || true
echo "registry_write_status=$(awk '/HTTP\//{print $2; exit}' /tmp/w)"
echo "registry_write_raw=$(tr -d '\r' < /tmp/w | grep -iE 'HTTP/|refused|resolve|denied|error' | head -1)"
# Reading other builds' images is refused too: the catalog and a known repository's tags.
wget -S -O /dev/null "http://%(registry)s:5000/v2/_catalog" > /tmp/r 2>&1 || true
echo "registry_catalog_status=$(awk '/HTTP\//{print $2; exit}' /tmp/r)"
wget -S -O /dev/null "http://%(registry)s:5000/v2/base/alpine/tags/list" > /tmp/r 2>&1 || true
echo "registry_tags_status=$(awk '/HTTP\//{print $2; exit}' /tmp/r)"
"""

SEE_PROCESSES = r"""
# Can build code see any process outside its own RUN? Under the process sandbox the RUN is
# in its own PID namespace, so ps shows only its own tree and buildkitd is not in it, and
# pid 1 in here is the RUN's own init, not the daemon. (Signalling pid 1 is NOT an escape:
# in an own PID namespace pid 1 is this shell's own init; the containment is the separate
# namespace, which "buildkitd not visible" and "few processes" show.)
echo "buildkitd_visible=$(ps -o args 2>/dev/null | grep -c '[b]uildkitd')"
echo "process_count=$(ps -o pid 2>/dev/null | grep -c '[0-9]')"
echo "pid1_comm=$(cat /proc/1/comm 2>/dev/null)"
"""

LEAVE_ORPHAN = r"""
# A process backgrounded in a RUN must not outlive the step. It writes a marker the harness
# looks for on the worker side afterwards; from in here we only start it.
( sleep 600 & echo "orphan_pid=$!" )
# The variant the gate named: detached into its own session, ignoring TERM and HUP, and
# double-forked so its parent is gone before the step ends.
setsid sh -c 'trap "" TERM HUP; ( sleep 777 & ) ; exit 0' </dev/null >/dev/null 2>&1 &
sleep 1
# The allow control: both were running when the step's script ended, so "gone afterwards"
# is the sandbox's doing and not a child that never started.
echo "orphans_started=$(ps -o args 2>/dev/null | grep -cE '^sleep (600|777)')"
"""

READ_SECRETS = r"""
# Is anything sensitive reachable? Build-time environment, the usual credential mount
# points, and another build's workspace. Each line reports what was found; the judge wants
# all of them empty.
echo "secret_env=$(env | grep -iE 'secret|token|password|aws_|_key=' | wc -l)"
found=""
for p in /run/secrets /var/run/secrets /root/.aws /root/.docker/config.json \
         /home/user/.aws /workspace /var/lib/skald; do
  [ -e "$p" ] && found="$found $p"
done
echo "cred_paths=${found:-none}"
# Allow controls, through the same two tests (7b1a2d1-F1): a file the RUN certainly has,
# and a secret-shaped variable set here, must both be found.
[ -e /probe.sh ] && echo "control_path=found" || echo "control_path=missing"
echo "control_env=$(SKALD_CONTROL_TOKEN=1 env | grep -iE 'secret|token|password|aws_|_key=' | wc -l)"
echo "docker_sock=$([ -S /var/run/docker.sock ] && echo present || echo absent)"
"""


# ------------------------------------------------------------------ judges (pure)

def judge_reach_daemon(report):
    reached = [line for line in report if line.startswith("daemon_tcp_")
               and line.endswith("=CONNECTED")]
    socket_here = _value(report, "socket_present") == "yes"
    abstract = _value(report, "abstract_sockets")
    # The same nc must reach the gateway, or "refused" means nothing (7b1a2d1-F1); an
    # absent or failed control is inconclusive, which is not containment.
    control = _value(report, "control_gateway") == "CONNECTED"
    ok = (control and not reached and not socket_here and abstract == "0"
          and bool(report))
    note = ""
    if not control:
        note = "  <- inconclusive: the in-RUN control could not reach the gateway either"
    elif reached:
        note = "  <- build code reached a daemon TCP port"
    elif socket_here:
        note = "  <- the daemon socket is in the RUN's mounts"
    elif abstract != "0":
        note = "  <- abstract unix sockets in the shared netns: %s" % (abstract or "none read")
    return ok, ("; ".join(report) if report else "no report") + note


def judge_write_registry(report):
    status = _value(report, "registry_write_status")
    reads = [_value(report, k) for k in ("registry_catalog_status", "registry_tags_status")]
    # Containment is a DEFINITE refusal by the registry: 401 (no credential) or 403. An
    # accepted write (2xx) is an escape; an empty/absent status is inconclusive -- the
    # attempt did not reach the registry -- and is not counted as containment, so the probe
    # cannot pass by the write silently going nowhere. Reads of other builds' images are
    # held to the same rule.
    refused = ("401", "403")
    contained = status in refused and all(r in refused for r in reads)
    detail = ("registry answered %s to a build-code write, %s to reads"
              % (status or "nothing", "/".join(r or "nothing" for r in reads)))
    if not contained:
        raw = _value(report, "registry_write_raw")
        if raw:
            detail += " (%s)" % raw
    return contained, detail


def judge_see_processes(report):
    visible = _value(report, "buildkitd_visible") not in ("0", "")
    count = _value(report, "process_count")
    pid1 = _value(report, "pid1_comm")
    # Its own PID namespace: buildkitd not visible, and a handful of processes (its own
    # tree), not the worker's dozens. pid1 is the RUN's own init, reported for the record.
    try:
        few = 0 < int(count) < 15
    except ValueError:
        few = False
    ok = not visible and few
    return ok, "buildkitd in ps: %s; process count: %s; pid1=%s" % (
        "yes" if visible else "no", count, pid1)


def judge_secrets(report):
    env = _value(report, "secret_env")
    paths = _value(report, "cred_paths")
    sock = _value(report, "docker_sock")
    # The tests must be able to find something (7b1a2d1-F1): a present file and a planted
    # secret-shaped variable, through the same two tests.
    controls = (_value(report, "control_path") == "found"
                and _value(report, "control_env") not in ("0", ""))
    ok = controls and env == "0" and paths == "none" and sock == "absent"
    return ok, "secret-shaped env: %s; cred paths: %s; docker.sock: %s%s" % (
        env, paths, sock, "" if controls else "  <- inconclusive: a control was not found")


def judge_orphans(report, survivors):
    started = _value(report, "orphans_started")
    # Both children must have been running inside the RUN (the control), and neither on the
    # worker afterwards.
    ok = started == "2" and not survivors
    return ok, "started in the RUN: %s; survivors: %s" % (
        started or "no report", "; ".join(survivors) if survivors else "none")


def _value(report, key):
    for line in report:
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return ""


# ------------------------------------------------------------------ the run

def attempt(tmp, name, script):
    report, blob = h.run_probe_step(tmp, name, script % {
        "worker": h.worker_ip_on_inner(), "gate": h.GATEWAY, "registry": h.REGISTRY,
        "gate_ip": h.gateway_ip_on_inner()})
    if not report.strip():
        return [], blob
    return [l.strip() for l in report.strip().splitlines() if l.strip()], blob


def orphan_survivors():
    """Processes on the worker that a RUN's backgrounded child left behind, if any."""
    out = docker(["exec", h.WORKER, "sh", "-c",
                  "ps -o pid,args 2>/dev/null | grep -E '[s]leep (600|777)' || true"])
    return [l for l in out.stdout.splitlines() if l.strip()]


def main(argv):
    print("== what build code cannot do from a RUN step ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-atk-")
    try:
        h.setup(tmp)
        if "--self-test" in argv:
            return self_test(tmp)

        report, blob = attempt(tmp, "reach-daemon", REACH_DAEMON)
        ok, detail = judge_reach_daemon(report)
        record("the daemon API is unreachable",
               "a RUN cannot connect to buildkitd on :1234",
               detail if report else "no report: %s" % blob.strip()[-120:], ok)

        report, _ = attempt(tmp, "write-registry", WRITE_REGISTRY)
        ok, detail = judge_write_registry(report)
        record("build code cannot write to the registry",
               "a RUN's push/upload is refused", detail, ok,
               "" if ok else "the registry accepts unauthenticated writes; only the trusted "
                             "client should be able to push")

        report, _ = attempt(tmp, "see-processes", SEE_PROCESSES)
        ok, detail = judge_see_processes(report)
        record("no process outside the RUN is visible or signallable",
               "the RUN is alone in its PID namespace", detail, ok)

        # The allow control for the registry: the trusted client (the harness) pushed each
        # attempt's own result image, so the registry does accept a write from the launcher
        # side. That the writes above are the ONLY thing refused is what makes the check real.
        pushed = [r for r in h.registry_catalog_via_host() if r.startswith("attempt/")]
        record("...and the trusted client still can (control)",
               "the launcher's own pushes reached the registry",
               "%d attempt image(s) in the catalog" % len(pushed), bool(pushed))

        report, _ = attempt(tmp, "leave-orphan", LEAVE_ORPHAN)
        ok, detail = judge_orphans(report, orphan_survivors())
        record("no process outlives the RUN",
               "a backgrounded child, and a detached TERM-ignoring one, are gone once the "
               "step ends", detail, ok)

        report, _ = attempt(tmp, "read-secrets", READ_SECRETS)
        ok, detail = judge_secrets(report)
        record("no credentials or other build's data are present",
               "no secret-shaped env, no credential mount, no other workspace, no socket",
               detail, ok)
    finally:
        h.teardown()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["contained"]]
    print()
    print("  %d check(s), %d not contained" % (len(results), len(bad)))
    print()
    print("RESULT:", "build code is contained on every attempt in the table"
          if not bad else "%d attempt(s) NOT contained" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


def self_test(tmp):
    """Each judge must call an uncontained observation uncontained, and the allow control
    must be able to fail. The judges are pure, so most of this is offline; the two live
    controls (the daemon is reachable by the trusted client, the registry accepts a trusted
    push) are what the main run's controls already assert, so they are not repeated here."""
    print("== self-test: each judge must catch an escape, and pass a contained result ==")
    missed = []

    def case(label, judged, want_contained):
        ok, detail = judged
        if ok != want_contained:
            print("  FAIL %s: judged contained=%s (%s)" % (label, ok, detail))
            missed.append(label)
        else:
            print("  ok   %s" % label)

    good = ["control_gateway=CONNECTED", "daemon_tcp_127.0.0.1=refused",
            "daemon_tcp_10.0.0.2=refused", "socket_present=no", "abstract_sockets=0"]

    def swap(lines, key, value):
        return [l for l in lines if not l.startswith(key + "=")] + ["%s=%s" % (key, value)]

    case("a reached daemon TCP port is not contained",
         judge_reach_daemon(swap(good, "daemon_tcp_127.0.0.1", "CONNECTED")), False)
    case("a socket in the RUN's mounts is not contained",
         judge_reach_daemon(swap(good, "socket_present", "yes")), False)
    case("an abstract unix socket in the shared netns is not contained",
         judge_reach_daemon(swap(good, "abstract_sockets", "1")), False)
    case("an unreadable socket list is not contained",
         judge_reach_daemon(swap(good, "abstract_sockets", "unreadable")), False)
    case("refused everywhere with a failed control is inconclusive, not contained",
         judge_reach_daemon(swap(good, "control_gateway", "refused")), False)
    case("refused with no control line at all is not contained",
         judge_reach_daemon([l for l in good if not l.startswith("control_")]), False)
    case("no port and no socket, control connected, is contained",
         judge_reach_daemon(good), True)
    reads = ["registry_catalog_status=401", "registry_tags_status=401"]
    case("a 202 registry write is not contained",
         judge_write_registry(["registry_write_status=202"] + reads), False)
    case("a 401 registry write is contained",
         judge_write_registry(["registry_write_status=401"] + reads), True)
    case("an inconclusive (empty) registry answer is not contained",
         judge_write_registry(["registry_write_status="] + reads), False)
    case("a 403 registry write is contained",
         judge_write_registry(["registry_write_status=403"] + reads), True)
    case("a readable catalog is not contained",
         judge_write_registry(["registry_write_status=401", "registry_catalog_status=200",
                               "registry_tags_status=401"]), False)
    case("an unanswered tags read is not contained",
         judge_write_registry(["registry_write_status=401", "registry_catalog_status=401"]),
         False)
    case("a surviving orphan is not contained",
         judge_orphans(["orphans_started=2"], ["123 sleep 777"]), False)
    case("orphans that never started are inconclusive, not contained",
         judge_orphans(["orphans_started=0"], []), False)
    case("both started and none survived is contained",
         judge_orphans(["orphans_started=2"], []), True)
    case("a visible daemon is not contained",
         judge_see_processes(["buildkitd_visible=1", "process_count=3",
                              "pid1_comm=sh"]), False)
    case("sharing the worker's crowded namespace is not contained",
         judge_see_processes(["buildkitd_visible=0", "process_count=40",
                              "pid1_comm=rootlesskit"]), False)
    case("alone in the namespace is contained",
         judge_see_processes(["buildkitd_visible=0", "process_count=3",
                              "pid1_comm=sh"]), True)
    ctl = ["control_path=found", "control_env=1"]
    case("a found secret env is not contained",
         judge_secrets(["secret_env=2", "cred_paths=none", "docker_sock=absent"] + ctl),
         False)
    case("a credential path is not contained",
         judge_secrets(["secret_env=0", "cred_paths= /root/.aws", "docker_sock=absent"]
                       + ctl), False)
    case("a docker socket is not contained",
         judge_secrets(["secret_env=0", "cred_paths=none", "docker_sock=present"] + ctl),
         False)
    case("a clean environment whose path control failed is inconclusive",
         judge_secrets(["secret_env=0", "cred_paths=none", "docker_sock=absent",
                        "control_path=missing", "control_env=1"]), False)
    case("a clean environment whose env control failed is inconclusive",
         judge_secrets(["secret_env=0", "cred_paths=none", "docker_sock=absent",
                        "control_path=found", "control_env=0"]), False)
    case("a clean environment with both controls found is contained",
         judge_secrets(["secret_env=0", "cred_paths=none", "docker_sock=absent"] + ctl),
         True)

    # One live case, so the judges are not only exercised on hand-written strings: the
    # process check against a real RUN must report the RUN alone in its namespace.
    report, blob = attempt(tmp, "selftest-processes", SEE_PROCESSES)
    if report:
        ok, detail = judge_see_processes(report)
        if ok:
            print("  ok   live: a real RUN is alone in its PID namespace (%s)" % detail)
        else:
            print("  FAIL live: a real RUN was judged uncontained (%s)" % detail)
            missed.append("live process check")
    else:
        print("  FAIL live process check produced no report: %s" % blob.strip()[-120:])
        missed.append("live process check")

    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- every judge catches an escape and passes a "
          "contained result")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
