#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The build worker's two runtime artifacts, shipped as files and checked against the
definitions the T3/T5 probes measured (WORKPLAN-BUNDLES.md T7, part 3).

  spec/build-worker-seccomp-v1.json   the worker's seccomp profile: Docker's default at the
                                      pinned commit plus the measured additions
                                      (buildkit_worker_profile.write)
  images/buildkit-worker/Dockerfile   the derived worker image (shipping_worker.
                                      worker_dockerfile), below a comment header
  images/egress-gateway/Dockerfile    the egress gateway's image (egress_gateway.DOCKERFILE),
                                      below a comment header
  dev/fixtures/worker/squid-confs.json
                                      squid.conf as egress_gateway.squid_conf (the measured
                                      rule) writes it for three configurations; the Java
                                      GatewayConfig is held to these byte for byte
  dev/fixtures/worker/cli-hostconfig.json
                                      what the docker CLI makes of the profile's launch
                                      arguments at production values: the HostConfig and
                                      environment of a container CREATED (never started) with
                                      them. The Java launcher talks to the Docker API, not the
                                      CLI, and the probes measured the CLI's launch; the
                                      Java side is held to this record (WorkerProfileTest),
                                      so it cannot drift from what was measured.

The probes generate both at run time. buildkit_worker_profile.py's docstring says so: "T7
owns what a deployment actually ships". The server cannot fetch from GitHub at launch, and
it should not run something nobody reviewed, so the deployment gets reviewed files. This
check keeps the shipped files from drifting from what the probes measure: a profile edited
by hand, or an addition made to the generator and not shipped, fails here. The profile is
compared as JSON (the shipped one is indented for review); the Dockerfile as text.

Usage: python3 dev/worker-artifacts.py [--write | --self-test]
  (no flag)    check both; exit 1 on any difference
  --write      regenerate both (then review the diff)
  --self-test  each check must fail on a file that differs in one measured respect
"""

import hashlib
import json
import pathlib
import sys
import tempfile
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import buildkit_worker_profile as bwp  # noqa: E402
import egress_gateway  # noqa: E402
import shipping_worker  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
SECCOMP = REPO / "spec/build-worker-seccomp-v1.json"
DOCKERFILE = REPO / "images/buildkit-worker/Dockerfile"
CLI_HOSTCONFIG = REPO / "dev/fixtures/worker/cli-hostconfig.json"
GATEWAY_DOCKERFILE = REPO / "images/egress-gateway/Dockerfile"
SQUID_CONFS = REPO / "dev/fixtures/worker/squid-confs.json"
GATEWAY_HEADER = """\
# Skald build-worker egress gateway: squid with the measured deny-by-default rule
# (WORKPLAN-BUNDLES.md "Build sandbox and dependency network"; T5 gate F6 part 4). GENERATED
# by dev/worker-artifacts.py --write from dev/egress_gateway.py; checked by the same script.
# The configuration is not baked in: the launcher writes squid.conf per attempt
# (publisher.worker.GatewayConfig, held to egress_gateway.squid_conf).
"""
# The configurations the Java port is held to: the registry alone; public repositories; and
# a declared private mirror alongside them (forge in the dev stack).
SQUID_CASES = [
    {"registry": "registry", "repos": [], "private_mirrors": []},
    {"registry": "skald-registry", "repos": ["cloud.r-project.org", "pypi.org",
                                             "files.pythonhosted.org"], "private_mirrors": []},
    {"registry": "registry", "repos": ["pypi.org"], "private_mirrors": ["forge"]},
    {"registry": "registry", "repos": ["pypi.org"], "private_mirrors": [],
     "dns_nameservers": ["10.250.250.53", "fd00::53"]},
]
# The production values the record is made at: WORKPLAN-BUNDLES.md's initial ceilings
# (2 CPUs, 4 GiB with no extra swap, 512 PIDs), the probes' scratch tmpfs, and BuildKit's own
# step-log defaults, pinned. WorkerSettings' defaults are held to these by WorkerProfileTest.
PRODUCTION_VALUES = {"cpu_quota": "2", "memory_limit": "4g", "pid_limit": "512",
                     "tmpfs_size": "256m", "step_log_max_bytes": "2097152",
                     "step_log_max_bytes_per_second": "204800"}
HOSTCONFIG_FIELDS = ["NanoCpus", "Memory", "MemorySwap", "PidsLimit", "ReadonlyRootfs", "Tmpfs",
                     "SecurityOpt", "NetworkMode", "Binds", "Privileged", "CapAdd"]
HEADER = """\
# Skald build worker: rootless BuildKit, derived from the pinned upstream (WORKPLAN-BUNDLES.md
# "Build sandbox and dependency network"; T3/T5 measured it, T7 ships it). GENERATED by
# dev/worker-artifacts.py --write from dev/shipping_worker.py; checked by the same script.
# Built by the operator when maintaining the platform, never by an upload.
#
# The identity is dedicated (uid 2401, subordinate ids 3000000+): unassigned on the host,
# so an escape does not land on a real account. The two setuid/setgid helpers the upstream
# carries beyond the uid-map tools are cleared, because no-new-privileges is waived for
# runc-rootless (user sign-off 2026-09-26; spec runtimes.runc-rootless.waived).
"""


def generated_seccomp():
    with tempfile.TemporaryDirectory() as d:
        base = bwp.fetch_default(d)
        return json.loads(pathlib.Path(bwp.write(d, base)).read_text())


def generated_dockerfile():
    return HEADER + shipping_worker.worker_dockerfile()


def generated_gateway_dockerfile():
    return GATEWAY_HEADER + egress_gateway.DOCKERFILE


def generated_squid_confs():
    return {"note": "Generated by dev/worker-artifacts.py --write from egress_gateway.squid_conf.",
            "cases": [dict(case, dns_nameservers=case.get("dns_nameservers", []),
                           conf=egress_gateway.squid_conf(
                               case["registry"], case["repos"], private_mirrors=case["private_mirrors"],
                               dns_nameservers=case.get("dns_nameservers", ())))
                      for case in SQUID_CASES]}


def cli_hostconfig():
    """Create (never start) a container with the docker CLI and the profile's arguments at
    PRODUCTION_VALUES, read back what the daemon recorded, and remove everything. The
    per-launch names are replaced by their placeholders, and the seccomp option, which the
    CLI sends as the profile's compacted JSON, is recorded by its SHA-256."""
    tag = uuid.uuid4().hex[:8]
    network, volume, name = "skald-wa-net-" + tag, "skald-wa-vol-" + tag, "skald-wa-" + tag
    args = shipping_worker.profile_arguments(dict(PRODUCTION_VALUES, egress_network=network,
                                                  quota_volume=volume,
                                                  seccomp_profile=str(SECCOMP)))
    shipping_worker.docker(["network", "create", "--internal", network])
    try:
        made = shipping_worker.docker(["create", "--name", name] + args
                                      + [shipping_worker.UPSTREAM_IMAGE], timeout=300)
        if made.returncode != 0:
            raise SystemExit("docker create failed: " + made.stderr[-300:])
        info = json.loads(shipping_worker.docker(["inspect", name]).stdout)[0]
    finally:
        shipping_worker.docker(["rm", "-f", "-v", name])
        shipping_worker.docker(["volume", "rm", volume])
        shipping_worker.docker(["network", "rm", network])
    hc = {k: info["HostConfig"].get(k) for k in HOSTCONFIG_FIELDS}
    hc["NetworkMode"] = hc["NetworkMode"].replace(network, "<egress_network>")
    hc["Binds"] = [b.replace(volume, "<quota_volume>") for b in hc["Binds"] or []]
    opts = []
    for opt in hc["SecurityOpt"] or []:
        if opt.startswith("seccomp="):
            opts.append("seccomp=sha256:" + hashlib.sha256(opt[len("seccomp="):].encode())
                        .hexdigest())
        else:
            opts.append(opt)
    hc["SecurityOpt"] = opts
    image_env = set(json.loads(shipping_worker.docker(
        ["image", "inspect", shipping_worker.UPSTREAM_IMAGE]).stdout)[0]["Config"]["Env"] or [])
    # Sorted: the CLI's order varies from run to run (measured: SIZE,SPEED in some creates
    # and SPEED,SIZE in others), and an environment is a set.
    env = sorted(e for e in info["Config"]["Env"] if e not in image_env)
    return {"note": "Generated by dev/worker-artifacts.py --write; see its docstring.",
            "runtime": shipping_worker.RUNTIME, "values": PRODUCTION_VALUES,
            "host_config": hc, "env": env}


def judge_seccomp(shipped_text, generated):
    try:
        shipped = json.loads(shipped_text)
    except ValueError as e:
        return False, "not JSON: %s" % e
    top = sorted(k for k in set(shipped) | set(generated)
                 if k != "syscalls" and shipped.get(k) != generated.get(k))
    if top:
        # d5d3237 review N1: say which field differs, not "0 rule(s)".
        return False, "differs from the generator in %s" % ", ".join(top)
    if shipped != generated:
        extra = [s for s in shipped.get("syscalls", []) if s not in generated["syscalls"]]
        missing = [s for s in generated["syscalls"] if s not in shipped.get("syscalls", [])]
        return False, "differs from the generator: %d rule(s) only shipped, %d only generated" \
            % (len(extra), len(missing))
    return True, "equal to the generator's (%d rules)" % len(generated["syscalls"])


def judge_record(shipped_text, generated):
    shipped = json.loads(shipped_text)
    if shipped != generated:
        diff = sorted(k for k in generated["host_config"]
                      if shipped.get("host_config", {}).get(k) != generated["host_config"][k])
        return False, "differs from a fresh docker create: %s" % (
            ", ".join(diff) or "values/env/runtime")
    return True, "equal to a fresh docker create"


def judge_squid(shipped_text, generated):
    shipped = json.loads(shipped_text)
    if shipped != generated:
        return False, "differs from egress_gateway.squid_conf"
    return True, "equal to egress_gateway.squid_conf (%d cases)" % len(generated["cases"])


def judge_dockerfile(shipped_text, generated):
    if shipped_text != generated:
        return False, "differs from the generator's Dockerfile text"
    return True, "equal to the generator's"


def main(argv):
    seccomp, dockerfile = generated_seccomp(), generated_dockerfile()
    if "--write" in argv:
        SECCOMP.write_text(json.dumps(seccomp, indent=2) + "\n")
        DOCKERFILE.parent.mkdir(parents=True, exist_ok=True)
        DOCKERFILE.write_text(dockerfile)
        CLI_HOSTCONFIG.parent.mkdir(parents=True, exist_ok=True)
        CLI_HOSTCONFIG.write_text(json.dumps(cli_hostconfig(), indent=2) + "\n")
        GATEWAY_DOCKERFILE.parent.mkdir(parents=True, exist_ok=True)
        GATEWAY_DOCKERFILE.write_text(generated_gateway_dockerfile())
        SQUID_CONFS.write_text(json.dumps(generated_squid_confs(), indent=2) + "\n")
        print("wrote " + ", ".join(str(p.relative_to(REPO)) for p in (
            SECCOMP, DOCKERFILE, CLI_HOSTCONFIG, GATEWAY_DOCKERFILE, SQUID_CONFS)))
        return 0
    if "--self-test" in argv:
        return self_test(seccomp, dockerfile)
    bad = 0
    for label, (ok, detail) in (
            ("seccomp", judge_seccomp(SECCOMP.read_text(), seccomp)),
            ("dockerfile", judge_dockerfile(DOCKERFILE.read_text(), dockerfile)),
            ("cli record", judge_record(CLI_HOSTCONFIG.read_text(), cli_hostconfig())),
            ("gateway", judge_dockerfile(GATEWAY_DOCKERFILE.read_text(),
                                         generated_gateway_dockerfile())),
            ("squid confs", judge_squid(SQUID_CONFS.read_text(), generated_squid_confs()))):
        print("  %-6s %-12s %s" % ("ok" if ok else "FAIL", label, detail))
        bad += not ok
    print("RESULT:", "the shipped worker artifacts are the measured ones" if not bad
          else "%d artifact(s) drifted" % bad)
    return 1 if bad else 0


def self_test(seccomp, dockerfile):
    missed = []

    def expect(label, judged, want):
        ok, detail = judged
        print("  %s %s (%s)" % ("ok  " if ok == want else "FAIL", label, detail[:80]))
        if ok != want:
            missed.append(label)

    shipped = SECCOMP.read_text()
    doc = json.loads(shipped)
    expect("the shipped profile passes", judge_seccomp(shipped, seccomp), True)
    no_pivot = json.loads(shipped)
    for rule in no_pivot["syscalls"]:
        if rule["names"] == bwp.ALLOWED:
            rule["names"] = [n for n in rule["names"] if n != "pivot_root"]
    expect("a profile without pivot_root is caught", judge_seccomp(json.dumps(no_pivot), seccomp),
           False)
    widened = json.loads(shipped)
    widened["syscalls"].append({"names": ["bpf"], "action": "SCMP_ACT_ALLOW"})
    expect("a profile allowing one more syscall is caught",
           judge_seccomp(json.dumps(widened), seccomp), False)
    keyctl = json.loads(shipped)
    keyctl["syscalls"] = [r for r in keyctl["syscalls"] if r["names"] != ["keyctl"]]
    expect("a profile without the keyctl ENOSYS rule is caught",
           judge_seccomp(json.dumps(keyctl), seccomp), False)
    default_action = dict(doc, defaultAction="SCMP_ACT_ALLOW")
    expect("a default-allow profile is caught",
           judge_seccomp(json.dumps(default_action), seccomp), False)
    text = DOCKERFILE.read_text()
    expect("the shipped Dockerfile passes", judge_dockerfile(text, dockerfile), True)
    expect("a Dockerfile keeping the setuid helpers is caught", judge_dockerfile(
        text.replace("RUN chmod u-s,g-s /usr/bin/fusermount3 /usr/sbin/unix_chkpwd\n", ""),
        dockerfile), False)
    expect("a Dockerfile running the worker as root is caught",
           judge_dockerfile(text.replace("USER 2401:2401", "USER root"), dockerfile), False)
    squid = SQUID_CONFS.read_text()
    expect("the shipped squid confs pass", judge_squid(squid, generated_squid_confs()), True)
    expect("squid confs without the metadata deny are caught", judge_squid(
        squid.replace("http_access deny metadata\\n", ""), generated_squid_confs()), False)
    gw = GATEWAY_DOCKERFILE.read_text()
    expect("a gateway on an unpinned alpine is caught", judge_dockerfile(
        gw.replace(egress_gateway.GATEWAY_BASE, "alpine:3.20"), generated_gateway_dockerfile()),
        False)
    print("RESULT:", "self-test passed" if not missed else "self-test FAILED: " + ", ".join(missed))
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
