#!/usr/bin/env python3
"""The build worker's egress gateway: deny all, allow the configured repositories (T3).

Q3 settled the rule and the reason: "**deny all except the configured repository hosts**,
which is stricter to state and easier to implement than a hard-coded allowlist, and it is
what lets a private mirror work without special-casing". Package sources are configurable
-- CRAN and PyPI by default, or an operator's own Nexus, Artifactory or Posit Package
Manager -- so the gateway allowlists a configured set rather than a fixed one.

`--network none`, which dev/validate-sandbox.sh measures, is the floor: it proves a worker
with no network has no egress, which is true and not useful, because a build has to fetch
its dependencies. This measures the thing a build actually runs with.

**The shape.** Two Docker networks. The worker sits on an `--internal` one, which has no
route off the host at all, together with the gateway's inner interface. The gateway also
has an interface on an ordinary bridge network, and that is the only path out. The worker
is given HTTP_PROXY and HTTPS_PROXY; the gateway is tinyproxy with FilterDefaultDeny, so
a host absent from the allowlist is refused rather than forwarded.

Two properties, and the second is the one people forget:

  1. the gateway refuses a host that is not allowlisted;
  2. the worker cannot go around the gateway. An allowlist on a proxy means nothing if the
     worker can open a socket itself, so the internal network carries no default route and
     the probe tries direct connections as well as proxied ones.

**Deterministic, and deliberately offline.** The "allowed" and "denied" hosts are local
containers on the gateway's outer network, not real PyPI. Reaching real PyPI would test
the internet as much as the rule, and would make a security probe fail on a bad day. What
is being measured is whether the allowlist binds, which two local servers answer exactly.

**And the checks must be able to fail.** Five denials that all pass is the same output a
probe that tests nothing produces. `--self-test` weakens the gateway one way at a time --
allowlist the denied host, turn default-deny off, allowlist it by IP, put the worker on the
routable network, empty the allowlist entirely -- and requires the matching check to notice.

Usage: python3 dev/egress-probe.py [--json] [--self-test]
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

INNER_NET = "skald-egress-inner"
OUTER_NET = "skald-egress-outer"
GATEWAY = "skald-egress-gateway"
ALLOWED = "allowed-repo"
DENIED = "denied-host"
# A name an attacker owns outright that EXTENDS an allowlisted one. This is the classic
# bypass of a host allowlist: tinyproxy matches filter entries as regexes against the
# destination host, so an unanchored `pypi.org` also matches `pypi.org.attacker.net`.
# Q3's rule is "deny all except the configured repository hosts", and this is the name
# that defeats it the moment the anchors are dropped.
SUFFIX_ATTACK = "allowed-repo.evil"
GATEWAY_IMAGE = "skald-egress-gateway:local"
CLIENT_IMAGE = os.environ.get("EGRESS_CLIENT_IMAGE", "alpine:3.20")
PORT = 8888

results = []


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "ok": ok, "note": note})
    print("  %-7s %-34s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("          %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def build_gateway(directory, allowlist, default_deny=True, anchored=True):
    """tinyproxy with a default-deny filter: the allowlist IS the configuration.

    Anchored, and that is load-bearing rather than tidy: an unanchored entry matches any
    host CONTAINING it, so `allowed-repo` would also admit `allowed-repo.evil`.
    """
    d = pathlib.Path(directory)
    pattern = "^%s$\n" if anchored else "%s\n"
    (d / "filter").write_text("".join(pattern % h for h in allowlist))
    (d / "tinyproxy.conf").write_text(
        "User nobody\nGroup nobody\n"
        "Port %d\nListen 0.0.0.0\nTimeout 60\n" % PORT +
        "Allow 0.0.0.0/0\n" +
        # The whole rule in two lines: everything is denied unless the filter lists it.
        ('FilterDefaultDeny %s\nFilter "/etc/tinyproxy/filter"\nFilterURLs Off\n'
         % ("Yes" if default_deny else "No")) +
        # CONNECT is how HTTPS goes through a proxy, and it is filtered too.
        "ConnectPort 443\nConnectPort 80\n"
        "LogLevel Info\n")
    (d / "Dockerfile").write_text(
        "FROM alpine:3.20\n"
        "RUN apk add --no-cache tinyproxy\n"
        "COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf\n"
        "COPY filter /etc/tinyproxy/filter\n"
        'CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]\n')
    built = docker(["build", "-q", "-t", GATEWAY_IMAGE, str(d)], timeout=900)
    if built.returncode != 0:
        raise SystemExit("could not build the gateway image:\n"
                         + built.stdout + built.stderr)


def cleanup():
    for name in (GATEWAY, ALLOWED, DENIED, SUFFIX_ATTACK):
        docker(["rm", "-f", name])
    # Anything else still attached, which is not hypothetical: a `docker run --rm` whose
    # CLIENT is killed by a timeout leaves the container running, and it then holds the
    # network open so the removal below fails and the next run cannot create it. The first
    # run of this probe wedged exactly that way.
    for net in (INNER_NET, OUTER_NET):
        out = docker(["network", "inspect", net, "-f",
                      "{{range .Containers}}{{.Name}} {{end}}"]).stdout.split()
        for name in out:
            docker(["rm", "-f", name])
        docker(["network", "rm", net])


def from_worker(script, network=None):
    """Run a command as the worker: on the internal network, proxy variables set."""
    proxy = "http://%s:%d" % (GATEWAY, PORT)
    return docker(["run", "--rm", "--network", network or INNER_NET,
                   "-e", "http_proxy=" + proxy, "-e", "https_proxy=" + proxy,
                   "-e", "HTTP_PROXY=" + proxy, "-e", "HTTPS_PROXY=" + proxy,
                   CLIENT_IMAGE, "sh", "-c", script], timeout=180)


def bring_up(tmp, allowlist, default_deny=True, anchored=True):
    """A gateway with the given configuration, and the servers behind it."""
    cleanup()
    build_gateway(tmp, allowlist, default_deny, anchored)
    docker(["network", "create", "--internal", INNER_NET])
    docker(["network", "create", OUTER_NET])
    for name in (ALLOWED, DENIED, SUFFIX_ATTACK):
        docker(["run", "-d", "--name", name, "--network", OUTER_NET,
                "--network-alias", name, "alpine:3.20", "sh", "-c",
                "while true; do printf 'HTTP/1.1 200 OK\\r\\n"
                "Content-Length: 3\\r\\n\\r\\nhi\\n' | nc -l -p 80; done"])
    docker(["run", "-d", "--name", GATEWAY, "--network", INNER_NET,
            "--network-alias", GATEWAY, GATEWAY_IMAGE])
    docker(["network", "connect", OUTER_NET, GATEWAY])
    ready = docker(["run", "--rm", "--network", INNER_NET, CLIENT_IMAGE, "sh", "-c",
                    "for i in $(seq 1 30); do nc -z %s %d && echo READY && break; "
                    "sleep 1; done" % (GATEWAY, PORT)], timeout=120)
    if "READY" not in ready.stdout:
        raise SystemExit("the gateway never came up; nothing below would mean anything")


def reaches(host, network=None):
    """Did the worker fetch from `host` through the proxy?"""
    r = from_worker("wget -q -T 10 -O - http://%s/ 2>&1; echo rc=$?" % host, network)
    return "rc=0" in r.stdout


def connects(host, network=None):
    """Did the worker open a socket to `host` directly, bypassing the proxy?"""
    r = from_worker("nc -z -w 5 %s 80 && echo CONNECTED || echo refused" % host, network)
    return "CONNECTED" in r.stdout


def denied_address():
    return docker(["inspect", "-f",
                   "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % OUTER_NET,
                   DENIED]).stdout.strip()


def self_test(tmp):
    """Weaken the gateway one way at a time; the matching check must notice."""
    print("== self-test: each check must fail when its rule is removed ==")
    missed = []

    def case(label, expect_true, description):
        ok = expect_true()
        print("  %s %s" % ("ok   detected:" if ok else "FAIL not detected:", label))
        if not ok:
            print("       expected: %s" % description)
            missed.append(label)

    bring_up(tmp, [ALLOWED, DENIED])
    case("the denied host is added to the allowlist",
         lambda: reaches(DENIED),
         "the unlisted-host check must be the allowlist, not something else")

    bring_up(tmp, [ALLOWED], default_deny=False)
    case("default-deny is turned off",
         lambda: reaches(DENIED),
         "with FilterDefaultDeny No an unlisted host must get through")

    bring_up(tmp, [ALLOWED])
    addr = denied_address()
    bring_up(tmp, [ALLOWED, addr.replace(".", r"\.")])
    case("the denied host is allowlisted by IP",
         lambda: reaches(denied_address()),
         "the by-IP check must follow the allowlist too")

    bring_up(tmp, [ALLOWED])
    case("the worker is put on the routable network",
         lambda: connects(ALLOWED, OUTER_NET),
         "the bypass checks must be the internal network, not the absence of a route")

    # The reviewer's own weakening: anchors dropped. It must fail the suffix check and
    # nothing else, which is what proves that check sees its own hole rather than
    # inheriting a pass from one of the others.
    bring_up(tmp, [ALLOWED], anchored=False)
    case("the allowlist is unanchored",
         lambda: reaches(SUFFIX_ATTACK),
         "an unanchored entry must admit a host that extends an allowed name")
    case("  ... and only that check notices",
         lambda: reaches(ALLOWED) and not reaches(DENIED),
         "the allowed host still works and the unrelated host is still refused, so the "
         "suffix check is the one that moved")

    bring_up(tmp, [])
    case("the allowlist is emptied",
         lambda: not reaches(ALLOWED),
         "the positive control must fail when nothing is allowed; otherwise it is not a "
         "control")

    cleanup()
    print()
    if missed:
        print("RESULT: self-test FAILED, %d of 7 weakening(s) undetected" % len(missed))
        return 1
    print("RESULT: self-test passed -- every check fails when its rule is removed")
    return 0


def main(argv):
    print("== the build worker's egress gateway ==")
    print("   deny all; allow only the configured repository hosts (Q3)")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-egress-")
    try:
        if "--self-test" in argv:
            return self_test(tmp)
        bring_up(tmp, [ALLOWED])

        # 1. POSITIVE CONTROL first. Everything else is a denial, and denials prove
        #    nothing if the allowed path does not work -- a gateway that refuses
        #    everything would pass every other check here.
        allowed = from_worker("wget -q -T 10 -O - http://%s/ 2>&1 | head -1" % ALLOWED)
        got = allowed.stdout.strip()
        record("allowed repository reachable", "the configured host is fetchable",
               "fetched %r" % got if got else "NOTHING: %s"
               % (allowed.stdout + allowed.stderr).strip()[-120:], bool(got),
               "" if got else "the allowlist lets nothing through, so every denial below "
                              "is meaningless")

        # 2. A host that is not on the allowlist.
        denied = from_worker("wget -q -T 10 -O - http://%s/ 2>&1; echo rc=$?" % DENIED)
        blocked = "rc=0" not in denied.stdout
        record("unlisted host refused", "the gateway denies what is not configured",
               "refused" if blocked else "REACHED IT: %s" % denied.stdout.strip()[-120:],
               blocked)

        # 3. Around the gateway, to the allowed host directly. An allowlist on a proxy is
        #    worth nothing if the worker can open its own socket.
        direct = from_worker("nc -z -w 5 %s 80 && echo CONNECTED || echo refused" % ALLOWED)
        no_direct = "CONNECTED" not in direct.stdout
        record("no direct route to the repo", "the worker cannot bypass the gateway",
               "refused" if no_direct else "CONNECTED DIRECTLY, bypassing the allowlist",
               no_direct)

        # 4. Around the gateway, to the internet.
        out = from_worker("nc -z -w 5 1.1.1.1 53 && echo CONNECTED || echo refused")
        no_internet = "CONNECTED" not in out.stdout
        record("no direct route off-host", "the internal network has no default route",
               "refused" if no_internet else "CONNECTED to 1.1.1.1", no_internet)

        # 5. A host the attacker owns that EXTENDS an allowlisted name. If the filter is
        #    unanchored this is admitted, and it is the bypass that matters in production:
        #    an attacker who registers pypi.org.example.net gets through a filter written
        #    without anchors.
        suffix = from_worker("wget -q -T 10 -O - http://%s/ 2>&1; echo rc=$?"
                             % SUFFIX_ATTACK)
        suffix_blocked = "rc=0" not in suffix.stdout
        record("suffix of an allowed name refused",
               "the allowlist is anchored, so extending a name does not admit it",
               "refused" if suffix_blocked
               else "REACHED %s, so the allowlist is not anchored" % SUFFIX_ATTACK,
               suffix_blocked)

        # 6. An IP literal through the gateway. Allowlisting by NAME is worthless if a
        #    numeric destination skips the filter.
        addr = docker(["inspect", "-f",
                       "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % OUTER_NET,
                       DENIED]).stdout.strip()
        if addr:
            by_ip = from_worker("wget -q -T 10 -O - http://%s/ 2>&1; echo rc=$?" % addr)
            ip_blocked = "rc=0" not in by_ip.stdout
            record("unlisted host refused by IP", "a numeric destination is filtered too",
                   "refused" if ip_blocked else "REACHED %s by address" % addr, ip_blocked)
        else:
            record("unlisted host refused by IP", "a numeric destination is filtered too",
                   "could not resolve the denied host's address", False,
                   "the probe could not be run, which is not the same as passing")
    finally:
        cleanup()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["ok"]]
    print()
    print("  %d check(s), %d failed" % (len(results), len(bad)))
    print()
    print("RESULT:", "egress is denied by default and allowed only where configured"
          if not bad else "%d egress check(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
