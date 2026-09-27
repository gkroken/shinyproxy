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

docker = h.docker
results = []

ALLOWED, DENIED, SUFFIX, REBIND = ("allowed-repo", "denied-host", "allowed-repo.evil",
                                   "rebind-repo")
METADATA = "169.254.169.254"
# Allowlisted names the gateway's resolver points at each kind of metadata address: the
# link-local one most clouds use, and the two outside link-local (b3d129f-F2).
REBINDS = {REBIND: METADATA, "rebind-aws6": "fd00:ec2::254",
           "rebind-alibaba": "100.100.100.200"}
REPOS = [ALLOWED] + sorted(REBINDS)
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


def outer_ip(name):
    cname = "skald-egr-" + name.replace(".", "-")
    return docker(["inspect", "-f",
                   "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % h.OUTER,
                   cname]).stdout.strip()


# ------------------------------------------------------------------ the attempts (shell)

MATRIX = r"""
P=http://%(gate_ip)s:8888
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
    | nc -w 10 %(gate_ip)s 8888 > /tmp/resp 2>/dev/null
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
          sleep 3; } | nc -w 5 %(gate_ip)s 8888 2>/dev/null | head -1 | awk '{print $2}')
  echo "$1=${st:-none}"
}
# direct KEY HOST PORT: a socket opened by build code itself, not through the gateway.
direct() {
  if nc -z -w 5 "$2" "$3" 2>/dev/null; then echo "$1=CONNECTED"; else echo "$1=refused"; fi
}
get allowed http://%(allowed)s/
get unlisted http://%(denied)s/
get unlisted_ip http://%(denied_ip)s/
get private_ip http://10.255.255.1/
get metadata http://%(metadata)s/latest/meta-data/
get rebind http://%(rebind)s/
get rebind_aws6 http://rebind-aws6/
get rebind_alibaba http://rebind-alibaba/
get repo_badport http://%(allowed)s:6379/
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
if nslookup example.com >/dev/null 2>&1; then echo "dns=resolved"; else echo "dns=failed"; fi
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


def judge(report):
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
    row("allowlisted repository on another port refused", policy_denied(r, "repo_badport"),
        "repo_badport")
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
        "denied_ip": outer_ip(DENIED), "allowed_ip": outer_ip(ALLOWED)}
    report, blob = h.run_local_step(tmp, "egress-" + label, script)
    lines = [l.strip() for l in report.strip().splitlines() if l.strip()]
    if not lines:
        return None, blob
    return judge(lines), blob


def shipped_gateway(weaken=None):
    h.start_gateway(repos=REPOS, weaken=weaken, add_hosts=ADD_HOSTS)


def main(argv):
    print("== the egress deny matrix, from a RUN step, through squid ==")
    print()
    tmp = tempfile.mkdtemp(prefix="skald-egress-run-")
    try:
        h.setup(tmp)
        start_hosts(tmp)
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
WEAKENINGS = [
    ("the unlisted host allowlisted", dict(repos=REPOS + [DENIED]),
     ["unlisted host refused by squid", "redirect to an unlisted host refused",
      "CONNECT to an unlisted host refused"]),
    ("allow all before deny all", dict(weaken="allow_all"),
     ["unlisted host refused by squid", "unlisted host refused by IP",
      "private IP literal refused", "suffix of an allowed name refused"]),
    ("no metadata deny", dict(weaken="no_metadata_deny"),
     ["allowlisted name resolving to metadata refused",
      "allowlisted name resolving to AWS IPv6 metadata refused",
      "allowlisted name resolving to Alibaba metadata refused"]),
    ("repositories on any port", dict(weaken="any_repo_port"),
     ["allowlisted repository on another port refused"]),
    ("the allowlist unanchored", dict(weaken="unanchored"),
     ["suffix of an allowed name refused"]),
    ("CONNECT to any port", dict(weaken="any_connect_port"),
     ["CONNECT to a non-443 port refused"]),
    ("the allowlist emptied", dict(repos=[]),
     ["allowed repository fetched (control)"]),
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

    for label, kw, must_fail in WEAKENINGS:
        weaken = kw.get("weaken")
        repos = kw.get("repos", REPOS)
        h.start_gateway(repos=repos, weaken=weaken, add_hosts=ADD_HOSTS)
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
        else:
            print("  ok   %s -- red: %s" % (label, "; ".join(
                "%s (%s)" % (n, rows[n][1][:70]) for n in must_fail)))

    # The worker on the routable network: the bypass rows must go red.
    shipped_gateway()
    docker(["network", "connect", h.OUTER, h.WORKER])
    rows, blob = run_matrix(tmp, "routable")
    docker(["network", "disconnect", h.OUTER, h.WORKER])
    if rows is None or rows["no direct socket to the repository"][0]:
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
