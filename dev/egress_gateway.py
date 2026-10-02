#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The build worker's egress gateway as squid, one definition (t5-e5e3071-F6, part 4).

Q3's rule: deny all, allow only the configured repository hosts. T3 proved it for tinyproxy
(dev/egress-probe.py); T3(b) then moved the gateway to squid, because tinyproxy drops pooled
keep-alive and BuildKit's blob POST failed through it. The gate found squid's own deny
matrix had been exercised by two requests. This module is the squid configuration the
probes run -- the RUN-attack harness and dev/run-egress-probe.py alike -- so the rule that
is measured is the rule that is shipped as the reference for T7.

The rule, in the order squid evaluates it (first match wins):
  1. instance-metadata destinations are refused, whatever the NAME resolved from: all of
     link-local (169.254.0.0/16, fe80::/10 -- AWS, GCP, Azure, OCI, OpenStack and most
     others serve metadata at 169.254.169.254) plus the known metadata addresses outside
     it, METADATA_ADDRESSES below (AWS's IPv6 endpoint, Alibaba Cloud's). A repository
     never lives at one, and an allowlisted name the operator's DNS points there (or
     rebinding) must not become a path to instance credentials. This is a LIST, not a
     guarantee: a provider whose endpoint is not on it is not covered, which is why the
     list is named here rather than described as "the metadata endpoint". (Alibaba's
     address and AWS's IPv6 one also fall inside rule 5's ranges, so they are refused
     twice; link-local is this rule's alone.) An IP literal is refused
     by rules 5 and 7 (rule 6 matches with -n); this rule is for names.
  2. the gateway's own loopback (to_localhost) is refused: squid's cache manager and any
     sidecar listening there are not a build's business.
  3. CONNECT (how HTTPS crosses a proxy) only to port 443.
  4. the registry, on its port, and then each host the operator marked as a PRIVATE MIRROR,
     on the repository ports. Both are allowed to live at private addresses.
  5. every private or non-public destination, PRIVATE_DESTINATIONS (RFC 1918, carrier-grade
     NAT 100.64.0.0/10, this host, benchmarking, multicast and reserved space, IPv6 ULA,
     site-local and loopback) and the IPv6 prefixes that embed an IPv4 address
     (EMBEDDED_IPV4_PREFIXES: NAT64 and 6to4), is refused, whatever NAME it was reached
     through. This is what refuses DNS rebinding: a PUBLIC repository name
     (CRAN, PyPI) that resolves to an inside address -- through rebinding, a poisoned
     resolver or a misconfiguration -- is not a repository but a path into the operator's
     network. The plan names RFC 1918 and DNS rebinding outright; until this rule the
     gateway allowed any configured name to resolve privately.
  6. each configured PUBLIC repository host, by EXACT name (dstdomain without a leading
     dot: no subdomains, and not a regex, so `allowed-repo.evil` does not match
     `allowed-repo`; and with -n, so squid matches the URL's host AS WRITTEN and never
     looks up an IP literal's reverse DNS -- without -n an address whose PTR names an
     allowlisted host is admitted, and the address's owner sets its PTR: gate finding
     t5-f4f5f32-F1), and only on the repository ports (80 and 443 by default). A mirror's
     other ports -- an admin API, a database, a metrics endpoint -- are not a build's
     business (b3d129f-F1).
  7. everything else is refused.

A private mirror must therefore be DECLARED as one (T7's configuration: a repository entry
marked private). Q3 said a private mirror should work "without special-casing"; it still
needs nothing beyond its entry in the repository list, but that entry has to say private,
because the alternative -- any configured name may resolve privately -- is exactly the
rebinding hole the plan forbids. Decided 2026-10-01 by the user, on the coder's
recommendation. A private IP LITERAL is refused by rule 5 as well as rule 7.

Redirects are not followed by squid, a forward proxy: the client follows them, and each
hop is a new request through these same rules.

`weaken` exists for the self-tests only, which must see each check fail when its rule is
removed. The shipped configuration is weaken=None.
"""

import pathlib

PORT = 8888
# Instance-metadata addresses outside link-local, denied by address (b3d129f-F2).
METADATA_ADDRESSES = ("fd00:ec2::254/128",      # AWS, IPv6 IMDS
                      "100.100.100.200/32")     # Alibaba Cloud
REPO_PORTS = (80, 443)
# Private and otherwise non-public destinations. A PUBLIC repository name that resolves into
# one of these is refused (DNS rebinding, or a public name pointed inward); only a host the
# operator marked as a private mirror may live here.
# IPv6 prefixes that EMBED an IPv4 address, which a translator turns back into it: on a
# NAT64 host 64:ff9b::<10.x> reaches 10.x, and 64:ff9b::a9fe:a9fe reaches the metadata
# service. Refused whole -- a repository is not reached through a translator by name
# (d8aaa14-F1). Kept as their own tuple so a self-test can drop exactly these.
EMBEDDED_IPV4_PREFIXES = ("64:ff9b::/96",       # RFC 6052 well-known NAT64
                          "64:ff9b:1::/48",     # RFC 8215 local-use NAT64
                          "2002::/16")          # 6to4
PRIVATE_DESTINATIONS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
                        "100.64.0.0/10",                                     # CGNAT, overlays
                        "127.0.0.0/8", "0.0.0.0/8",                          # this host
                        "198.18.0.0/15",                                     # benchmarking
                        "224.0.0.0/4", "240.0.0.0/4",                        # multicast, reserved
                        "fc00::/7", "fec0::/10", "::1/128")                  # ULA, site-local, lo
WEAKENINGS = ("allow_all", "no_metadata_deny", "unanchored", "any_connect_port",
              "any_repo_port", "reverse_lookup", "no_private_deny", "no_embedded_ipv4_deny")


def squid_conf(registry, repos, weaken=None, repo_ports=REPO_PORTS, private_mirrors=()):
    """The squid.conf text. `repos` are the configured PUBLIC repository host names and
    `private_mirrors` the ones the operator marked as living on a private network; both are
    reachable on `repo_ports`."""
    if weaken not in (None,) + WEAKENINGS:
        raise ValueError("unknown weakening %r" % weaken)
    lines = ["http_port %d" % PORT,
             "acl metadata dst 169.254.0.0/16 fe80::/10 %s" % " ".join(METADATA_ADDRESSES),
             "acl repo_ports port %s" % " ".join(str(p) for p in repo_ports),
             "acl SSL_ports port 443",
             "acl CONNECT method CONNECT",
             # -n: match the URL's host as written, never its reverse DNS (gate finding
             # t5-f4f5f32-F1). Without it squid resolves the PTR of an IP-literal URL and
             # admits the address if the PTR names an allowlisted host -- and whoever owns
             # an address sets its PTR, so build code reached an attacker's server.
             "acl registry dstdomain %s%s" % (
                 "" if weaken == "reverse_lookup" else "-n ", registry),
             "acl registry_port port 5000",
             "acl private_dst dst %s" % " ".join(
                 PRIVATE_DESTINATIONS + (() if weaken == "no_embedded_ipv4_deny"
                                         else EMBEDDED_IPV4_PREFIXES))]
    if private_mirrors:
        lines.append("acl private_mirrors dstdomain %s%s" % (
            "" if weaken == "reverse_lookup" else "-n ", " ".join(private_mirrors)))
    if repos:
        if weaken == "unanchored":
            # A regex with no anchors: matches any host CONTAINING the name.
            lines.append("acl repos dstdom_regex -n %s" % " ".join(
                r.replace(".", r"\.") for r in repos))
        else:
            lines.append("acl repos dstdomain %s%s" % (
                "" if weaken == "reverse_lookup" else "-n ", " ".join(repos)))
    if weaken != "no_metadata_deny":
        lines.append("http_access deny metadata")
    lines.append("http_access deny to_localhost")
    if weaken != "any_connect_port":
        lines.append("http_access deny CONNECT !SSL_ports")
    if weaken == "allow_all":
        lines.append("http_access allow all")
    lines.append("http_access allow registry registry_port")
    if private_mirrors:
        lines.append("http_access allow private_mirrors repo_ports")
    if weaken != "no_private_deny":
        lines.append("http_access deny private_dst")
    if repos:
        lines.append("http_access allow repos" if weaken == "any_repo_port"
                     else "http_access allow repos repo_ports")
    lines += ["http_access deny all",
              "cache deny all",
              "access_log stdio:/dev/stdout",
              "cache_log stdio:/dev/stderr",
              "pid_filename none",
              "coredump_dir /tmp"]
    return "\n".join(lines) + "\n"


def write_conf(directory, registry, repos, weaken=None, private_mirrors=()):
    """Writes squid.conf under `directory`, world-readable (squid runs as its own user)."""
    path = pathlib.Path(directory) / "squid.conf"
    path.write_text(squid_conf(registry, repos, weaken, private_mirrors=private_mirrors))
    path.chmod(0o644)
    return str(path)


# The image: alpine's squid, the configuration mounted at run time so a self-test can
# restart the gateway weakened without rebuilding.
DOCKERFILE = ("FROM alpine:3.20\nRUN apk add --no-cache squid\nUSER squid\n"
              'CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]\n')
