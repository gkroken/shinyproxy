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
     list is named here rather than described as "the metadata endpoint". Whole ranges
     were rejected where a mirror can legitimately live (100.64.0.0/10 also carries
     carrier-grade NAT and overlay networks such as Tailscale). An IP literal is refused
     by rule 5 anyway; this rule is for names.
  2. the gateway's own loopback (to_localhost) is refused: squid's cache manager and any
     sidecar listening there are not a build's business.
  3. CONNECT (how HTTPS crosses a proxy) only to port 443.
  4. the registry, on its port; then each configured repository host, by EXACT name
     (dstdomain without a leading dot: no subdomains, and not a regex, so
     `allowed-repo.evil` does not match `allowed-repo`), and only on the repository ports
     (80 and 443 by default). A mirror's other ports -- an admin API, a database, a
     metrics endpoint -- are not a build's business (b3d129f-F1).
  5. everything else is refused.

Private (RFC 1918) destinations are NOT refused by rule: an operator's own mirror (Nexus,
Artifactory, Posit Package Manager) typically lives on one, and Q3 exists to let it work.
A private IP LITERAL is refused by rule 5 like any unlisted destination; a configured name
that resolves privately is allowed, because configuring it is the operator's statement that
it is a repository.

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
WEAKENINGS = ("allow_all", "no_metadata_deny", "unanchored", "any_connect_port",
              "any_repo_port")


def squid_conf(registry, repos, weaken=None, repo_ports=REPO_PORTS):
    """The squid.conf text. `repos` are the configured repository host names, reachable
    on `repo_ports`."""
    if weaken not in (None,) + WEAKENINGS:
        raise ValueError("unknown weakening %r" % weaken)
    lines = ["http_port %d" % PORT,
             "acl metadata dst 169.254.0.0/16 fe80::/10 %s" % " ".join(METADATA_ADDRESSES),
             "acl repo_ports port %s" % " ".join(str(p) for p in repo_ports),
             "acl SSL_ports port 443",
             "acl CONNECT method CONNECT",
             "acl registry dstdomain %s" % registry,
             "acl registry_port port 5000"]
    if repos:
        if weaken == "unanchored":
            # A regex with no anchors: matches any host CONTAINING the name.
            lines.append("acl repos dstdom_regex %s" % " ".join(
                r.replace(".", r"\.") for r in repos))
        else:
            lines.append("acl repos dstdomain %s" % " ".join(repos))
    if weaken != "no_metadata_deny":
        lines.append("http_access deny metadata")
    lines.append("http_access deny to_localhost")
    if weaken != "any_connect_port":
        lines.append("http_access deny CONNECT !SSL_ports")
    if weaken == "allow_all":
        lines.append("http_access allow all")
    lines.append("http_access allow registry registry_port")
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


def write_conf(directory, registry, repos, weaken=None):
    """Writes squid.conf under `directory`, world-readable (squid runs as its own user)."""
    path = pathlib.Path(directory) / "squid.conf"
    path.write_text(squid_conf(registry, repos, weaken))
    path.chmod(0o644)
    return str(path)


# The image: alpine's squid, the configuration mounted at run time so a self-test can
# restart the gateway weakened without rebuilding.
DOCKERFILE = ("FROM alpine:3.20\nRUN apk add --no-cache squid\nUSER squid\n"
              'CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]\n')
