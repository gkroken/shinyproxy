#!/usr/bin/env bash
# The egress deny matrix from a RUN step, through the squid gateway (WORKPLAN-BUNDLES.md
# T5, gate finding t5-e5e3071-F6 part 4; Q3's rule: deny all, allow only the configured
# repository hosts).
#
# Under the worker the shipping profile launches, a real RUN tries every row -- unlisted
# hosts by name and IP, private and metadata addresses, a name resolving to metadata, a
# suffix of an allowed name, redirects out of an allowed host, CONNECT, direct sockets
# around the gateway, DNS, and the registry -- and each refusal must be squid's own policy
# refusal, beside an allow control. See dev/run-egress-probe.py; the squid rule is
# dev/egress_gateway.py. dev/validate-egress.sh is T3's tinyproxy predecessor.
#
# Builds the worker image, two networks, a registry, the gateway, three stand-in hosts and
# one worker, and removes all of it, including on failure. Offline by design: the hosts
# are local containers.
#
# Usage: bash dev/validate-run-egress.sh [--json]
#        bash dev/validate-run-egress.sh --self-test   (each row goes red without its rule)
set -uo pipefail
cd "$(dirname "$0")/.."
exec python3 dev/run-egress-probe.py "$@"
