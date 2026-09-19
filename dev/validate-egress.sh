#!/usr/bin/env bash
# The build worker's egress gateway: deny all, allow only the configured repository hosts
# (WORKPLAN-BUNDLES.md T3, rule settled in Q3).
#
# dev/validate-sandbox.sh measures `--network none`, which is the floor: a worker with no
# network has no egress, which is true and useless, because a build must fetch its
# dependencies. This measures what a build actually runs with.
#
# Two Docker networks. The worker sits on an --internal one with no route off the host,
# alongside the gateway's inner interface; the gateway's other interface is the only exit.
# The allowlist is tinyproxy's filter with FilterDefaultDeny, so an unconfigured host is
# refused rather than forwarded.
#
# Offline by design: the allowed and denied hosts are local containers, not real PyPI.
# Reaching the internet would test the internet as much as the rule, and a security probe
# that fails on a bad network day gets ignored.
#
# Creates two networks and three containers and removes them, including on failure, and
# including anything else left attached -- a `docker run --rm` whose client is killed
# leaves the container behind and wedges the next run.
#
# Usage: bash dev/validate-egress.sh [--json]
#        bash dev/validate-egress.sh --self-test   (proves the checks can fail)

set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 dev/egress-probe.py "$@"
