#!/usr/bin/env bash
# The launcher/worker contract and registry transport (WORKPLAN-BUNDLES.md T3, decision 6).
#
# The launcher -- this script's caller, which holds Docker access -- starts one rootless
# buildkitd per attempt on an --internal network. The worker gets no Docker socket, no
# context mount and no credentials; a separate client container holds the build context
# and streams it over the BuildKit session; the worker's only route out is the egress
# gateway, allowlisted to the registry alone.
#
# It asserts the whole build: each image is pulled back from the registry by the launcher
# and must hold the file its nested RUN step wrote. The worker's seccomp profile is
# dev/buildkit_worker_profile.py; the probe's docstring records why the RUN used to fail.
#
# Creates two networks, a registry, a gateway and one worker per attempt, and removes all
# of them including on failure.
#
# Usage: bash dev/validate-launcher-contract.sh [--json]

set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 dev/launcher-contract-probe.py "$@"
