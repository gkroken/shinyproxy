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
# of them including on failure -- with their volumes, and a check that the workers' state
# volumes are gone after disposal (t5-e5e3071-F7).
#
# Usage: bash dev/validate-launcher-contract.sh [--json]
#        bash dev/validate-launcher-contract.sh --self-test   (a disposal that leaves the
#                                                             worker's state is caught)

set -uo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--self-test" ]; then
    exec python3 dev/worker_disposal.py --self-test
fi
exec python3 dev/launcher-contract-probe.py "$@"
