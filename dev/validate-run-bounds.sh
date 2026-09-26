#!/usr/bin/env bash
# What build code cannot consume from a RUN step (WORKPLAN-BUNDLES.md T5, gate finding
# t5-e5e3071-F6 part 3; decision 6's bounded CPU, memory, PIDs, disk and logs).
#
# Under the worker the shipping profile launches, on the loop-backed quota volume, each
# bound is attacked from inside a real RUN and must hold, with an allow control in the same
# RUN. See dev/run-bounds-probe.py.
#
# Builds the worker image, an internal network, a registry behind the egress gateway, a
# quota volume on a loop device (attached by a one-off privileged setup container -- the
# launcher's privilege, never the worker's) and one worker, and removes all of it,
# including the loop device, on success and on failure.
#
# Usage: bash dev/validate-run-bounds.sh [--json]
#        bash dev/validate-run-bounds.sh --self-test   (each check fails without its defence)
set -uo pipefail
cd "$(dirname "$0")/.."
exec python3 dev/run-bounds-probe.py "$@"
