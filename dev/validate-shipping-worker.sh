#!/usr/bin/env bash
# The build worker under the launch arguments it ships with (WORKPLAN-BUNDLES.md T5, gate
# finding t5-e5e3071-F6; decision 6).
#
# Starts the rootless BuildKit worker with every argument spec/isolation-profile-v1.json
# gives the build-worker profile, read from that file by dev/shipping_worker.py, and checks:
# the container's own configuration carries each bound, a RUN builds under it, the waived
# no-new-privileges is still impossible, the waiver's three replacement checks hold, the
# root is read-only, and nothing outlives the worker.
#
# Builds the derived worker image (dedicated uid, setuid bits cleared), creates an
# internal network, a workspace volume and one worker, and removes all of them, including
# on failure.
#
# Usage: bash dev/validate-shipping-worker.sh [--json]
#        bash dev/validate-shipping-worker.sh --self-test   (each check fails without its
#                                                           defence)

set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 dev/shipping-worker-probe.py "$@"
