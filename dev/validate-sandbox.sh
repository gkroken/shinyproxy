#!/usr/bin/env bash
# Measures what this Docker host can actually enforce on a worker
# (WORKPLAN-BUNDLES.md T3). Every bound the isolation contract requires is exercised
# against a container that tries to exceed it; a bound that is not demonstrably enforced
# fails the run.
#
# Unlike the other dev suites this runs on the HOST and drives docker directly, because
# the host is the subject. It creates only --rm containers, one named volume and at most
# one loop device, and removes all of them, including on failure.
#
# Two of its containers are --privileged: the ones that make a filesystem image and attach
# a loop device. That privilege is the trusted launcher's, not a worker's -- the worker
# gets a volume with a read-only rootfs and never sees the device.
#
# Usage: bash dev/validate-sandbox.sh [--json]

set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 dev/sandbox-probe.py "$@"
