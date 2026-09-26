#!/usr/bin/env bash
# Rootless BuildKit under a real seccomp profile (WORKPLAN-BUNDLES.md T3, Q2's default).
#
# BuildKit's own rootless guide runs the container with `--security-opt seccomp=unconfined
# --security-opt apparmor=unconfined`, and the usual workaround for nested builds is
# `--oci-worker-no-process-sandbox`. Decision 6 rejects all three by name, and
# seccomp=unconfined is in the isolation profile's forbidden_arguments. So this does not
# ask whether rootless BuildKit runs; it asks whether it runs without them.
#
# It does: Docker's deny-by-default profile plus seven namespace-management syscalls, with
# keyctl answered ENOSYS and the process sandbox intact, proved by a real build rather than
# by a daemon that started. The profile and the reason for each member are in
# dev/buildkit_worker_profile.py. (This said "plus clone and mount" until t5-e5e3071-F8;
# that was false from 98c00fb on, and the two-call claim never had a RUN behind it.)
#
# Fetches Docker's default profile over the network and refuses to run without it, rather
# than substituting something weaker. Runs on the HOST and drives docker directly; creates
# one container per case and removes it, including on failure.
#
# Usage: bash dev/validate-rootless-buildkit.sh [--json]
#        bash dev/validate-rootless-buildkit.sh --self-test   (proves each syscall is needed)

set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 dev/rootless-buildkit-probe.py "$@"
