#!/usr/bin/env bash
# Runs hostile code inside a REAL dependency-install hook, against the launch arguments
# spec/isolation-profile-v1.json actually specifies (WORKPLAN-BUNDLES.md T3).
#
# Everything dev/validate-sandbox.sh measures is the platform testing its own bounds with
# cooperative code. This is the other half: a package whose setup.py is trying to get out,
# which is where a supply-chain attack actually lives. A lockfile pins WHICH code runs; it
# has never said anything about what that code does.
#
# Like the sandbox suite this runs on the HOST and drives docker directly, because the
# host is the subject. It builds one throwaway base image, creates two named volumes and
# removes them, including on failure.
#
# The base image is built WITH network before the worker starts, and the worker gets none.
# That is the architecture, not a shortcut: Q3 settled that system packages are the
# administrator's, installed into the base images.
#
# Usage: bash dev/validate-hostile-deps.sh [--json]
#        bash dev/validate-hostile-deps.sh --self-test   (proves the attacks can detect)

set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 dev/hostile-dep-probe.py "$@"
