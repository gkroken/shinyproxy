#!/usr/bin/env bash
# The trusted bases in images/, built through forge and checked against images/catalog.json
# (WORKPLAN-BUNDLES.md T7). Starts a pinned forge in eval mode on port 18081, builds each base
# with --network host through it, checks every recorded fact inside the built image, and
# removes forge and the images afterwards. See dev/bases-probe.py.
#
# Usage: bash dev/validate-bases.sh [--json]
#        bash dev/validate-bases.sh --self-test   (each check catches what it exists for)
set -uo pipefail
cd "$(dirname "$0")/.."
exec python3 dev/bases-probe.py "$@"
