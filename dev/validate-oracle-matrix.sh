#!/usr/bin/env bash
# Proves the ORACLE can fail (WORKPLAN-BUNDLES.md T2b Pass line): it hands
# dev/bundle-oracle.py a series of extractors that are each wrong in one specific way and
# asserts which finding comes back, on which fixture.
#
# Root in a disposable container with --network none and the repository read-only, for the
# reason dev/validate-sentinels.sh explains: several scenarios escape on purpose.
#
# Slower than the other suites -- it is eleven full oracle passes plus a deliberate
# timeout. Run it after anything that touches the oracle, the extractor or the sentinels.
#
# Usage: bash dev/validate-oracle-matrix.sh [--full]

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="${BUNDLE_CORPUS_IMAGE:-python:3.12-slim}"

docker run --rm --user 0:0 --network none -v "$PWD":/ws:ro -w /ws \
    -e HOME=/tmp -e SKALD_WORLD_BASE=/work "$IMAGE" \
    python dev/bundle-oracle-matrix.py "$@"
