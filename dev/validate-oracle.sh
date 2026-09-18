#!/usr/bin/env bash
# Runs the oracle over the whole corpus with the disposable extractor
# (WORKPLAN-BUNDLES.md T2b): every fixture extracted for real, in a fresh world, judged
# against the corpus decisions AND the outside-root sentinels.
#
# Root in a disposable container, for the reason dev/validate-sentinels.sh explains: the
# corpus names /etc/passwd and /etc/skald-escape.txt as escape targets, and a sentinel
# over a path this process cannot write to is a check that cannot fail. --network none,
# the repository mounted read-only, and the worlds inside the container's own filesystem,
# so an escape stays in a container that is thrown away.
#
# Arguments after the script name go to the oracle: --full for the documented limit
# profile, or `-- --without duplicates` to remove one guard from the extractor.
#
# Usage: bash dev/validate-oracle.sh [--full] [-- EXTRACTOR ARGS...]

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="${BUNDLE_CORPUS_IMAGE:-python:3.12-slim}"

docker run --rm --user 0:0 --network none -v "$PWD":/ws:ro -w /ws \
    -e HOME=/tmp -e SKALD_WORLD_BASE=/work "$IMAGE" \
    python dev/bundle-oracle.py "$@"
