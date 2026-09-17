#!/usr/bin/env bash
# Checks the adversarial bundle corpus (WORKPLAN-BUNDLES.md T2).
#
# Separate from dev/validate-manifests.sh on purpose. That one checks released schemas
# against fixture documents; this one checks archive BYTES, and will grow the oracle, the
# outside-root sentinels and the deliberately unsafe extractor that proves the oracle can
# detect an escape. Different subject, different failure modes, different runtime.
#
# What it establishes today, none of which involves an extractor -- there isn't one, and
# neither script may import one:
#
#   * the corpus regenerates deterministically and matches every recorded SHA-256
#   * every negative fixture actually exhibits the property its name claims
#   * every positive control exhibits none of the hostile properties
#
# That last pair is the point. A corpus of negatives that nothing runs against will report
# itself as complete forever; the way it rots is a fixture quietly becoming benign while
# still being counted as covered.
#
# Runs in a container because there is no local Python package set, matching how everything
# else here builds. Nothing is decompressed beyond a bound -- the corpus contains bombs.
#
# Usage: bash dev/validate-bundles.sh          (needs Docker; no dev stack required)

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="${BUNDLE_CORPUS_IMAGE:-python:3.12-slim}"

echo "== adversarial bundle corpus =="
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/ws:ro -w /ws -e HOME=/tmp "$IMAGE" \
    python dev/bundle-corpus-check.py
