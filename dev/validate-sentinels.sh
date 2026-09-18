#!/usr/bin/env bash
# Proves the outside-root sentinel harness can detect what it watches (WORKPLAN-BUNDLES.md
# T2b). It does NOT extract anything -- there is no extractor yet, and this file may not
# import one.
#
# Runs as root in a disposable container, on purpose and not for convenience. The corpus
# names /etc/passwd, /etc/skald-escape.txt and /tmp/escape.txt as escape targets. Watching
# a path this process cannot write to reports "unchanged" forever, so a sentinel suite run
# unprivileged is a suite that cannot fail -- the harness detects that case and says so.
# The repository is mounted read-only and the world lives in the container's own
# filesystem, so nothing here can reach the host or the working tree.
#
# Usage: bash dev/validate-sentinels.sh          (needs Docker; no dev stack required)

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="${BUNDLE_CORPUS_IMAGE:-python:3.12-slim}"

echo "== outside-root sentinels =="
docker run --rm --user 0:0 --network none -v "$PWD":/ws:ro -w /ws -e HOME=/tmp "$IMAGE" \
    python dev/bundle_sentinels.py --self-test
