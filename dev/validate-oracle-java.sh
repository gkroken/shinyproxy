#!/usr/bin/env bash
# Runs the corpus oracle over the extractor that ships -- BundleExtractor, through the
# test-tree adapter BundleExtractorCli -- instead of the disposable reference extractor
# (WORKPLAN-BUNDLES.md T5). Same oracle, same corpus, same sentinels as
# dev/validate-oracle.sh; only --extractor differs.
#
# Three steps:
#   1. compile main and test classes and write the dependency classpath, with Maven in a
#      container as the invoking user (the same image and caches as `make build`)
#   2. build the runner image, python plus a JRE copied from eclipse-temurin:21-jre
#   3. run the oracle as root with --network none and the repository read-only, for the
#      reason dev/validate-sentinels.sh explains; the Maven cache is mounted read-only at
#      the path the classpath names
#
# Arguments go to the oracle: --full for the documented limit profile, --symlinked-root,
# --rename-race [--repeat N], --only FIXTURE.
#
# Usage: bash dev/validate-oracle-java.sh [ORACLE ARGS...]

set -uo pipefail
cd "$(dirname "$0")/.."

M2="$HOME/.cache/skald/m2"
M2_HOME="$HOME/.cache/skald/m2home"
IMAGE=skald-oracle-java
mkdir -p "$M2" "$M2_HOME"

docker run --rm -u "$(id -u):$(id -g)" -e HOME=/m2home \
    -v "$PWD":/ws -v "$M2":/m2 -v "$M2_HOME":/m2home -w /ws \
    maven:3.9-eclipse-temurin-21 \
    mvn -B -q -Dmaven.repo.local=/m2 -Dlicense.skip=true test-compile \
        dependency:build-classpath -Dmdep.outputFile=target/oracle-classpath.txt \
        -Dmdep.includeScope=test \
    || { echo "  FAIL could not compile or resolve the classpath"; exit 1; }

docker build -q -t "$IMAGE" dev/oracle-java >/dev/null \
    || { echo "  FAIL could not build $IMAGE"; exit 1; }

docker run --rm --user 0:0 --network none -v "$PWD":/ws:ro -v "$M2":/m2:ro -w /ws \
    -e HOME=/tmp -e SKALD_WORLD_BASE=/work "$IMAGE" \
    python dev/bundle-oracle.py --extractor dev/fixtures/bundles/skald_extractor.py "$@"
