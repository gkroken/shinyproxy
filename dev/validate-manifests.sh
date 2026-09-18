#!/usr/bin/env bash
# Checks every released schema in this repository against its fixture corpus:
#
#   schemas/manifest/v1.schema.json          + dev/fixtures/manifests
#   schemas/output-descriptor/v1.schema.json + dev/fixtures/output-descriptors
#
# Two passes, and the second is not decoration:
#
#   dev/schema-fixture-check.py   JSON Schema validation with python jsonschema -- NOT the
#                                 networknt library the server will use. It also proves each
#                                 schema constrains anything at all, checks the published
#                                 manifest path is the same document the version selects,
#                                 asserts the input and output path rules have not drifted,
#                                 and round-trips a descriptor whose filenames need URL
#                                 encoding.
#   dev/schema-regex-check.js     The raw patterns against ECMA-262. `$` matches before a
#                                 final newline in both Python's re and java.util.regex, so
#                                 an anchor that looks right in one engine can be wrong in
#                                 the one that ships (finding dd46cac-F2).
#
# Both run in containers because there is no local JDK, Maven or Python package set, which is
# how everything else here builds. The scripts are separate files rather than heredocs so
# that `$schema`, `$defs` and `$ref` are not exposed to shell expansion.
#
# Usage: bash dev/validate-manifests.sh          (needs Docker; no dev stack required)

set -uo pipefail
cd "$(dirname "$0")/.."

PY_IMAGE="${SCHEMA_VALIDATOR_IMAGE:-python:3.12-slim}"
JS_IMAGE="${SCHEMA_REGEX_IMAGE:-node:22-slim}"

echo "== JSON Schema validation (python jsonschema; not the server's networknt) =="
docker run --rm -v "$PWD":/ws:ro -w /ws "$PY_IMAGE" sh -c '
  # rfc3339-validator is not optional. jsonschema alone has no date-time checker, so
  # `format` stays an inert annotation and February 30th validates (finding c225d50-F1).
  # Both are MIT, both are container-only dev tools, and neither ships in the jar.
  pip install --quiet --disable-pip-version-check \
      "jsonschema==4.26.0" "rfc3339-validator==0.1.4" >/dev/null 2>&1 || {
    echo "!! could not install jsonschema + rfc3339-validator in the validator container" >&2
    exit 2; }
  # The self-test first, in the same container and the same process image. It mutates the
  # isolation profile IN MEMORY and requires each check to fail for its own stated reason.
  # Running it here rather than by hand is the point: 23 mutations previously lived in
  # commit messages, so a reverted fix left this suite vouching for it (finding 29f0ba0-F1).
  python dev/schema-fixture-check.py --self-test || exit 1
  echo
  exec python dev/schema-fixture-check.py
' || exit 1

echo
echo "== pattern anchors, cross-checked against ECMA-262 (node) =="
docker run --rm -v "$PWD":/ws:ro -w /ws "$JS_IMAGE" node dev/schema-regex-check.js
