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
  pip install --quiet --disable-pip-version-check jsonschema >/dev/null 2>&1 || {
    echo "!! could not install jsonschema in the validator container" >&2; exit 2; }
  exec python dev/schema-fixture-check.py
' || exit 1

echo
echo "== pattern anchors, cross-checked against ECMA-262 (node) =="
docker run --rm -v "$PWD":/ws:ro -w /ws "$JS_IMAGE" node dev/schema-regex-check.js
