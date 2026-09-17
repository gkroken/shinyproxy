#!/usr/bin/env bash
# Checks schemas/manifest/v1.schema.json against dev/fixtures/manifests, using a JSON Schema
# implementation that is NOT the one the product will use.
#
# That is the point of the script rather than an accident of tooling. The server will validate
# with networknt's Java library; if the fixtures were only ever checked with the same library,
# a fixture and the validator could agree on something the written contract does not say, and
# nothing would notice. Python's `jsonschema` is a second opinion on the same document.
#
# It runs in a container because there is no local JDK, Maven or Python package set, matching
# how everything else in this repository builds.
#
# Usage: bash dev/validate-manifests.sh          (needs Docker; no dev stack required)

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="${MANIFEST_VALIDATOR_IMAGE:-python:3.12-slim}"

docker run --rm --network bridge -v "$PWD":/ws:ro -w /ws "$IMAGE" sh -c '
  pip install --quiet --disable-pip-version-check jsonschema >/dev/null 2>&1 || {
    echo "!! could not install jsonschema in the validator container" >&2; exit 2; }
  python - <<PYEOF
import json, pathlib, sys
from jsonschema import Draft202012Validator
import jsonschema

base = pathlib.Path("dev/fixtures/manifests")
exp = json.loads((base / "expectations.json").read_text())
schema = json.loads(pathlib.Path(exp["schema"]).read_text())

# A schema that is itself invalid would silently accept everything.
Draft202012Validator.check_schema(schema)

# The index must point at the schema actually being exercised, and must not itself be a
# schema -- if it were, an edit to it could change what a released manifest version means.
index = json.loads(pathlib.Path("schemas/manifest.schema.json").read_text())
assert "\$schema" not in index, "schemas/manifest.schema.json is a schema; it must be an index"
assert index["versions"]["1"] == exp["schema"], "the index does not point at the schema under test"

validator = Draft202012Validator(schema)

print("validator: python jsonschema", jsonschema.__version__, "| dialect 2020-12")
print("schema   :", exp["schema"])
print()

ok = True

def report(mark, group, name, detail=""):
    print("  %-4s %-16s %-36s %s" % (mark, group, name, detail))

for name in exp["valid"]:
    doc = json.loads((base / "valid" / (name + ".json")).read_text())
    errs = sorted(validator.iter_errors(doc), key=lambda e: e.path)
    if errs:
        ok = False
        report("FAIL", "valid", name, "rejected: " + errs[0].message)
    else:
        report("ok", "valid", name)

for name in exp["schema_invalid"]:
    doc = json.loads((base / "invalid" / (name + ".json")).read_text())
    errs = sorted(validator.iter_errors(doc), key=lambda e: e.path)
    if errs:
        report("ok", "schema-invalid", name, errs[0].message[:60])
    else:
        ok = False
        report("FAIL", "schema-invalid", name, "ACCEPTED by the schema")

# These must be accepted here. The schema cannot express containment, inventory membership or
# entrypoint resolution, so a rejection would mean the schema is enforcing something other than
# what is written -- and would hide the fact that the semantic validator still owes this check.
for name in exp["semantic_invalid"]:
    doc = json.loads((base / "invalid" / (name + ".json")).read_text())
    errs = sorted(validator.iter_errors(doc), key=lambda e: e.path)
    if errs:
        ok = False
        report("FAIL", "semantic-only", name, "schema rejected it: " + errs[0].message[:50])
    else:
        report("ok", "semantic-only", name, "accepted, as specified; owed to the semantic validator")

print()
print("valid %d | schema-invalid %d | semantic-only %d" % (
    len(exp["valid"]), len(exp["schema_invalid"]), len(exp["semantic_invalid"])))
print("RESULT:", "all fixtures behaved as specified" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
PYEOF
'
