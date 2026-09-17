#!/usr/bin/env bash
# Checks the bundle manifest schema against dev/fixtures/manifests.
#
# Two things this deliberately does, both because of review findings on dd46cac:
#
#   1. It validates through BOTH schemas/manifest.schema.json (the published path a
#      consumer reads) and schemas/manifest/v1.schema.json (the version a validator
#      selects), asserts they are identical, and requires identical verdicts. An earlier
#      revision put a non-schema "index" at the published path on the mistaken belief that
#      a document without $schema cannot be used as one. JSON Schema ignores unknown
#      keywords, so that document was a schema that accepted null, 42 and every malformed
#      manifest -- strictly worse than the copy it replaced (finding dd46cac-F1).
#
#   2. It uses a JSON Schema implementation that is NOT the one the product will use, and
#      cross-checks the raw patterns against a second regex engine. The server will
#      validate with networknt on java.util.regex; the anchors here have to hold in
#      ECMA-262 too, and `$` does not mean "end of string" in either of them -- it matches
#      before a final newline, which is how a 65-character SHA-256 once passed
#      (finding dd46cac-F2).
#
# Runs in a container because there is no local JDK, Maven or Python package set, matching
# how everything else in this repository builds.
#
# Usage: bash dev/validate-manifests.sh          (needs Docker; no dev stack required)

set -uo pipefail
cd "$(dirname "$0")/.."

PY_IMAGE="${MANIFEST_VALIDATOR_IMAGE:-python:3.12-slim}"
JS_IMAGE="${MANIFEST_REGEX_IMAGE:-node:22-slim}"

echo "== JSON Schema validation (python jsonschema; not the server's networknt) =="
docker run --rm -v "$PWD":/ws:ro -w /ws "$PY_IMAGE" sh -c '
  pip install --quiet --disable-pip-version-check jsonschema >/dev/null 2>&1 || {
    echo "!! could not install jsonschema in the validator container" >&2; exit 2; }
  python - <<PYEOF
import json, pathlib, sys
from jsonschema import Draft202012Validator
import jsonschema

base = pathlib.Path("dev/fixtures/manifests")
exp = json.loads((base / "expectations.json").read_text())

published = pathlib.Path("schemas/manifest.schema.json")
versioned = pathlib.Path(exp["schema"])

# The published path must be a real schema, and the same one the version selects.
pub_text, ver_text = published.read_text(), versioned.read_text()
assert pub_text == ver_text, "%s and %s differ; the published path could validate something the released version rejects" % (published, versioned)
pub, ver = json.loads(pub_text), json.loads(ver_text)
Draft202012Validator.check_schema(pub)
Draft202012Validator.check_schema(ver)
assert "\$schema" in pub, "the published path is not a JSON Schema document"

# A schema that accepts anything would make every check below vacuous.
for name, doc in (("null", None), ("42", 42), ("empty object", {})):
    assert not Draft202012Validator(pub).is_valid(doc), "published schema accepts %s" % name
    assert not Draft202012Validator(ver).is_valid(doc), "versioned schema accepts %s" % name

validators = {"published": Draft202012Validator(pub), "v1": Draft202012Validator(ver)}
print("validator: python jsonschema", jsonschema.__version__, "| dialect 2020-12")
print("documents:", published, "==", versioned)
print()

ok = True

def verdicts(doc):
    return {k: sorted(v.iter_errors(doc), key=lambda e: e.path) for k, v in validators.items()}

def report(mark, group, name, detail=""):
    print("  %-4s %-16s %-38s %s" % (mark, group, name, detail))

def check(group, folder, name, must_accept):
    global ok
    doc = json.loads((base / folder / (name + ".json")).read_text())
    v = verdicts(doc)
    if bool(v["published"]) != bool(v["v1"]):
        ok = False
        report("FAIL", group, name, "published and v1 disagree")
        return
    errs = v["v1"]
    if must_accept and errs:
        ok = False; report("FAIL", group, name, "rejected: " + errs[0].message[:55])
    elif must_accept:
        report("ok", group, name)
    elif errs:
        report("ok", group, name, errs[0].message[:55])
    else:
        ok = False; report("FAIL", group, name, "ACCEPTED by the schema")

for name in exp["valid"]:
    check("valid", "valid", name, True)
for name in exp["schema_invalid"]:
    check("schema-invalid", "invalid", name, False)

# These must be accepted here. The schema cannot express containment, inventory membership
# or entrypoint resolution, so a rejection would mean the schema is enforcing something
# other than what is written -- and would hide that the semantic validator still owes it.
for name in exp["semantic_invalid"]:
    doc = json.loads((base / "invalid" / (name + ".json")).read_text())
    v = verdicts(doc)
    if v["published"] or v["v1"]:
        ok = False
        report("FAIL", "semantic-only", name, "schema rejected it")
    else:
        report("ok", "semantic-only", name, "accepted, as specified; owed to the semantic validator")

print()
print("valid %d | schema-invalid %d | semantic-only %d | both documents agreed on all %d" % (
    len(exp["valid"]), len(exp["schema_invalid"]), len(exp["semantic_invalid"]),
    len(exp["valid"]) + len(exp["schema_invalid"]) + len(exp["semantic_invalid"])))
print("RESULT:", "all fixtures behaved as specified" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
PYEOF
' || exit 1

echo
echo "== pattern anchors, cross-checked against ECMA-262 (node) =="
# The server validates on java.util.regex and the spec says ECMA-262. Neither treats `$`
# as end-of-input. This asserts the anchors reject a trailing newline in the other engine
# too, rather than trusting that one implementation's agreement generalises.
docker run --rm -v "$PWD":/ws:ro -w /ws "$JS_IMAGE" node -e '
const fs = require("fs");
const s = JSON.parse(fs.readFileSync("schemas/manifest.schema.json", "utf8"));
const cases = [
  ["sha256",         s.properties.files.items.properties.sha256.pattern, "a".repeat(64)],
  ["runtime.version",s.properties.runtime.properties.version.pattern,    "4.4.1"],
  ["entrypoint",     s.properties.entrypoint.pattern,                    "app.py"],
  ["payloadPath",    s.$defs.payloadPath.pattern,                        "src/app.py"],
];
let ok = true;
for (const [name, pattern, good] of cases) {
  const re = new RegExp(pattern);
  const accepts = (v) => re.test(v);
  const pos = accepts(good), lf = accepts(good + "\n"), mid = accepts(good + "\nx");
  const pass = pos && !lf && !mid;
  if (!pass) ok = false;
  // Plain concatenation: console.log understands %s but not printf padding like %-16s,
  // and a half-substituted line reporting "trailingLF=true" for a passing anchor is worse
  // than no line at all.
  console.log("  " + (pass ? "ok  " : "FAIL") + " " + name.padEnd(16) +
    " accepts-valid=" + pos + " rejects-trailing-LF=" + (!lf) +
    " rejects-embedded-LF=" + (!mid));
}
console.log("");
console.log("RESULT:", ok ? "anchors hold in ECMA-262 as well" : "MISMATCH");
process.exit(ok ? 0 : 1);
'
