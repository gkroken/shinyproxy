# Validates every schema fixture corpus in this repository.
#
# Run through dev/validate-manifests.sh, which supplies a container holding a JSON Schema
# implementation that is NOT the one the server will use. Kept as a file rather than a shell
# heredoc so that `$schema`, `$defs` and `$ref` are not at the mercy of shell expansion, and
# so it can be read on its own.
#
# Two review findings shaped what this checks, and both are worth knowing before editing it:
#
#   dd46cac-F1  A document without `$schema` is still a schema. JSON Schema ignores unknown
#               keywords, so an "index" placed at a schema path validated null, 42 and every
#               malformed input. Hence the vacuity probes below: a schema that accepts
#               anything makes every other assertion here meaningless.
#   dd46cac-F2  `$` does not mean end-of-string in Python's re or java.util.regex; it matches
#               before a final newline. Hence the trailing-newline fixtures, and the separate
#               ECMA-262 cross-check in dev/schema-regex-check.js.

import json
import pathlib
import re
import sys

from importlib.metadata import version as _pkg_version

from jsonschema import Draft202012Validator, FormatChecker

REPO = pathlib.Path(".")

CORPORA = [
    {
        "name": "manifest",
        "dir": REPO / "dev/fixtures/manifests",
        # The published path a consumer reads, which must be the same document the version
        # selects. Absent for corpora that have no published alias.
        "published": REPO / "schemas/manifest.schema.json",
    },
    {
        "name": "output-descriptor",
        "dir": REPO / "dev/fixtures/output-descriptors",
        "published": None,
    },
]

ok = True


def require_format_checkers(needed):
    """Refuse to run unless `format` is actually enforceable for the formats we rely on.

    Two separate things have to be true, and neither is a default. In JSON Schema 2020-12
    `format` is an ANNOTATION: a validator ignores it unless asked to assert. And in this
    library, asking is not enough -- `date-time` only appears in the checker registry when a
    date-time implementation is installed alongside. With `pip install jsonschema` alone,
    passing FORMAT_CHECKER silently checks nothing, which is how four impossible timestamps
    (month 99, February 30th, hour 99, offset +99:99) validated against a schema that
    advertises RFC 3339 (finding c225d50-F1).

    Failing loudly here is the point. A missing dependency must not quietly restore the green
    this once had.
    """
    available = FormatChecker().checkers
    if not needed:
        return
    missing = [f for f in needed if f not in available]
    if missing:
        print("!! format checker(s) not installed: %s" % ", ".join(missing))
        print("!! `format` would be an inert annotation and impossible values would validate.")
        print("!! install rfc3339-validator alongside jsonschema; see dev/validate-manifests.sh")
        sys.exit(2)
    print("format assertions enabled for: %s" % ", ".join(sorted(needed)))


def fail(message):
    global ok
    ok = False
    print("  FAIL " + message)


def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def vacuity_probe(validator, label):
    """A schema that accepts anything would make every check below pass for free."""
    for name, doc in (("null", None), ("42", 42), ("empty object", {})):
        if validator.is_valid(doc):
            fail("%s accepts %s; it is not constraining anything" % (label, name))


def check_corpus(corpus):
    print("== %s ==" % corpus["name"])
    exp = load(corpus["dir"] / "expectations.json")
    require_format_checkers(exp.get("requires_format_assertion", []))
    versioned = pathlib.Path(exp["schema"])
    ver_text = versioned.read_text(encoding="utf-8")

    validators = {}
    if corpus["published"] is not None:
        pub_text = corpus["published"].read_text(encoding="utf-8")
        if pub_text != ver_text:
            fail("%s and %s differ; the published path could validate something the "
                 "released version rejects" % (corpus["published"], versioned))
            return
        pub = json.loads(pub_text)
        if "$schema" not in pub:
            fail("%s is not a JSON Schema document" % corpus["published"])
        Draft202012Validator.check_schema(pub)
        validators["published"] = Draft202012Validator(pub, format_checker=FormatChecker())

    ver = json.loads(ver_text)
    Draft202012Validator.check_schema(ver)
    validators["versioned"] = Draft202012Validator(ver, format_checker=FormatChecker())

    for label, v in validators.items():
        vacuity_probe(v, "%s (%s)" % (corpus["name"], label))

    def verdicts(doc):
        return {k: sorted(v.iter_errors(doc), key=lambda e: e.path) for k, v in validators.items()}

    def report(mark, group, name, detail=""):
        print("  %-4s %-16s %-38s %s" % (mark, group, name, detail))

    def check(group, folder, name, must_accept, must_reject_everywhere=False):
        doc = load(corpus["dir"] / folder / (name + ".json"))
        v = verdicts(doc)
        if len({bool(errs) for errs in v.values()}) > 1:
            fail("%s: documents disagree about %s" % (corpus["name"], name))
            return
        errs = v["versioned"]
        if must_accept and errs:
            fail("%s %s rejected: %s" % (group, name, errs[0].message[:60]))
        elif must_accept:
            report("ok", group, name)
        elif must_reject_everywhere and not errs:
            fail("%s %s ACCEPTED by the schema" % (group, name))
        elif must_reject_everywhere:
            report("ok", group, name, errs[0].message[:55])
        elif errs:
            # A semantic-only case. The schema rejecting it would mean the schema is
            # enforcing something other than what is written, and would hide that the
            # semantic validator still owes the check.
            fail("%s %s: schema rejected a semantic-only case" % (group, name))
        else:
            report("ok", group, name, "accepted, as specified; owed to the semantic validator")

    for name in exp["valid"]:
        check("valid", "valid", name, True)
    for name in exp["schema_invalid"]:
        check("schema-invalid", "invalid", name, False, must_reject_everywhere=True)
    for name in exp["semantic_invalid"]:
        check("semantic-only", "invalid", name, False)

    print("  valid %d | schema-invalid %d | semantic-only %d | documents checked: %s" % (
        len(exp["valid"]), len(exp["schema_invalid"]), len(exp["semantic_invalid"]),
        ", ".join(sorted(validators))))
    print()


def check_path_rules_have_not_drifted():
    """An output path and an input path face the same hostile input.

    The two definitions are duplicated rather than $ref'd across files, because a released
    schema that resolves a reference to another file is a schema whose meaning depends on
    what that other file says later. Duplication is the safer trade only while something
    notices divergence, which is this.
    """
    print("== path rules ==")
    manifest = load("schemas/manifest/v1.schema.json")["$defs"]["payloadPath"]
    descriptor = load("schemas/output-descriptor/v1.schema.json")["$defs"]["renditionPath"]
    for key in ("pattern", "minLength", "maxLength", "type"):
        if manifest.get(key) != descriptor.get(key):
            fail("payloadPath.%s and renditionPath.%s have drifted: %r vs %r"
                 % (key, key, manifest.get(key), descriptor.get(key)))
            return
    print("  ok   payloadPath and renditionPath agree on type, pattern and bounds")
    print()


def parse_semantic_rule_table(plan):
    """Fixture -> [rule ids] from the S-table in "Semantic validation".

    A bounded parser of one known table, not a Markdown framework. It reads only rows whose
    first cell is a rule id, and only the last cell of those rows, so a fixture name
    appearing in prose, in the Rejects column, or in a historical note is not an owner.
    """
    mapping = {}
    rules = set()
    for line in plan.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 4:
            continue
        rule_id = cells[0]
        if not re.fullmatch(r"S\d+", rule_id):
            continue
        rules.add(rule_id)
        for name in re.findall(r"`([a-z0-9][a-z0-9-]*)`", cells[3]):
            mapping.setdefault(name, []).append(rule_id)
    return mapping, rules


def check_semantic_fixtures_have_an_owning_rule():
    """Every semantic-only fixture must be owned by a numbered rule.

    These fixtures are the ones the schema deliberately accepts, so nothing else in this
    runner can fail when one is wrong -- by construction they all "pass". That makes them the
    easiest thing in the corpus to add and forget, and a fixture nobody owns is
    indistinguishable from a rule nobody implemented.

    The association is parsed, not searched for. An earlier version asked whether the fixture
    name occurred anywhere in the plan, which stayed green after every rule row was deleted so
    long as the names survived in a note saying they had no rule (finding 61101bc-F1). The
    mutation test that accompanied it only removed names entirely, which is the one mutation
    that version could catch.
    """
    print("== semantic rule coverage ==")
    plan = pathlib.Path("WORKPLAN-BUNDLES.md").read_text(encoding="utf-8")
    exp = load("dev/fixtures/manifests/expectations.json")

    mapping, rules = parse_semantic_rule_table(plan)
    if not rules:
        fail("no S-numbered rule rows found in WORKPLAN-BUNDLES.md; the coverage check "
             "would otherwise pass by having nothing to check against")
        return

    orphans = sorted(n for n in exp["semantic_invalid"] if n not in mapping)
    if orphans:
        fail("semantic fixtures with no owning rule row: %s" % ", ".join(orphans))
        return

    unknown = sorted(n for n in mapping if n not in exp["semantic_invalid"]
                     and n not in exp["schema_invalid"] and n not in exp["valid"])
    if unknown:
        fail("rule rows cite fixtures that do not exist: %s" % ", ".join(unknown))
        return

    print("  ok   %d semantic-only fixtures, each owned by a rule row (%d rules parsed)"
          % (len(exp["semantic_invalid"]), len(rules)))
    for name in sorted(exp["semantic_invalid"]):
        print("       %-38s %s" % (name, ", ".join(mapping[name])))
    print()


def check_descriptor_round_trip():
    """Names that need URL encoding must survive being written and read again.

    Not a test of S3 or of a URL builder, neither of which exists yet: a test that the
    descriptor carries such names literally, so that whatever encodes them later does it at
    one boundary rather than inheriting something already mangled.

    The comparison is against `url_encoding_expected_paths` in expectations.json, not against
    the fixture's own re-serialisation. `json.loads(json.dumps(x)) == x` is true whatever the
    fixture contains, and a check that cannot fail is worse than no check.
    """
    print("== descriptor round-trip ==")
    corpus = pathlib.Path("dev/fixtures/output-descriptors")
    exp = load(corpus / "expectations.json")
    expected = exp["url_encoding_expected_paths"]
    src = corpus / "valid" / (exp["url_encoding_fixture"] + ".json")

    original = json.loads(src.read_text(encoding="utf-8"))
    actual = [f["path"] for f in original["files"]]
    if actual != expected:
        fail("descriptor paths differ from the stated expectation:\n       file:     %r\n"
             "       expected: %r" % (actual, expected))
        return

    # Both encodings a writer might choose must parse back to the same code points.
    for label, text in (("escaped ASCII", json.dumps(original, ensure_ascii=True)),
                        ("UTF-8", json.dumps(original, ensure_ascii=False))):
        back = [f["path"] for f in json.loads(text)["files"]]
        if back != expected:
            fail("a %s round-trip changed the names" % label)
            return

    print("  ok   %d awkward names match the stated expectation and survive both an "
          "escaped-ASCII and a UTF-8 round-trip" % len(expected))
    for p in expected:
        print("       %s" % p)
    print()


print("validator: python jsonschema %s | dialect 2020-12" % _pkg_version("jsonschema"))
print()
for corpus in CORPORA:
    check_corpus(corpus)
check_path_rules_have_not_drifted()
check_semantic_fixtures_have_an_owning_rule()
check_descriptor_round_trip()

print("RESULT:", "all fixtures behaved as specified" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
