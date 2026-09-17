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


def check_lifecycle_is_consistent():
    """The bundle and build state machines, checked for the ways a hand-written one rots.

    spec/lifecycle-v1.json is the single source: T6's tables, the coordinator and the admin
    API are written from it, and WORKPLAN-BUNDLES.md explains it rather than restating it.
    Nothing validates against it, so nothing else would notice a state that became
    unreachable, a terminal state that grew an outgoing edge, or a non-terminal state with no
    way out -- each of which is a coordinator that hangs or loses an attempt.
    """
    print("== lifecycle ==")
    spec = load("spec/lifecycle-v1.json")
    actors = {"platform", "worker", "operator"}
    required = {"bundle", "build"}

    # Require the machines before inspecting them. The loop below reports nothing at all for
    # an empty map, so deleting the build lifecycle from the file left its own consistency
    # gate green (finding c4087cd-F2). This is the third checker in this runner to need the
    # same guard: a loop over supplied data passes vacuously unless something demands the
    # data first.
    machines = spec.get("machines") or {}
    absent = sorted(required - set(machines))
    if absent:
        fail("spec/lifecycle-v1.json is missing required machine(s): %s" % ", ".join(absent))
        return

    for name, m in machines.items():
        for key in ("initial", "terminal", "states", "transitions", "deadline_bounded"):
            if not m.get(key):
                fail("%s: %s is missing or empty" % (name, key))
                return

    for name, m in machines.items():
        states, terminal = set(m["states"]), set(m["terminal"])
        transitions = m["transitions"]
        froms = {t["from"] for t in transitions}

        unknown = sorted({t[k] for t in transitions for k in ("from", "to")} - states)
        if unknown:
            fail("%s: transitions reference undeclared states: %s" % (name, ", ".join(unknown)))
            return
        if not terminal <= states:
            fail("%s: terminal states not declared: %s" % (name, ", ".join(sorted(terminal - states))))
            return
        if m["initial"] not in states:
            fail("%s: initial state %s is not declared" % (name, m["initial"]))
            return

        bad_actor = sorted({t["actor"] for t in transitions} - actors)
        if bad_actor:
            fail("%s: unknown actor(s) %s; who causes a transition decides who may be "
                 "fenced off from it" % (name, ", ".join(bad_actor)))
            return

        # Terminal and "has no way out" must be the same set, checked both ways. One
        # direction alone lets a state be forgotten from the terminal list, or a terminal
        # state quietly grow an outgoing edge.
        dead_ends = states - froms
        if dead_ends != terminal:
            fail("%s: terminal list %s disagrees with the states that have no outgoing "
                 "transition %s" % (name, sorted(terminal), sorted(dead_ends)))
            return

        # Every state must be reachable from the initial one.
        reachable, frontier = {m["initial"]}, [m["initial"]]
        while frontier:
            here = frontier.pop()
            for t in transitions:
                if t["from"] == here and t["to"] not in reachable:
                    reachable.add(t["to"])
                    frontier.append(t["to"])
        orphans = sorted(states - reachable)
        if orphans:
            fail("%s: unreachable state(s) %s" % (name, ", ".join(orphans)))
            return

        # Every state that waits on something must have a deadline outcome, and the machine
        # has to say which states those are. Structural checks pass happily over a phase with
        # no timeout at all: PUBLISHING was reachable and had outgoing edges, and simply had
        # no defined outcome when a push stalled (finding c4087cd-F1).
        for state, target in m["deadline_bounded"].items():
            if state not in states:
                fail("%s: deadline_bounded names unknown state %s" % (name, state))
                return
            if target not in terminal:
                fail("%s: deadline from %s targets %s, which is not terminal"
                     % (name, state, target))
                return
            if not any(t["from"] == state and t["to"] == target for t in transitions):
                fail("%s: %s is declared deadline-bounded but has no transition to %s; a phase "
                     "that can stall with no timeout outcome is a coordinator that hangs"
                     % (name, state, target))
                return

        print("  ok   %-7s %d states, %d transitions, %d terminal, %d deadline-bounded, all reachable"
              % (name, len(states), len(transitions), len(terminal), len(m["deadline_bounded"])))

    print()


# Anchored here, NOT read from the document being checked. An earlier version took the deny
# list from spec/admin-transport-v1.json itself, so deleting "text/plain" from that list and
# then accepting text/plain passed (finding 29afb31-F1). What a browser can send is a fact
# about browsers; a document under review does not get to redefine it.
FORM_PRODUCIBLE = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
})

BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def normalise_media_type(value):
    """Lower-cased type/subtype with parameters stripped.

    `text/plain; charset=UTF-8` and `TEXT/PLAIN` are text/plain to a browser and were not to
    the string comparison this replaces.
    """
    return value.split(";", 1)[0].strip().lower()


def check_admin_transport():
    """The admin surface, checked for what is checkable without an implementation.

    Chiefly one thing: no endpoint may accept a media type an HTML form can produce.
    ShinyProxy enables CSRF protection for POST /login alone, so that rule IS the defence for
    everything spine #2 adds, and the obvious way to build a file upload --
    multipart/form-data -- is exactly what a cross-site form can forge.
    """
    print("== admin transport ==")
    spec = load("spec/admin-transport-v1.json")
    required = {"bundle.create", "bundle.upload", "build.create", "build.cancel",
                "build.logs.replay"}

    endpoints = spec.get("endpoints") or []
    if not endpoints:
        fail("spec/admin-transport-v1.json declares no endpoints; every check below would "
             "pass over an empty list")
        return
    absent = sorted(required - {e["id"] for e in endpoints})
    if absent:
        fail("admin transport is missing required endpoint(s): %s" % ", ".join(absent))
        return

    # The document may restate the deny list, but only in full. Understating it there would
    # otherwise read as a relaxation to anyone consulting the spec rather than this file.
    declared = {normalise_media_type(t) for t in spec["csrf"]["form_producible"]}
    if declared != set(FORM_PRODUCIBLE):
        fail("csrf.form_producible is %s; it must list exactly the three types a browser form "
             "can send: %s" % (sorted(declared), sorted(FORM_PRODUCIBLE)))
        return

    for e in endpoints:
        if not e["path"].startswith("/admin/"):
            fail("%s is at %s, outside /admin, so it would need its own authorization rule"
                 % (e["id"], e["path"]))
            return

        accepts = e.get("accepts", [])
        if e["method"] in BODY_METHODS and not accepts:
            fail("%s is a %s with no declared accepts; an endpoint that names no media type "
                 "constrains none" % (e["id"], e["method"]))
            return

        for raw in accepts:
            media = normalise_media_type(raw)
            if "*" in media:
                fail("%s accepts %r; a wildcard admits every form-producible type, so it can "
                     "never be checked" % (e["id"], raw))
                return
            if media in FORM_PRODUCIBLE:
                fail("%s accepts %r, which an HTML form can produce cross-site"
                     % (e["id"], raw))
                return

    upload = next(e for e in endpoints if e["id"] == "bundle.upload")
    if upload.get("requires_header") != spec["csrf"]["required_header"]:
        fail("the upload endpoint does not require %s; a raw body with no custom header "
             "leans entirely on the content type" % spec["csrf"]["required_header"])
        return

    create = next(e for e in endpoints if e["id"] == "build.create")
    if create["success"] != 202:
        fail("build.create returns %s; it must be 202, because it returns a build id and a "
             "status URL and does not wait for an image" % create["success"])
        return

    bundle = load("spec/lifecycle-v1.json")["machines"]["bundle"]
    build = load("spec/lifecycle-v1.json")["machines"]["build"]

    # The upload may only be accepted where no receipt is committed, or it would rewrite
    # immutable bytes or reopen a terminal state (finding 29afb31-F2).
    # Against the lifecycle's declaration of where bytes are still writable, NOT against
    # terminality. VALIDATING is non-terminal and has a committed receipt, so a terminal-state
    # test accepted it and would have permitted the committed-byte replacement the replay
    # contract forbids (finding 2b01e24-F1). Not terminal is not a synonym for still writable.
    accepted_in = upload.get("accepted_in_states") or []
    admissible = bundle.get("upload_admissible_states") or []
    if not accepted_in:
        fail("bundle.upload does not say which bundle states accept it, so nothing stops it "
             "rewriting committed bytes")
        return
    if not admissible:
        fail("the bundle machine declares no upload_admissible_states, so the check below "
             "would have nothing to compare against")
        return
    if sorted(accepted_in) != sorted(admissible):
        fail("bundle.upload is accepted in %s but the bundle machine says bytes are writable "
             "only in %s" % (sorted(accepted_in), sorted(admissible)))
        return
    for state in accepted_in:
        if state not in bundle["states"]:
            fail("bundle.upload accepted_in_states names unknown bundle state %s" % state)
            return
    if not upload.get("conflict"):
        fail("bundle.upload declares no conflict status, so a replay after the receipt is "
             "committed has no defined answer")
        return

    refused = spec.get("cancel_refused_states") or []
    if not refused:
        fail("cancel_refused_states is empty; the agreement with the lifecycle below would "
             "then be vacuous")
        return
    for state in refused:
        if state not in build["states"]:
            fail("cancel_refused_states names unknown build state %s" % state)
            return
        if any(t["from"] == state and t["to"] == "CANCELLED" for t in build["transitions"]):
            fail("%s refuses cancellation in the transport but the lifecycle has a %s -> "
                 "CANCELLED transition" % (state, state))
            return

    print("  ok   %d endpoints, all under /admin; no wildcard or form-producible accepts"
          % len(endpoints))
    print("  ok   upload requires %s, accepted only in %s, conflicts with %s"
          % (spec["csrf"]["required_header"], ", ".join(accepted_in), upload["conflict"]))
    print("  ok   build.create returns 202; cancellation refused in %s, matching the lifecycle"
          % ", ".join(refused))
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
check_lifecycle_is_consistent()
check_admin_transport()
check_descriptor_round_trip()

print("RESULT:", "all fixtures behaved as specified" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
