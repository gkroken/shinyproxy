"""Proof that the oracle can fail (WORKPLAN-BUNDLES.md T2b, the Pass line).

The corpus establishes that an extractor is wrong. Nothing in it establishes that the
ORACLE is right, and an oracle that reports "clean" whatever it is handed is the same
defect as a corpus of negatives nothing runs against, one layer up. T2's Pass line is
about detection, in four named classes:

    the oracle detects outside-root changes, duplicate overwrite, limit bypass and
    unexpected acceptance; it is not a collection of negative fixtures that would "pass"
    because nothing runs

So this hands the oracle a series of extractors that are wrong in one specific way each,
and asserts WHICH finding comes back, on WHICH fixture. "Something failed" would be too
weak: an oracle that failed everything for the wrong reason would satisfy it.

Two kinds of subject:

  guard removal   the disposable extractor with one or two guards taken out. This is the
                  plan's "deliberately remove a bound, link check or duplicate guard and
                  record the specific assertion that fails".
  degenerate      extractors that are not weakened but broken -- accepts everything,
                  rejects everything, decides perfectly but escapes, decides perfectly
                  but leaves residue, never finishes. These probe the oracle's own
                  checks rather than the extractor's.

One result deserves reading before the table: removing a single bound is usually MASKED
by another guard. With only `--without limits`, the inventory check rejects most bombs
first -- a bomb that ships an undeclared file is caught as inventory-extra-file long
before any cap is consulted. That is good news about layering and bad news about
single-guard matrices, and it is why the limit-bypass and duplicate-overwrite scenarios
remove two guards: to isolate the one under test rather than to make the numbers larger.

Usage:
    python3 dev/bundle-oracle-matrix.py [--full]
"""

import json
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ORACLE = HERE / "bundle-oracle.py"
DISPOSABLE = "dev/fixtures/bundles/disposable_extractor.py"
DEGENERATE = "dev/fixtures/bundles/degenerate_extractor.py"

# (label, oracle args, what the oracle MUST report, notes)
#
# Each expectation is a (fixture, finding kind) pair, because the class of finding is the
# claim. A scenario that produced the right number of failures for the wrong reason would
# pass a count-based assertion and tell us nothing.
SCENARIOS = [
    ("guarded baseline", [], "clean",
     "if this is not clean, nothing below means anything"),

    ("unexpected acceptance", ["--extractor", DEGENERATE, "--", "--mode", "always-accept"],
     [("trav-dotdot", "unexpected-accept"),
      ("bomb-entries-over-limit", "unexpected-accept"),
      ("pos-r-root", "missing-output")],
     "accepts everything and writes nothing; the positives catch the second half"),

    ("unexpected rejection", ["--extractor", DEGENERATE, "--", "--mode", "always-reject"],
     [("pos-r-root", "unexpected-reject"),
      ("bomb-entries-at-limit", "unexpected-reject")],
     "rejects everything, and passes 71 of 90; the positive controls are the only thing "
     "between it and a clean report"),

    ("outside-root change", ["--extractor", DEGENERATE, "--", "--mode", "escapes"],
     [("pos-r-root", "outside-root-change"),
      ("trav-dotdot", "outside-root-change")],
     "every DECISION is correct and it plants one file outside the root; a decision-only "
     "oracle passes this"),

    ("residue after rejection", ["--extractor", DEGENERATE, "--", "--mode", "residue"],
     [("trav-dotdot", "residue")],
     "correct decisions, but a rejected bundle leaves the root populated"),

    ("escape through traversal", ["--", "--without", "path"],
     [("trav-dotdot", "outside-root-change"),
      ("trav-absolute", "outside-root-change"),
      ("pos-empty-file", "extra-output")],
     "the path guard removed from the real disposable extractor. It also stops stripping "
     "the payload root, so accepted bundles land under app/ and every declared file is "
     "both missing and extra -- which is what pins extra-output (finding 3e23732-F1)"),

    ("escape through links", ["--", "--unsafe"],
     [("link-symlink-dir-then-child", "outside-root-change"),
      ("link-hardlink-outside", "outside-root-change"),
      ("trav-absolute", "outside-root-change"),
      ("bomb-sparse-claimed", "crash")],
     "tarfile.extractall(filter='fully_trusted'). The crash pair is not incidental: "
     "under --unsafe the oracle sees nine crashes on fixtures the corpus expects to be "
     "REJECTED, so folding crash into rejection would turn all nine into silent passes "
     "(finding 64f5dd8-F1)"),

    ("limit bypass", ["--", "--without", "limits", "--without", "manifest"],
     [("bomb-entries-over-limit", "unexpected-accept"),
      ("bomb-expanded-over-limit", "unexpected-accept"),
      ("bomb-compressed-over-limit", "unexpected-accept"),
      ("bomb-extended-header-over-limit", "unexpected-accept")],
     "the manifest guard is removed too, to isolate the caps from the inventory check"),

    ("limit bypass, bounds only", ["--", "--unbounded"],
     [("bomb-compressed-over-limit", "unexpected-accept"),
      ("bomb-entries-over-limit", "unexpected-accept")],
     "the --unbounded variant the plan names; most bombs are still caught by the "
     "inventory check, which is the masking effect and is expected"),

    ("duplicate overwrite",
     ["--", "--without", "duplicates", "--without", "manifest"],
     [("dup-regular", "unexpected-accept"),
      ("dup-manifest", "unexpected-accept"),
      ("dup-case-alias", "unexpected-accept")],
     "with the manifest guard on, dup-regular is caught by the hash check instead -- the "
     "duplicate guard is not what rejects it, so removing it alone proves nothing"),

    ("outer deadline", ["--only", "pos-r-root", "--deadline", "5",
                        "--extractor", DEGENERATE, "--", "--mode", "slow"],
     [("pos-r-root", "timeout")],
     "a subject that never finishes; proves the oracle's own deadline bites"),

    ("outer disk budget", ["--only", "pos-r-root", "--disk-budget", str(1 << 20),
                           "--extractor", DEGENERATE, "--", "--mode", "bloats"],
     [("pos-r-root", "over-disk-budget")],
     "correct decision, 64 MiB written against a 1 MiB budget; a bomb rejected only "
     "after filling the disk has not been rejected"),

    ("no verdict at all", ["--only", "pos-r-root",
                           "--extractor", DEGENERATE, "--", "--mode", "silent"],
     [("pos-r-root", "no-verdict")],
     "an extractor that prints nothing has decided nothing, and silence must not read "
     "as a rejection"),

    ("accepted with the wrong bytes", ["--only", "pos-r-root",
                                       "--extractor", DEGENERATE, "--", "--mode",
                                       "corrupts"],
     [("pos-r-root", "wrong-output")],
     "accepting is not enough: the tree has to be the one the manifest described"),

    ("symlinked root refused", ["--symlinked-root"], "clean",
     "the root is a symlink to a real directory; every fixture must be rejected and "
     "nothing may appear through the link. Not expressible as a fixture: every path "
     "check passes and every member still lands wherever the link points"),

    ("symlinked root followed", ["--symlinked-root", "--", "--without", "path"],
     [("pos-r-root", "outside-root-change"),
      ("pos-r-root", "unexpected-accept")],
     "the same root with the path guard removed, so the oracle is shown to notice -- "
     "before this check the guarded extractor wrote three files through the link and "
     "reported accept"),

    ("rename race survived", ["--only", "bomb-entries-at-limit", "--repeat", "8",
                              "--rename-race"], "clean",
     "a directory inside the root is swapped for a symlink pointing out of it, over and "
     "over, while the subject writes 400 files into it. Either decision is acceptable "
     "under a race -- refusing is correct and finishing is correct -- so only "
     "containment is judged, and a run where the racer never swapped is a failure "
     "rather than a pass"),

    ("rename race followed", ["--only", "bomb-entries-at-limit", "--repeat", "8",
                              "--rename-race", "--", "--without", "path"],
     [("bomb-entries-at-limit", "outside-root-change")],
     "the same race against the path guard removed. Without this the row above would be "
     "a negative result from a window that might never open; with it, the window is "
     "known to be reachable"),

    ("race that never raced", ["--only", "pos-r-root", "--repeat", "2",
                               "--rename-race"],
     [("pos-r-root", "race-not-raced")],
     "pos-r-root has no www directory, so the racer has nothing to swap. A race that "
     "never happened must be reported as such and never as a clean run -- and with its "
     "own kind, so it is not confused with the subject printing nothing"),

    ("unrecognised decision", ["--only", "pos-r-root",
                               "--extractor", DEGENERATE, "--", "--mode", "nonsense"],
     [("pos-r-root", "bad-decision")],
     "a decision string that is none of the three. A subject defect must be reported as "
     "one; aborting the run with an error about the oracle's own vocabulary loses the "
     "other 89 verdicts and says nothing about the subject"),

    ("accepted with a setuid bit", ["--only", "pos-r-root",
                                    "--extractor", DEGENERATE, "--", "--mode", "setuid"],
     [("pos-r-root", "privileged-mode")],
     "the corpus rejects setuid members in the archive; this is the same outcome "
     "arriving by the extractor's own hand"),
]


def oracle_kinds():
    r = subprocess.run([sys.executable, str(ORACLE), "--kinds"], capture_output=True)
    return json.loads(r.stdout.decode())


def run(args, full):
    cmd = [sys.executable, str(ORACLE), "--json"] + (["--full"] if full else []) + args
    r = subprocess.run(cmd, capture_output=True)
    try:
        return json.loads(r.stdout.decode())
    except Exception:
        return {"error": (r.stderr.decode() or r.stdout.decode())[-300:]}


def main(argv):
    full = "--full" in argv
    ok = True
    print("== can the oracle fail? ==")
    print("   %d scenarios, %s profile" % (len(SCENARIOS), "default" if full else "reduced"))
    print()
    for label, args, expected, note in SCENARIOS:
        started = time.time()
        result = run(args, full)
        took = time.time() - started
        if "error" in result:
            ok = False
            print("  FAIL %-28s the oracle did not run: %s" % (label, result["error"]))
            continue
        found = {(f["name"], x["kind"]) for f in result["failures"] for x in f["findings"]}
        if expected == "clean":
            if result["clean"] != result["fixtures"]:
                ok = False
                print("  FAIL %-28s %d of %d clean; %s"
                      % (label, result["clean"], result["fixtures"], result["kinds"]))
            else:
                print("  ok   %-28s %d of %d clean  (%.0fs)"
                      % (label, result["clean"], result["fixtures"], took))
            continue
        missing = [pair for pair in expected if pair not in found]
        if missing:
            ok = False
            print("  FAIL %-28s not detected: %s"
                  % (label, ", ".join("%s/%s" % m for m in missing)))
            print("         the oracle reported: %s" % (result["kinds"] or "nothing"))
        else:
            print("  ok   %-28s %d of %d clean, %s  (%.0fs)"
                  % (label, result["clean"], result["fixtures"],
                     ", ".join("%s %d" % kv for kv in sorted(result["kinds"].items())),
                     took))
        print("       %s" % note)
    # Coverage by construction. Enumerating the kinds by hand is what produced three
    # consecutive findings of "a check that nothing checks": each fix closed the kinds
    # that had been named and left the ones nobody had counted. The oracle declares its
    # own list, and a kind with no scenario behind it fails here the day it is added.
    asserted = {kind for _, _, expected, _ in SCENARIOS if expected != "clean"
                for _, kind in expected}
    unpoliced = [k for k in oracle_kinds() if k not in asserted]
    print()
    if unpoliced:
        ok = False
        print("  FAIL the oracle can report %d finding kind(s) no scenario asserts: %s"
              % (len(unpoliced), ", ".join(unpoliced)))
        print("       remove the check and this suite stays green, which is the defect")
    else:
        print("  ok   every finding kind the oracle declares is asserted by a scenario")
    print()
    print("RESULT:", "the oracle detects every class it claims to" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
