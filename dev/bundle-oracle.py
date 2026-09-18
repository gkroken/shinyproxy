"""The oracle: judges a real extraction against the corpus and the sentinels (T2b).

The corpus says which archives must be rejected. The sentinels say what must not have
moved. This runs an extractor over every fixture, in a fresh world, and decides whether
the outcome was acceptable -- which is more than "did the return code match":

  * the decision matches the corpus, and a CRASH is never a rejection
  * nothing outside the extraction root was created, overwritten, deleted, re-moded or
    retargeted
  * a rejected bundle left an empty root: no residue to clean up later
  * an accepted bundle actually produced its declared inventory, byte for byte, with no
    extra files and no privileged modes
  * the extractor stayed inside the outer test limits -- a wall-clock deadline and a disk
    budget -- so a bomb that is "rejected" only after filling the disk still fails
  * with `--symlinked-root`, that it fails closed when its root is a symlink rather than
    a directory -- which is not a property of any archive, so no fixture can express it
  * with `--rename-race`, that a directory swapped for a symlink WHILE it is extracting
    does not take anything outside the root with it. Under a race either decision is
    acceptable -- refusing is correct and finishing is correct -- so only containment is
    judged

It imports no Skald class and no extractor. The extractor is a subprocess named by
`--extractor`, so the same oracle judges the real one at T5 by being pointed at it.

By default it runs a REDUCED limit profile. Every boundary fixture is parameterised off
the limits, so the properties hold at any profile, and at the documented defaults the
bombs alone would write about three gigabytes per pass. `--full` uses the defaults.

Usage:
    python3 dev/bundle-oracle.py [--full] [--keep] [--json] [--only FIXTURE]
                                 [--deadline SECONDS] [--disk-budget BYTES]
                                 [--extractor PATH] [--symlinked-root]
                                 [--rename-race] [--repeat N]
    python3 dev/bundle-oracle.py --kinds
                                 [-- EXTRACTOR ARGS...]

`--json` prints the findings as one object instead of a report, which is how
dev/bundle-oracle-matrix.py consumes a run.

Anything after `--` is appended to the extractor's argv, which is how a guard is removed
(`-- --without duplicates`) or a variant selected (`-- --unsafe`). The subject is invoked
as:

    <python> <extractor> --root DIR --archive FILE --limits JSON [extra args...]

and must print one JSON object on stdout with a "decision" of accept, reject or crash.
Any other program obeying that contract can be judged by this oracle; `--extractor` is
how the real one gets pointed at.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from bundle_sentinels import World, snapshot, changes, read_detection  # noqa: E402

HERE = pathlib.Path("dev/fixtures/bundles")
DEFAULT_EXTRACTOR = HERE / "disposable_extractor.py"

# The reduced profile. Chosen so every N/N+1 pair still straddles its limit while the
# whole corpus extracts in seconds; the properties are what is under test, not the
# particular numbers.
SMALL = {
    "max_compressed_bytes": 4 * 1024 * 1024,
    "max_expanded_bytes": 48 * 1024 * 1024,
    "max_file_bytes": 12 * 1024 * 1024,
    "max_entries": 400,
    "max_manifest_bytes": 512 * 1024,
}

# Outer test limits, applied by the oracle and not by the extractor. An extractor that
# rejects a bomb only after writing it everywhere has not rejected it.
DISK_BUDGET_FACTOR = 4          # of max_expanded_bytes
DEADLINE_SLACK = 2.0            # of extraction_deadline_seconds


# Every finding this oracle can produce, declared in one place so the matrix can check
# its own coverage BY CONSTRUCTION instead of by someone remembering to add a scenario.
# Three commits in a row were corrected for "a check that nothing checks"; enumerating
# the list again would only move the next omission somewhere else.
KINDS = (
    "timeout",               # the subject never finished inside the outer deadline
    "no-verdict",            # it printed nothing parseable: silence is not a decision
    "race-not-raced",        # --rename-race never got a swap in: the run proves nothing
    "crash",                 # it fell over: also not a decision
    "bad-decision",          # it said something that is none of the three
    "unexpected-accept",     # the corpus said reject
    "unexpected-reject",     # the corpus said accept -- what positive controls are for
    "outside-root-change",   # a sentinel moved
    "over-disk-budget",      # rejected, eventually, after filling the disk
    "residue",               # rejected, but the root was not emptied
    "missing-output",        # accepted, but a declared file is not there
    "wrong-output",          # accepted, and a declared file has the wrong bytes
    "privileged-mode",       # accepted, and something carries setuid/setgid/sticky
    "extra-output",          # accepted, and something undeclared is there
)


class Failure:
    def __init__(self, kind, detail):
        assert kind in KINDS, "undeclared finding kind %r; add it to KINDS" % kind
        self.kind, self.detail = kind, detail

    def __str__(self):
        return "%s: %s" % (self.kind, self.detail)


def tree_bytes(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total


class Racer(threading.Thread):
    """Swap `<root>/www` between a real directory and a symlink pointing outside.

    The classic time-of-check/time-of-use against an extractor: every path it validated
    was fine, and by the time it opens the parent the parent is a link. An extractor that
    walks with O_NOFOLLOW at each component either wins or fails closed; one that resolves
    a path and then opens it writes through the link.

    Deliberately crude -- a tight loop rather than a synchronised handoff -- because a
    synchronised race tests the synchronisation. The caller repeats the fixture so that a
    window missed once is not read as a window that cannot be hit.
    """

    def __init__(self, root, outside):
        super().__init__(daemon=True)
        self.root, self.outside, self.running = pathlib.Path(root), outside, True
        self.swaps = 0
        # Both spellings, because they are not the same subject. A guarded extractor
        # strips the payload root and writes <root>/www; one with the path guard removed
        # does not, and writes <root>/app/www. Racing only the first meant the VULNERABLE
        # variant was never raced at all, and its clean run was mistaken for a pass.
        self.targets = [self.root / "www", self.root / "app" / "www"]

    def stop(self):
        self.running = False
        self.join(timeout=5)

    def run(self):
        while self.running:
            for target in self.targets:
                if not self.running:
                    break
                self.swap(target)

    def swap(self, target):
        stash = target.parent / (".racer-stash-" + target.name)
        try:
            if target.is_dir() and not target.is_symlink():
                os.rename(target, stash)
                os.symlink(self.outside, target)
                self.swaps += 1
                time.sleep(0.0005)
                os.unlink(target)
                os.rename(stash, target)
        except OSError:
            # The subject is writing underneath us; a lost race here is expected and is
            # not what is being measured. What must never be left behind is the symlink.
            try:
                if target.is_symlink():
                    os.unlink(target)
                if stash.exists() and not target.exists():
                    os.rename(stash, target)
            except OSError:
                pass


def judge(fixture, world, root_path, expect, verdict, before, after, elapsed,
          timed_out, budget):
    """Everything that has to be true, not only the decision."""
    out = []
    root = str(root_path)

    if timed_out:
        out.append(Failure("timeout", "killed after %.1fs" % elapsed))
    elif verdict is None:
        out.append(Failure("no-verdict", "the extractor printed nothing parseable"))
    elif verdict.get("decision") == "crash":
        # Deliberately not treated as a rejection. An extractor that falls over on a
        # hostile archive has decided nothing, and calling that "rejected" is how a
        # corpus of negatives passes without anything working.
        out.append(Failure("crash", "%s: %s" % (verdict.get("rule"),
                                                verdict.get("reason", "")[:70])))
    elif expect is None:
        pass          # a raced run: any decision is acceptable, containment is not
    elif verdict.get("decision") not in ("accept", "reject"):
        # A subject defect, reported as one. Building Failure("unexpected-" + decision)
        # here made an unrecognised decision string violate the oracle's own KINDS assert
        # and abort the whole run with a traceback about its internals, losing the other
        # 89 verdicts (finding 6024d51-F1). At T5 the subject is a different
        # implementation and a drifting decision string is exactly what this should
        # report, not die on.
        out.append(Failure("bad-decision", "decision %r is not accept, reject or crash"
                           % (verdict.get("decision"),)))
    elif verdict["decision"] != expect:
        out.append(Failure("unexpected-" + verdict["decision"],
                           "expected %s; %s" % (expect, verdict.get("rule", ""))))

    escaped = [(p, w) for p, w in changes(before, after)
               if p != root and not p.startswith(root + os.sep)]
    for path, what in escaped[:4]:
        out.append(Failure("outside-root-change", "%s (%s)" % (path, what[:60])))

    written = tree_bytes(root_path)
    if written > budget:
        out.append(Failure("over-disk-budget", "%d bytes written, budget %d"
                           % (written, budget)))

    if verdict and verdict.get("decision") == "reject" and expect is not None:
        residue = sorted(p.name for p in root_path.iterdir()) if root_path.is_dir() else []
        if residue:
            out.append(Failure("residue", "root not emptied: %s" % residue[:4]))

    if verdict and verdict.get("decision") == "accept" and expect == "accept":
        out.extend(check_produced(root_path))
    return out, written


def check_produced(root):
    """An accepted bundle must have produced what its manifest declared.

    Without this, an extractor that accepts everything and writes nothing passes every
    positive control, which is the mirror of the "rejects everything" failure the corpus
    guards against.
    """
    import hashlib
    out = []
    manifest = root / "manifest.json"
    if not manifest.is_file():
        return [Failure("missing-output", "no manifest.json in the extracted tree")]
    try:
        doc = json.loads(manifest.read_bytes())
    except Exception as e:
        return [Failure("missing-output", "manifest unreadable: %s" % type(e).__name__)]
    declared = {f["path"]: f for f in doc.get("files", [])}
    present = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            full = pathlib.Path(dirpath) / name
            rel = str(full.relative_to(root))
            if rel == "manifest.json":
                continue
            present[rel] = full
    for rel, f in declared.items():
        full = present.get(rel)
        if full is None:
            out.append(Failure("missing-output", "declared but not extracted: %s" % rel))
            continue
        data = full.read_bytes()
        if len(data) != f["size"] or hashlib.sha256(data).hexdigest() != f["sha256"]:
            out.append(Failure("wrong-output", "%s does not match its declared bytes" % rel))
        mode = full.stat().st_mode & 0o7000
        if mode:
            out.append(Failure("privileged-mode", "%s has mode %o" % (rel, mode)))
    for rel in sorted(set(present) - set(declared)):
        out.append(Failure("extra-output", "extracted but not declared: %s" % rel))
    return out[:4]


def run(argv):
    if "--kinds" in argv:
        print(json.dumps(list(KINDS)))
        return 0
    full = "--full" in argv
    keep = "--keep" in argv
    as_json = "--json" in argv
    # One fixture, for the checks whose cost is per-run rather than per-corpus -- the
    # deadline probe sleeps past it, and doing that ninety times would take an hour.
    only = argv[argv.index("--only") + 1] if "--only" in argv else None
    # The outer deadline, overridable so the matrix can prove it bites without waiting
    # two minutes for a subject that is sleeping on purpose.
    deadline_override = (int(argv[argv.index("--deadline") + 1])
                         if "--deadline" in argv else None)
    budget_override = (int(argv[argv.index("--disk-budget") + 1])
                       if "--disk-budget" in argv else None)
    # Hand the subject a root that is a SYMLINK to a real directory, which the world
    # already builds. Not a property of any archive: every path check can pass and every
    # member still lands wherever the link points. The contract says fail closed, so in
    # this mode every fixture -- positives included -- must be rejected.
    symlinked_root = "--symlinked-root" in argv
    # Swap a directory inside the root for a symlink pointing OUT of it, over and over,
    # while the subject is writing into it. The plan's last links case, and like the
    # symlinked root it is a property of the world rather than of any archive.
    rename_race = "--rename-race" in argv
    repeat = int(argv[argv.index("--repeat") + 1]) if "--repeat" in argv else 1
    extra = argv[argv.index("--") + 1:] if "--" in argv else []
    head = argv[:argv.index("--")] if "--" in argv else argv
    extractor = pathlib.Path(head[head.index("--extractor") + 1]) \
        if "--extractor" in head else DEFAULT_EXTRACTOR
    if not extractor.is_file():
        print("  FAIL no extractor at %s" % extractor)
        return 1

    base = pathlib.Path(os.environ.get("SKALD_WORLD_BASE", "/work"))
    base.mkdir(parents=True, exist_ok=True)
    corpus = base / "corpus"
    shutil.rmtree(corpus, ignore_errors=True)
    corpus.mkdir(parents=True)

    gen = [sys.executable, str(HERE / "generate.py"), str(corpus)]
    if not full:
        gen += ["--limit"] + ["%s=%d" % kv for kv in SMALL.items()]
    produced = subprocess.run(gen, capture_output=True)
    if produced.returncode != 0:
        print("  FAIL the generator failed: " + produced.stderr.decode()[-300:])
        return 1
    doc = json.loads(produced.stdout.decode())
    limits, fixtures = doc["limits"], doc["fixtures"]
    if only:
        fixtures = [f for f in fixtures if f["name"] == only]
        if not fixtures:
            print("  FAIL no fixture named %r" % only)
            return 1
    # Each repeat gets its own world. A race that only sometimes hits its window has to
    # be given more than one chance, and a single clean run would prove nothing.
    fixtures = fixtures * repeat
    if deadline_override is not None:
        limits["extraction_deadline_seconds"] = deadline_override
    budget = (budget_override if budget_override is not None
              else limits["max_expanded_bytes"] * DISK_BUDGET_FACTOR)
    deadline = limits["extraction_deadline_seconds"] * DEADLINE_SLACK

    regime = read_detection(str(base))
    if not as_json:
        print("== oracle: %d fixtures, %s profile ==" %
              (len(fixtures), "default" if full else "reduced"))
        print("   subject: %s %s" % (extractor, " ".join(extra) or "(all guards on)"))
        if symlinked_root:
            print("   root is a SYMLINK to a real directory; every fixture must be "
                  "rejected")
        print("   outer limits: %.0fs deadline, %d MiB disk budget per fixture"
              % (deadline, budget // (1 << 20)))
        if regime != "strictatime":
            print("   note: atime regime is %s, so 'nothing was read' is NOT claimed"
                  % regime)
        print()

    failures, kinds, worst, records, total_swaps = 0, {}, [], [], 0
    for i, f in enumerate(fixtures):
        # A previous run that died mid-fixture leaves its world behind, and World()
        # refuses to reuse a directory. Without this, one crash cascades: every later
        # scenario in the same container fails with FileExistsError and reports "the
        # oracle did not run", which hides whatever the real failure was.
        here = base / ("w%03d" % i)
        shutil.rmtree(here, ignore_errors=True)
        world = World(here)
        root_path = world.path / "via-symlink" if symlinked_root else world.root
        # expect None means "either decision is acceptable". Under a hostile concurrent
        # rename, refusing is correct and finishing is correct; escaping never is, so
        # containment is the only thing judged.
        expect = None if rename_race else (
            "reject" if symlinked_root else f["expect"])
        archive = corpus / (f["name"] + ".tar.gz")
        watched = world.watched()
        before = snapshot(watched)
        cmd = [sys.executable, str(extractor), "--root", str(root_path),
               "--archive", str(archive), "--limits", json.dumps(limits)] + extra
        started, timed_out, verdict = time.time(), False, None
        racer = Racer(root_path, world.path / "neighbour") if rename_race else None
        swaps = 0
        if racer:
            racer.start()
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=deadline)
            try:
                verdict = json.loads(r.stdout.decode())
            except Exception:
                verdict = None
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if racer:
                racer.stop()
                swaps = racer.swaps
        elapsed = time.time() - started
        after = snapshot(watched)
        bad, written = judge(f, world, root_path, expect, verdict, before, after,
                             elapsed, timed_out, budget)
        total_swaps += swaps
        if bad:
            failures += 1
            for b in bad:
                kinds[b.kind] = kinds.get(b.kind, 0) + 1
            records.append({"name": f["name"], "expect": f["expect"], "group": f["group"],
                            "findings": [{"kind": b.kind, "detail": b.detail}
                                         for b in bad]})
            if len(worst) < 25:
                worst.append((f["name"], f["expect"], bad))
        if not keep:
            world.destroy()

    # A race that never swapped is not a race, and "no escape observed" from a window
    # that never opened is the result this whole suite exists to refuse. Judged over the
    # WHOLE run rather than per repeat: one repeat that misses its window still had its
    # containment checked, and failing on it made the suite intermittently red for
    # something that is not a defect in the subject (finding 69478b0-F1). Zero swaps
    # across every repeat is a different thing, and is a failure.
    if rename_race and total_swaps == 0:
        failures += 1
        kinds["race-not-raced"] = 1
        detail = ("the racer never swapped anything across %d repeat(s); this run raced "
                  "nothing and proves nothing" % len(fixtures))
        records.append({"name": fixtures[0]["name"], "expect": fixtures[0]["expect"],
                        "group": fixtures[0]["group"],
                        "findings": [{"kind": "race-not-raced", "detail": detail}]})
        worst.append((fixtures[0]["name"], fixtures[0]["expect"],
                      [Failure("race-not-raced", detail)]))

    if as_json:
        if not keep:
            shutil.rmtree(corpus, ignore_errors=True)
        print(json.dumps({"fixtures": len(fixtures), "clean": len(fixtures) - failures,
                          "profile": "full" if full else "reduced",
                          "subject": str(extractor), "args": extra,
                          "atime_regime": regime, "kinds": kinds,
                          "failures": records}))
        return 0 if not failures else 1

    for name, expect, bad in worst:
        print("  FAIL %-34s (want %s)" % (name, expect))
        for b in bad[:3]:
            print("         %s" % b)
    if failures > len(worst):
        print("  ... and %d more fixtures with findings" % (failures - len(worst)))
    print()
    print("  %d of %d fixtures clean" % (len(fixtures) - failures, len(fixtures)))
    if rename_race:
        print("  the racer swapped %d time(s) across %d repeat(s)"
              % (total_swaps, len(fixtures)))
    if kinds:
        print("  findings by kind: " + ", ".join("%s %d" % kv for kv in sorted(kinds.items())))
    print()
    print("RESULT:", "the extractor satisfied the corpus and the sentinels" if not failures
          else "%d fixtures the oracle rejected" % failures)
    if not keep:
        shutil.rmtree(corpus, ignore_errors=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
