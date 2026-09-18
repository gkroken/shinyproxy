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

It imports no Skald class and no extractor. The extractor is a subprocess named by
`--extractor`, so the same oracle judges the real one at T5 by being pointed at it.

By default it runs a REDUCED limit profile. Every boundary fixture is parameterised off
the limits, so the properties hold at any profile, and at the documented defaults the
bombs alone would write about three gigabytes per pass. `--full` uses the defaults.

Usage:
    python3 dev/bundle-oracle.py [--full] [--keep] [--extractor PATH]
                                 [-- EXTRACTOR ARGS...]

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
import tempfile
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


class Failure:
    def __init__(self, kind, detail):
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


def judge(fixture, world, verdict, before, after, elapsed, limits, timed_out, budget):
    """Everything that has to be true, not only the decision."""
    out = []
    root = str(world.root)

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
    elif verdict["decision"] != fixture["expect"]:
        out.append(Failure("unexpected-" + verdict["decision"],
                           "expected %s; %s" % (fixture["expect"],
                                                verdict.get("rule", ""))))

    escaped = [(p, w) for p, w in changes(before, after)
               if p != root and not p.startswith(root + os.sep)]
    for path, what in escaped[:4]:
        out.append(Failure("outside-root-change", "%s (%s)" % (path, what[:60])))

    written = tree_bytes(world.root)
    if written > budget:
        out.append(Failure("over-disk-budget", "%d bytes written, budget %d"
                           % (written, budget)))

    if verdict and verdict.get("decision") == "reject":
        residue = sorted(p.name for p in world.root.iterdir()) if world.root.is_dir() else []
        if residue:
            out.append(Failure("residue", "root not emptied: %s" % residue[:4]))

    if verdict and verdict.get("decision") == "accept" and fixture["expect"] == "accept":
        out.extend(check_produced(world.root))
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
    full = "--full" in argv
    keep = "--keep" in argv
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
    budget = limits["max_expanded_bytes"] * DISK_BUDGET_FACTOR
    deadline = limits["extraction_deadline_seconds"] * DEADLINE_SLACK

    print("== oracle: %d fixtures, %s profile ==" %
          (len(fixtures), "default" if full else "reduced"))
    print("   subject: %s %s" % (extractor, " ".join(extra) or "(all guards on)"))
    print("   outer limits: %.0fs deadline, %d MiB disk budget per fixture"
          % (deadline, budget // (1 << 20)))
    regime = read_detection(str(base))
    if regime != "strictatime":
        print("   note: atime regime is %s, so 'nothing was read' is NOT claimed" % regime)
    print()

    failures, kinds, worst = 0, {}, []
    for i, f in enumerate(fixtures):
        world = World(base / ("w%03d" % i))
        archive = corpus / (f["name"] + ".tar.gz")
        watched = world.watched()
        before = snapshot(watched)
        cmd = [sys.executable, str(extractor), "--root", str(world.root),
               "--archive", str(archive), "--limits", json.dumps(limits)] + extra
        started, timed_out, verdict = time.time(), False, None
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=deadline)
            try:
                verdict = json.loads(r.stdout.decode())
            except Exception:
                verdict = None
        except subprocess.TimeoutExpired:
            timed_out = True
        elapsed = time.time() - started
        after = snapshot(watched)
        bad, written = judge(f, world, verdict, before, after, elapsed, limits,
                             timed_out, budget)
        if bad:
            failures += 1
            for b in bad:
                kinds[b.kind] = kinds.get(b.kind, 0) + 1
            if len(worst) < 25:
                worst.append((f["name"], f["expect"], bad))
        if not keep:
            world.destroy()

    for name, expect, bad in worst:
        print("  FAIL %-34s (want %s)" % (name, expect))
        for b in bad[:3]:
            print("         %s" % b)
    if failures > len(worst):
        print("  ... and %d more fixtures with findings" % (failures - len(worst)))
    print()
    print("  %d of %d fixtures clean" % (len(fixtures) - failures, len(fixtures)))
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
