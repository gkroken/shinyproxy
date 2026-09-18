"""Extractors that are wrong in one specific way, so the oracle can be shown to fail.

**Test scaffolding, like disposable_extractor.py.** Nothing in the product may call it.

The corpus proves an extractor is wrong. Nothing so far proves the ORACLE is right, and
an oracle that reports "clean" whatever it is handed is the same defect as a corpus of
negatives nothing runs against -- one layer up. Each mode below is broken in exactly one
way, and the matrix asserts which finding the oracle produces for it.

Modes:
  always-accept    accepts everything and writes nothing. Must fail every rejected
                   fixture, AND every accepted one, because an empty tree is not the
                   declared inventory.
  always-reject    rejects everything. This is the interesting one: it passes most of the
                   corpus, and the only thing standing between it and a clean report is
                   the positive controls.
  escapes          decides exactly as the guarded extractor does, and additionally writes
                   one file outside the root. Decisions alone would call it perfect.
  residue          decides correctly, but leaves the root populated after a rejection.
  slow             sleeps past the outer deadline, so the oracle's own timeout is shown
                   to bite rather than being assumed.
  silent           prints nothing at all. An extractor that says nothing has decided
                   nothing, and the oracle must not read silence as a rejection.
  bloats           decides correctly and then writes far past the outer disk budget. A
                   bomb "rejected" only after filling the disk has not been rejected.
  corrupts         accepts and writes a declared file with the WRONG bytes. Accepting is
                   not enough; the tree has to be the one the manifest described.
  setuid           accepts and sets 04755 on an extracted file. The corpus rejects
                   setuid members in the archive; this is the same outcome arriving by
                   the extractor's own hand.
  nonsense         prints a decision that is none of accept, reject or crash. The oracle
                   has to report that as a finding about the SUBJECT, not fall over with
                   an error about its own vocabulary.
"""

import getopt
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))


def main(argv):
    opts, _ = getopt.getopt(argv, "", ["root=", "archive=", "limits=", "mode=",
                                       "without=", "unsafe", "unbounded"])
    root = archive = None
    limits, mode = {}, "always-accept"
    for key, value in opts:
        if key == "--root":
            root = value
        elif key == "--archive":
            archive = value
        elif key == "--limits":
            limits = json.loads(value)
        elif key == "--mode":
            mode = value

    if mode == "always-accept":
        pathlib.Path(root).mkdir(parents=True, exist_ok=True)
        print(json.dumps({"decision": "accept", "reason": "", "entries": 0, "bytes": 0}))
        return 0
    if mode == "always-reject":
        print(json.dumps({"decision": "reject", "rule": "always", "reason": ""}))
        return 0
    if mode == "silent":
        return 0
    if mode == "nonsense":
        print(json.dumps({"decision": "maybe", "rule": "", "reason": ""}))
        return 0
    if mode == "slow":
        time.sleep((limits.get("extraction_deadline_seconds", 60) * 2) + 30)
        print(json.dumps({"decision": "reject", "rule": "eventually", "reason": ""}))
        return 0

    # The remaining modes borrow the guarded extractor's decisions on purpose: the point
    # is an extractor whose VERDICTS are perfect and whose behaviour is not, which is the
    # case a decision-only oracle would pass.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "disposable", pathlib.Path(__file__).resolve().parent / "disposable_extractor.py")
    disposable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(disposable)

    try:
        verdict = disposable.Extractor(root, archive, {**disposable.DEFAULT_LIMITS,
                                                       **limits}, []).run()
    except disposable.Reject as r:
        verdict = {"decision": "reject", "rule": r.rule, "reason": r.detail}
    except Exception as e:
        verdict = {"decision": "crash", "rule": type(e).__name__, "reason": str(e)[:200]}

    if mode in ("corrupts", "setuid") and verdict["decision"] == "accept":
        declared = json.loads((pathlib.Path(root) / "manifest.json").read_bytes())
        target = pathlib.Path(root) / declared["files"][0]["path"]
        if mode == "corrupts":
            target.write_bytes(b"not what the manifest declared\n")
        else:
            os.chmod(target, 0o4755)
    elif mode == "bloats":
        blob = pathlib.Path(root) / "bloat.bin"
        blob.parent.mkdir(parents=True, exist_ok=True)
        with open(blob, "wb") as fh:
            for _ in range(64):
                fh.write(b"\0" * (1 << 20))
    elif mode == "escapes":
        outside = pathlib.Path(root).parent / "escape.txt"
        try:
            outside.write_bytes(b"planted by the degenerate extractor\n")
        except OSError:
            pass
    elif mode == "residue" and verdict["decision"] == "reject":
        leftover = pathlib.Path(root) / "leftover.tmp"
        leftover.parent.mkdir(parents=True, exist_ok=True)
        leftover.write_bytes(b"not cleaned up\n")

    verdict["mode"] = mode
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
