#!/usr/bin/env python3
"""Check that every review-finding ID cited in a tracked document exists.

WORKPLAN-BUNDLES.md argues for itself by citing finding IDs: "the IDs are here
rather than a bare count because this paragraph's whole authority is that its
numbers are checkable". Three commits running, they were not. 7bd7d18-F2 was a
miscount; a0d3ce1-F1/F2/F3 were three citations that did not support the claims
attached to them -- an oracle finding attributed to a commit predating the
oracle, a git range off by one commit, and a finding ID off by one with the
wrong task attached.

What this checks, and what it cannot:

  CAN   the cited hash resolves, is an ancestor of HEAD, has a review report,
        and that report contains that finding ID as a finding header.
  CAN   a cited `a..b` range resolves and the commit count matches any "Across
        <number> review cycles" claim attached to it.
  CANNOT  that the finding *says* what the sentence claims it says. Measured
        against the three defects that prompted this: it catches a0d3ce1-F2 (the
        range count) and MISSES a0d3ce1-F1 and -F3, because both cite a real
        finding ID that exists in the report it names and attach it to the wrong
        claim -- an oracle finding blamed on a commit predating the oracle, and a
        T1f finding presented as T2 evidence. No string check reaches those; only
        a reader does. This narrows the class, it does not close it, and anyone
        reporting a green here should say so in those terms.

Vacuity: the review reports live in code_review/, which is reviewer-owned and
untracked, so this cannot be wired into a tracked suite that must pass on a
fresh clone. It is a pre-commit tool, and it EXITS 2 rather than passing when
the reports are absent or when a document yields no citations at all -- a
citation checker that silently finds nothing to check is the defect it exists
to catch. Run it before committing anything that cites a finding ID.

Usage:  python3 dev/check-citations.py [doc ...]        (default: the workplans)
        python3 dev/check-citations.py --self-test      (proves it can fail)
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REVIEWS = REPO / "code_review"
DEFAULT_DOCS = ["WORKPLAN-BUNDLES.md", "WORKPLAN.md", "WORKPLAN-REGISTRY.md",
                "WORKPLAN-DEVSTACK.md"]

# `<hash7+>-F<n>`, the finding-ID form every report uses.
CITE = re.compile(r"`([0-9a-f]{7,40})-(F\d+)`")
# A git range, in BOTH the forms these documents use: `a..b` and `a`..`b`.
# Matching only the first form is how the checker's own first draft passed the
# very text it was written to reject -- a0d3ce1 wrote `29857f7`..`2124414`.
_H = r"`?([0-9a-f]{7,40})`?"
RANGE = re.compile(_H + r"\.\." + _H)
# "Across seventeen review cycles (`a..b`" -- the count and the range together.
WORDS = {"three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
         "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
         "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
         "eighteen": 18, "nineteen": 19, "twenty": 20}
COUNTED_RANGE = re.compile(
    r"Across (\w+)\s+review\s+cycles\s+\(" + _H + r"\.\." + _H, re.S)


def git(*args):
    r = subprocess.run(("git",) + args, cwd=REPO, capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def report_for(full_hash):
    p = REVIEWS / f"{full_hash}-done.txt"
    return p if p.exists() else None


def check_doc(path, failures):
    text = path.read_text(encoding="utf-8")
    cites = CITE.findall(text)
    ranges = RANGE.findall(text)

    for short, fid in sorted(set(cites)):
        rc, full, _ = git("rev-parse", "--verify", f"{short}^{{commit}}")
        if rc != 0:
            failures.append(f"{path.name}: `{short}-{fid}` -- hash does not resolve")
            continue
        rc, _, _ = git("merge-base", "--is-ancestor", full, "HEAD")
        if rc != 0:
            failures.append(f"{path.name}: `{short}-{fid}` -- {short} is not an "
                            f"ancestor of HEAD")
            continue
        rpt = report_for(full)
        if rpt is None:
            failures.append(f"{path.name}: `{short}-{fid}` -- no review report "
                            f"{full[:7]}-done.txt")
            continue
        body = rpt.read_text(encoding="utf-8", errors="replace")
        # The report writes a finding as a header at column 0.
        if not re.search(rf"^{re.escape(short)}-{fid}\b", body, re.M):
            have = sorted(set(re.findall(rf"^{re.escape(short)}-(F\d+)\b", body, re.M)))
            failures.append(f"{path.name}: `{short}-{fid}` -- not a finding in "
                            f"{full[:7]}-done.txt (it has: "
                            f"{', '.join(have) if have else 'none'})")
        else:
            print(f"  ok   {path.name}: {short}-{fid}")

    for a, b in sorted(set(ranges)):
        rc, out, err = git("rev-list", "--count", f"{a}..{b}")
        if rc != 0:
            failures.append(f"{path.name}: range `{a}..{b}` does not resolve ({err})")
        else:
            print(f"  ok   {path.name}: range {a}..{b} = {out} commits")

    for word, a, b in COUNTED_RANGE.findall(text):
        claimed = WORDS.get(word.lower())
        if claimed is None:
            failures.append(f"{path.name}: 'Across {word} review cycles' -- "
                            f"unrecognised number word, cannot check")
            continue
        rc, out, _ = git("rev-list", "--count", f"{a}..{b}")
        if rc != 0:
            continue  # already reported by the range pass
        if int(out) != claimed:
            failures.append(f"{path.name}: 'Across {word} review cycles "
                            f"(`{a}..{b}`)' -- that range is {out} commits, "
                            f"not {claimed}")
        else:
            print(f"  ok   {path.name}: '{word} review cycles' == "
                  f"{out} in {a}..{b}")

    return len(set(cites)), len(set(ranges))


def self_test():
    """A green run proves nothing unless a wrong citation turns it red."""
    import tempfile
    print("== self-test: each case must be REPORTED ==")
    rc, head, _ = git("rev-parse", "HEAD")
    cases = [
        ("a finding ID that does not exist in a real report",
         f"see `{head[:7]}-F99` for this"),
        ("a hash that does not resolve",
         "see `deadbee-F1` for this"),
        ("a range whose commit count contradicts its stated number",
         "Across three review cycles (`3f8bdd2..2124414`, ten of them CR)"),
        # Regression: the first draft of this checker matched only `a..b` and so
        # passed a0d3ce1's text verbatim, which is the one text it existed to
        # reject. Both spellings are checked from here on.
        ("the same, with each hash separately backticked (a0d3ce1's spelling)",
         "Across seventeen review cycles (`29857f7`..`2124414`, ten of them CR)"),
    ]
    bad = []
    for label, body in cases:
        with tempfile.NamedTemporaryFile("w", suffix=".md", dir=REPO,
                                         delete=False, encoding="utf-8") as fh:
            fh.write(body + "\n")
            tmp = Path(fh.name)
        try:
            f = []
            check_doc(tmp, f)
            if f:
                print(f"  ok   caught: {label}")
                for line in f:
                    print(f"         -> {line}")
            else:
                print(f"  FAIL not caught: {label}")
                bad.append(label)
        finally:
            tmp.unlink()
    if bad:
        print(f"\nRESULT: self-test FAILED, {len(bad)} case(s) not caught")
        return 1
    print("\nRESULT: self-test passed -- the checker can fail")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    if not REVIEWS.is_dir():
        print(f"ERROR: {REVIEWS} does not exist. The review reports are what this "
              f"checks against;\n       without them every citation would be "
              f"'unverified' and this would pass vacuously.", file=sys.stderr)
        return 2
    n_reports = len(list(REVIEWS.glob("*-done.txt")))
    if n_reports == 0:
        print(f"ERROR: no *-done.txt review reports in {REVIEWS}. Refusing to "
              f"report success\n       with nothing to check against.", file=sys.stderr)
        return 2

    docs = [Path(a) for a in argv if not a.startswith("-")] or \
           [REPO / d for d in DEFAULT_DOCS]
    docs = [d if d.is_absolute() else REPO / d for d in docs]

    print(f"== finding citations, against {n_reports} review reports ==")
    failures, total_cites, total_ranges = [], 0, 0
    checked = 0
    for d in docs:
        if not d.exists():
            continue
        checked += 1
        c, r = check_doc(d, failures)
        total_cites += c
        total_ranges += r

    if checked == 0:
        print("ERROR: none of the named documents exist.", file=sys.stderr)
        return 2
    if total_cites == 0 and total_ranges == 0:
        print(f"ERROR: {checked} document(s) read and NOT ONE citation or range "
              f"found.\n       The citation patterns have almost certainly broken; "
              f"refusing to pass.", file=sys.stderr)
        return 2

    print(f"\n{total_cites} finding citations, {total_ranges} ranges, "
          f"{checked} document(s)")
    if failures:
        print(f"\nRESULT: {len(failures)} bad citation(s)")
        for f in failures:
            print(f"  BAD  {f}")
        return 1
    print("RESULT: every cited finding ID exists in the report it names")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
