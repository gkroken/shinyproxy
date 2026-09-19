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
        <number> review cycles" claim attached to it. Every such claim is located
        independently, and one this tool did not pair with a range is reported as
        UNCHECKED rather than passed over; a number word it cannot read is reported
        too. Three spellings have already slipped a pattern that merely matched one
        shape -- `a`..`b`, then a comma for a parenthesis, then a hyphenated number
        word -- so coverage is asserted rather than enumerated. The span is what
        `Across\s+([\w-]+)\s+review\s+cycles` reaches: rephrase that lead-in and the
        claim is invisible again, which is a limit of the pattern and not a
        property the assertion can rescue.
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
the reports are absent, when they contain no finding at all, or when the default
document set yields zero of ANY of the three kinds it looks for -- citations,
ranges, count claims. Per-kind, because a surviving range vouching for a CITE
pattern that had quietly stopped matching is exactly the silence this guards
against. A document named explicitly on the command line is held only to
"something was examined", since it carries no promise about what it contains.
Findings are reported before any of that, so a vacuity guard can never pre-empt
a real one. Run it before committing anything that cites a finding ID.

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
# A count claim paired with the range that should support it. The separator is
# deliberately loose, but looseness is NOT the guarantee -- LOOSE_COUNT below finds
# every count claim however it is written, and any claim this pattern did not pair
# with a range is reported as unchecked. Widening an alternation is what failed
# twice already (`a`..`b`, then a comma for a paren); asserting coverage is the fix,
# in the shape 6024d51 used for the oracle matrix.
COUNTED_RANGE = re.compile(
    r"Across\s+([\w-]+)\s+review\s+cycles\b[\s(,:-]*" + _H + r"\.\." + _H, re.S)
# Every count claim, paired or not. `[\w-]`, not `\w`: the hyphen matters, because
# `\w` excluded it and "Across twenty-one review cycles" therefore matched NEITHER
# pattern -- so the claim was not mis-parsed, it ceased to exist, and a count of
# twenty-one against a range of twenty passed in silence (b16b1e4-F1). This series
# stands at seventeen cycles, so the next number that breaks it is the next one it
# reaches. An unrecognised word is a loud failure below; being unseen is not.
LOOSE_COUNT = re.compile(r"Across\s+([\w-]+)\s+review\s+cycles\b")

# "**46 tests** in that package" -- a count of @Test methods, which is derivable and has
# now been wrong three times in this document (7bd7d18-F2, a0d3ce1-F2, 525199b-F1). The
# package it refers to is named in the same entry, so the claim carries its own subject.
TEST_COUNT = re.compile(r"\*\*(\d+) tests\*\* in (?:that|the) package")
# Which package: the last `publisher/<name>/` path mentioned before the claim.
PACKAGE = re.compile(r"`publisher/([a-z]+)/`")


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

    n_counts = 0
    paired = set()
    for m in COUNTED_RANGE.finditer(text):
        paired.add(m.start())
        word, a, b = m.group(1), m.group(2), m.group(3)
        n_counts += 1
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

    # "N tests" claims, counted from the tree rather than trusted.
    for m in TEST_COUNT.finditer(text):
        n_counts += 1
        claimed = int(m.group(1))
        packages = PACKAGE.findall(text[:m.start()])
        if not packages:
            failures.append(f"{path.name}: '**{claimed} tests** in that package' names no "
                            f"`publisher/<name>/` package before it, so nothing says what "
                            f"to count")
            continue
        pkg = packages[-1]
        root = REPO / "src/test/java/eu/openanalytics/shinyproxy/publisher" / pkg
        if not root.is_dir():
            failures.append(f"{path.name}: '**{claimed} tests**' refers to package "
                            f"{pkg!r}, which has no test directory")
            continue
        actual = sum(f.read_text(encoding="utf-8", errors="replace").count("@Test")
                     for f in root.glob("*.java"))
        if actual != claimed:
            failures.append(f"{path.name}: '**{claimed} tests** in that package' -- "
                            f"{pkg} actually has {actual} @Test methods")
        else:
            print(f"  ok   {path.name}: {claimed} tests in publisher/{pkg}")

    # Coverage, not enumeration: a count claim this checker did not pair with a
    # range is an UNCHECKED claim, and must fail rather than pass in silence.
    for m in LOOSE_COUNT.finditer(text):
        if m.start() not in paired:
            n_counts += 1
            failures.append(f"{path.name}: 'Across {m.group(1)} review cycles' at "
                            f"offset {m.start()} -- count claim NOT CHECKED: no "
                            f"`a..b` range follows it, so nothing verified the number")

    return len(set(cites)), len(set(ranges)), n_counts


def _reviewed_commit():
    """A commit that HAS a review report, so the header branch is reachable.

    The self-test must not key on HEAD: at commit time HEAD has no report (the
    report is written after the commit), so the case falls to the missing-report
    branch; once reviewed, the same case reaches the header branch instead. A test
    that silently changes which branch it exercises depending on when it runs is
    how f1078e5-F1 happened.
    """
    for f in sorted(REVIEWS.glob("*-done.txt")):
        h = f.name[:-len("-done.txt")]
        rc, _, _ = git("merge-base", "--is-ancestor", h, "HEAD")
        if rc == 0 and re.search(r"^[0-9a-f]{7}-F\d+", f.read_text(errors="replace"), re.M):
            return h
    return None


def _unreviewed_ancestor():
    """A commit with no review report, for the missing-report branch."""
    rc, out, _ = git("log", "--format=%H", "-400", "HEAD")
    for h in out.split():
        if not (REVIEWS / f"{h}-done.txt").exists():
            return h
    return None


def self_test():
    """A green run proves nothing unless a wrong citation turns it red.

    Every case asserts WHICH check fired, not merely that something did. Asserting
    only "it was caught" is what let the finding-header check go uncovered while the
    self-test reported four of four: the case was being caught two branches earlier
    (f1078e5-F1).
    """
    import tempfile
    print("== self-test: each case must be reported FOR THE STATED REASON ==")

    reviewed = _reviewed_commit()
    unreviewed = _unreviewed_ancestor()
    if reviewed is None:
        print("ERROR: no reviewed ancestor with a parseable finding; the "
              "finding-header branch cannot be exercised.", file=sys.stderr)
        return 2
    if unreviewed is None:
        print("ERROR: every recent commit has a report; the missing-report branch "
              "cannot be exercised.", file=sys.stderr)
        return 2

    cases = [
        ("a finding number that does not exist, on a REVIEWED commit",
         f"see `{reviewed[:7]}-F99` for this",
         "not a finding in"),
        ("a citation on a commit with no review report",
         f"see `{unreviewed[:7]}-F1` for this",
         "no review report"),
        ("a hash that does not resolve",
         "see `deadbee-F1` for this",
         "hash does not resolve"),
        ("a contradicted count, paren form",
         "Across three review cycles (`3f8bdd2..2124414`, ten of them CR)",
         "that range is 17 commits, not 3"),
        # Regression: the first draft matched only `a..b` and so passed a0d3ce1's
        # text verbatim -- the one text it existed to reject.
        ("a contradicted count, each hash separately backticked (a0d3ce1's spelling)",
         "Across seventeen review cycles (`29857f7`..`2124414`, ten of them CR)",
         "that range is 16 commits, not 17"),
        # Regression: f1078e5-F2, a comma where the pattern wanted a parenthesis.
        ("a contradicted count, comma instead of a paren",
         "Across seventeen review cycles, `29857f7..2124414`, ten of them CR.",
         "that range is 16 commits, not 17"),
        # The coverage assertion: a count claim with no range at all must FAIL,
        # because nothing verified it. This is the case that makes rewording safe.
        ("a count claim with no range following it at all",
         "Across nineteen review cycles the reviewer found things.",
         "count claim NOT CHECKED"),
        # 525199b-F1: a test count in the durable record, wrong, beside a number that was
        # right -- which is what makes a reader trust it.
        ("a wrong test count for a real package",
         "See `publisher/storage/`. **999 tests** in that package.",
         "actually has"),
        ("a test count naming no package",
         "**12 tests** in that package, somewhere.",
         "names no"),
        # Regression: b16b1e4-F1. `\w` excluded the hyphen, so this matched neither
        # pattern and twenty-one-against-twenty passed silently.
        ("a hyphenated number word, which must at least be SEEN",
         "Across twenty-one review cycles (`a6615c1..b16b1e4`, all reviewed).",
         "unrecognised number word"),
    ]

    bad = []
    for label, body, expect in cases:
        with tempfile.NamedTemporaryFile("w", suffix=".md", dir=REPO,
                                         delete=False, encoding="utf-8") as fh:
            fh.write(body + "\n")
            tmp = Path(fh.name)
        try:
            f = []
            check_doc(tmp, f)
            if not f:
                print(f"  FAIL not caught at all: {label}")
                bad.append(label)
            elif not any(expect in line for line in f):
                print(f"  FAIL caught for the WRONG REASON: {label}")
                print(f"         expected to contain: {expect!r}")
                for line in f:
                    print(f"         got: {line}")
                bad.append(label)
            else:
                print(f"  ok   caught, for the stated reason: {label}")
        finally:
            tmp.unlink()

    if bad:
        print(f"\nRESULT: self-test FAILED, {len(bad)} of {len(cases)} case(s) "
              f"not caught for their stated reason")
        return 1
    print(f"\nRESULT: self-test passed -- all {len(cases)} cases fail for the "
          f"reason claimed, so each branch is genuinely covered")
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

    explicit = [Path(a) for a in argv if not a.startswith("-")]
    docs = explicit or [REPO / d for d in DEFAULT_DOCS]
    docs = [d if d.is_absolute() else REPO / d for d in docs]

    print(f"== finding citations, against {n_reports} review reports ==")
    failures, total_cites, total_ranges, total_counts = [], 0, 0, 0
    checked = 0
    for d in docs:
        if not d.exists():
            continue
        checked += 1
        c, r, n = check_doc(d, failures)
        total_cites += c
        total_ranges += r
        total_counts += n

    if checked == 0:
        print("ERROR: none of the named documents exist.", file=sys.stderr)
        return 2
    print(f"\n{total_cites} finding citations, {total_ranges} ranges, "
          f"{total_counts} count claims, {checked} document(s)")

    # Findings first. A vacuity guard that pre-empts a real finding hides the very
    # thing the run was for -- the first draft of this fix did exactly that, turning
    # the comma-form probe from "BAD, 16 not seventeen" into a bare exit 2.
    if failures:
        print(f"\nRESULT: {len(failures)} bad citation(s)")
        for f in failures:
            print(f"  BAD  {f}")
        return 1

    # Only now, and only for the default set: `or` would let one surviving range
    # vouch for a CITE pattern that had silently stopped matching (f1078e5-F3).
    # The workplans are known to carry all three kinds, so a zero there means the
    # pattern broke. An explicitly named document carries no such promise, so it is
    # held only to "something was examined".
    if explicit:
        if total_cites + total_ranges + total_counts == 0:
            print(f"ERROR: {checked} named document(s) yielded no citation, range or "
                  f"count claim.\n       Refusing to report success for a set that was "
                  f"not examined.", file=sys.stderr)
            return 2
    else:
        empty = [name for name, n in (("finding citations", total_cites),
                                      ("ranges", total_ranges),
                                      ("count claims", total_counts)) if n == 0]
        if empty:
            print(f"ERROR: {checked} document(s) read and NOT ONE of: "
                  f"{', '.join(empty)}.\n       The workplans carry all three kinds, so a "
                  f"zero means the pattern broke\n       (or the last such claim was "
                  f"removed, in which case update this guard deliberately).\n       "
                  f"Refusing to report success for a set that was not examined.",
                  file=sys.stderr)
            return 2
    # Name what was actually examined. "Everything is fine" is not a result.
    print(f"RESULT: {total_cites} cited finding IDs exist in the reports they name; "
          f"{total_counts} count claim(s) checked against {total_ranges} range(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
