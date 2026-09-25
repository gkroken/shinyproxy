#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Reads strace output of the extractor and says whether it touched a traversal target.

WORKPLAN-BUNDLES.md T5 (deferred from T2): syscall tracing for "no reads outside the root".
The corpus oracle already proves, with snapshots, that nothing outside the root CHANGED.
A snapshot cannot see a read, or an attempt that failed, and the atime regime on this host
does not record reads reliably (the oracle says so when it runs). A trace can.

**What counts as touching.** Any path the extractor named in a path-taking system call, or
that a descriptor it used refers to, that is one of the corpus's traversal targets:

    <world>/escape.txt  <world>/pax-escape.txt  <world>/neighbour[/...]
    <world>/via-symlink-target[/...]
    /etc/skald-escape.txt  /etc/passwd  /tmp/escape.txt

-- every destination the corpus's traversal and link fixtures aim at. The list is read from
dev/bundle_sentinels.py (WORLD_ESCAPE_TARGETS, ABSOLUTE_ESCAPE_TARGETS), the table the
oracle documents them in; this file used to keep its own shorter copy and missed the last
two (finding f352115-F1: a mutation that stat'ed /tmp/escape.txt in every extraction
passed both the oracle and this check).

**One exception, and exactly one.** The JVM reads /etc/passwd at startup to look up its
user: `openat(AT_FDCWD</ws>, "/etc/passwd", O_RDONLY|O_CLOEXEC)`, once, in every trace.
That exact line is allowed ONCE per trace. Any other appearance of /etc/passwd is a
touch: as a link or rename argument, reached through a descriptor, opened any other way,
or a second read in the same form. What this cannot tell apart is an extractor that reads
/etc/passwd once in precisely the JVM's form INSTEAD of the JVM doing so -- the traces
are identical. It is stated rather than papered over; the link fixtures, which are what
aim at /etc/passwd, are refused on their headers and name it nowhere. An
attempt counts even if the kernel refused it: a traversal the extractor tried and the
filesystem happened to stop is still a traversal. Paths are resolved lexically, which is
deliberately conservative -- "../escape.txt" relative to a directory in the root is
reported whether or not the kernel would have followed it.

**How a path is resolved.** The extractor works through descriptors, and strace -y prints
each descriptor with what it refers to, so `openat(5</work/w003/root>, "app.R", ...)`
resolves to /work/w003/root/app.R. A path given with no descriptor (AT_FDCWD, or a plain
open/stat) is resolved against the working directory the adapter recorded beside the
trace. A trace with no recorded working directory, or one that shows chdir or fchdir, is
refused rather than resolved by guesswork.

**What it does not cover, stated rather than implied.** Listing a directory (getdents)
takes no path and is not a %file call, so it is not seen; listing the world directory
would reveal the targets' NAMES without touching them. Nor are open_by_handle_at (opens
by handle, no path) or io_uring submissions; the JVM uses neither. /tmp itself is not a
target -- the JVM probes /tmp/.java_pid<N> -- only /tmp/escape.txt is; the oracle's
sentinel over /tmp covers anything that changes there. Reads through a descriptor are
covered only in that the descriptor had to be opened by a path first, which is seen.

**Positive controls, because a check that sees nothing passes everything.** Every trace
must be non-empty and must show at least one descriptor-relative call resolved inside its
own world directory -- the adapter opens the root through its parent's descriptor, so a
trace without one means -y is not doing its job. The number of traces must equal the
number of extractions the caller expected. And `--self-test` makes real traces, with the
same strace flags as the extractor's (skald_extractor.prepare_trace), of small programs
that touch each target in each way, and requires every one to be caught -- and a control
that touches only the root not to be.

Usage: trace-check.py DIR --expect N [--world-base /work]
       trace-check.py --self-test          (needs strace; run in dev/oracle-java-trace)
"""

import importlib.util
import os
import pathlib
import posixpath
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from bundle_sentinels import ABSOLUTE_ESCAPE_TARGETS, WORLD_ESCAPE_TARGETS  # noqa: E402

# The JVM's own startup read of /etc/passwd, allowed once per trace; see the docstring.
STARTUP_PASSWD = re.compile(r'^\d+ +openat\(AT_FDCWD(?:<[^>]*>)?, "/etc/passwd", '
                            r'O_RDONLY\|O_CLOEXEC\) = (?:\d+</etc/passwd>|-1 .*)$')

# A descriptor with its path, then a string argument: the descriptor-relative form.
DIRFD_NAME = re.compile(r'(\d+)<(/[^>]*)>, "((?:[^"\\]|\\.)*)"')
# AT_FDCWD, or a path-taking call whose first argument is the string. Under -y strace
# annotates AT_FDCWD too -- `AT_FDCWD</ws>` -- which the first version of this pattern did
# not allow for, so it matched nothing and an absolute path passed without a descriptor
# went unseen. The self-test's /etc/skald-escape.txt case is what caught it.
CWD_NAME = re.compile(r'(?:AT_FDCWD(?:<([^>]*)>)?, |^\d+ +[a-z0-9_]+\()"((?:[^"\\]|\\.)*)"')
# Every descriptor annotation, including return values: `= 6</work/w003/root/app.R>`.
ANNOTATION = re.compile(r'\d+<(/[^>]*)>')
# Any absolute path string anywhere in the call -- a symlink's target, a second name --
# whatever position it is in. Conservative: named is enough.
ABSOLUTE_STRING = re.compile(r'"(/(?:[^"\\]|\\.)*)"')
# execve's argument vector is strings, not accesses: the JVM is started with
# "--root /work/w003/root" and naming that is not touching it. Only its program path counts.
EXECVE = re.compile(r'^\d+ +execve(?:at)?\(')
CHDIR = re.compile(r'^\d+ +f?chdir\(')


def unescape(s):
    return s.encode().decode("unicode_escape", errors="replace")


def targets_for(base):
    world = re.escape(base.rstrip("/")) + r"/w\d+/"
    names = "|".join(re.escape(n) for n in WORLD_ESCAPE_TARGETS)
    return re.compile(r"^(?:%s(?:%s)(?:/.*)?|%s)$" % (
        world, names, "|".join(re.escape(p) for p in ABSOLUTE_ESCAPE_TARGETS)))


def check_trace(path, base):
    """Returns (problems, resolved_in_world, named_world) for one trace file."""
    problems = []
    target = targets_for(base)
    world_dir = re.compile(r"^%s/w\d+(?:/.*)?$" % re.escape(base.rstrip("/")))
    cwd_file = pathlib.Path(str(path) + ".cwd")
    if not cwd_file.is_file():
        return (["no recorded working directory; relative paths cannot be resolved"],
                False, False)
    cwd = cwd_file.read_text().strip()
    text = pathlib.Path(path).read_text(errors="replace")
    if not text.strip():
        return ["the trace is empty"], False, False
    resolved_in_world = named_world = False
    startup_passwd_seen = False
    for line in text.splitlines():
        if STARTUP_PASSWD.match(line) and not startup_passwd_seen:
            startup_passwd_seen = True
            continue
        if CHDIR.match(line):
            problems.append("the working directory changed, so relative paths are not "
                            "resolvable: " + line[:160])
            continue
        paths = []
        for _fd, directory, name in DIRFD_NAME.findall(line):
            name = unescape(name)
            joined = posixpath.normpath(name if name.startswith("/")
                                        else posixpath.join(directory, name))
            paths.append(joined)
            if world_dir.match(directory):
                resolved_in_world = True
        for annotated_cwd, name in CWD_NAME.findall(line):
            name = unescape(name)
            paths.append(posixpath.normpath(name if name.startswith("/") else
                                            posixpath.join(annotated_cwd or cwd, name)))
        paths += [posixpath.normpath(p) for p in ANNOTATION.findall(line)]
        if EXECVE.match(line):
            paths = paths[:1]
        else:
            paths += [posixpath.normpath(unescape(p))
                      for p in ABSOLUTE_STRING.findall(line)]
        # Two patterns can name the same string (AT_FDCWD's, and any absolute string);
        # one touch is one problem.
        for p in dict.fromkeys(paths):
            if world_dir.match(p):
                named_world = True
            if target.match(p):
                problems.append("%s <- %s" % (p, line.strip()[:200]))
    return problems, resolved_in_world, named_world


def check_directory(directory, expect, base):
    traces = sorted(pathlib.Path(directory).glob("*.strace"))
    failures = 0
    print("== tracing: %d trace(s), %d extraction(s) expected ==" % (len(traces), expect))
    if len(traces) != expect:
        print("  FAIL %d traces for %d extractions: some ran untraced, or twice"
              % (len(traces), expect))
        failures += 1
    touched = resolved_count = unopened = 0
    for trace in traces:
        problems, resolved, named = check_trace(trace, base)
        resolved_count += resolved
        if not named:
            # Refused before the root was opened -- the adapter checks the upload's size
            # first -- so the world was never named at all. Honest, and counted.
            unopened += 1
        elif not resolved:
            # It named the world (the adapter opens the root's parent by absolute path)
            # but no descriptor-relative call resolved there: -y is not working, and
            # nothing in this trace says where the extractor's descriptors pointed.
            problems.append("the world was named but no descriptor-relative call resolved "
                            "inside it, so this trace proves nothing about where the "
                            "extractor went")
        if problems:
            failures += 1
            touched += 1
            print("  FAIL %s" % trace.name)
            for p in problems[:5]:
                print("         %s" % p)
    if traces and not resolved_count:
        print("  FAIL not one trace resolved a descriptor inside its world")
        failures += 1
    lines = sum(1 for t in traces for _ in open(t, errors="replace"))
    print("  %d trace(s) clean, %d not; %d resolved descriptors inside their world, %d "
          "refused before opening the root; %d traced calls read" %
          (len(traces) - touched, touched, resolved_count, unopened, lines))
    print()
    print("RESULT:", "no extraction touched a traversal target" if not failures
          else "%d problem(s)" % failures)
    return 0 if not failures else 1


# ------------------------------------------------------------------ self-test

# Each is a small program that touches one target one way. All of them must be caught.
# They run with the world directory as argv[1].
TOUCHES = {
    "escape.txt through the world's descriptor":
        "import os,sys; d=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY);"
        "os.stat('escape.txt', dir_fd=d)",
    "pax-escape.txt opened through the world's descriptor":
        "import os,sys; d=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY);"
        "os.close(os.open('pax-escape.txt', os.O_RDONLY, dir_fd=d))",
    "neighbour/keep.txt through the world's descriptor":
        "import os,sys; d=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY);"
        "os.close(os.open('neighbour/keep.txt', os.O_RDONLY, dir_fd=d))",
    "via-symlink-target by absolute path":
        "import os,sys; os.listdir(os.path.join(sys.argv[1], 'via-symlink-target'))",
    "/etc/skald-escape.txt, which does not exist":
        "import os\ntry: os.stat('/etc/skald-escape.txt')\nexcept OSError: pass",
    "../escape.txt from inside the root":
        "import os,sys; d=os.open(os.path.join(sys.argv[1], 'root'), "
        "os.O_RDONLY|os.O_DIRECTORY)\ntry: os.open('../escape.txt', os.O_RDONLY, dir_fd=d)\n"
        "except OSError: pass",
    "/tmp/escape.txt by absolute path":
        "import os\ntry: os.stat('/tmp/escape.txt')\nexcept OSError: pass",
    "/etc/passwd as a symlink's target, created in the root":
        "import os,sys; d=os.open(os.path.join(sys.argv[1], 'root'), "
        "os.O_RDONLY|os.O_DIRECTORY); os.symlink('/etc/passwd', 'x', dir_fd=d)",
    "/etc/passwd read a second time, in the JVM's own form":
        "open('/etc/passwd').close(); open('/etc/passwd').close()",
    "a chdir, after which relative paths cannot be judged":
        "import os,sys; os.chdir(sys.argv[1]); open('root/x', 'w').close()",
}
# The control: what the extractor does -- the parent's descriptor, then the root, then a
# file in it -- plus one read of /etc/passwd in the JVM's startup form, the one exception.
# Must be clean, and must satisfy the positive control.
CONTROL = ("import os,sys; d=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY);"
           "r=os.open('root', os.O_RDONLY|os.O_DIRECTORY, dir_fd=d);"
           "os.close(os.open('app.R', os.O_WRONLY|os.O_CREAT, 0o600, dir_fd=r));"
           "open('/etc/passwd').close()")


def self_test():
    spec = importlib.util.spec_from_file_location(
        "skald_extractor", HERE / "fixtures/bundles/skald_extractor.py")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    sys.path.insert(0, str(HERE))
    from bundle_sentinels import World

    base = tempfile.mkdtemp(prefix="skald-trace-selftest-")
    missed = []
    print("== self-test: every touch must be caught, the control must not be ==")
    cases = list(TOUCHES.items()) + [("control", CONTROL)]
    for i, (label, program) in enumerate(cases):
        world = World(os.path.join(base, "w%03d" % i))
        out = os.path.join(base, "case%d.strace" % i)
        argv = adapter.prepare_trace(out) + [sys.executable, "-c", program, str(world.path)]
        subprocess.run(argv, check=False)
        problems, resolved, _ = check_trace(out, base)
        if label == "control":
            ok = not problems and resolved
            print("  %-4s control: clean and resolved inside its world%s" % (
                "ok" if ok else "FAIL",
                "" if ok else " -- problems %s, resolved %s" % (problems[:2], resolved)))
        else:
            ok = bool(problems)
            print("  %-4s caught: %s" % ("ok" if ok else "FAIL", label))
        if not ok:
            missed.append(label)

    # The positive control must be able to fail too: the same control, traced WITHOUT -y,
    # names the world by path but resolves no descriptor, and must be refused.
    world = World(os.path.join(base, "w%03d" % len(cases)))
    out = os.path.join(base, "no-y.strace")
    argv = [a for a in adapter.prepare_trace(out) if a != "-y"]
    subprocess.run(argv + [sys.executable, "-c", CONTROL, str(world.path)], check=False)
    _, resolved, named = check_trace(out, base)
    ok = named and not resolved
    print("  %-4s caught: a trace made without -y (named the world, resolved nothing)"
          % ("ok" if ok else "FAIL"))
    if not ok:
        missed.append("trace without -y")
    print()
    print("RESULT:", "self-test passed" if not missed
          else "self-test FAILED: %s" % "; ".join(missed))
    return 0 if not missed else 1


def main(argv):
    if "--self-test" in argv:
        return self_test()
    base = argv[argv.index("--world-base") + 1] if "--world-base" in argv else "/work"
    if "--expect" not in argv or not argv or argv[0].startswith("--"):
        print(__doc__.strip().splitlines()[-2])
        return 2
    return check_directory(argv[0], int(argv[argv.index("--expect") + 1]), base)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
