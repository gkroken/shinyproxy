#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Outside-root sentinels for the bundle corpus (WORKPLAN-BUNDLES.md T2b).

The corpus says which archives must be rejected. This says what "rejected" has to mean
beyond a return code: that nothing outside the extraction root was created, overwritten,
deleted, re-moded or retargeted while the extractor was refusing.

Written before the extractor and independent of it, like the corpus: standard library
only, no import of any Skald class. It knows nothing about extraction -- it takes a
picture of the world, lets somebody else run, and takes another picture.

Three things it must not be, because each would make it look like it works:

  1. A check that cannot fail. Every sentinel path is one the corpus actually names, and
     the self-test below proves the harness can create, modify, delete and retarget each
     protected target itself. A sentinel over a read-only directory reports "unchanged"
     forever and says nothing.
  2. A snapshot that silently stops. Walks are bounded, and hitting a bound is an error,
     not a shorter snapshot.
  3. A claim to detect reads. It cannot, reliably: atime depends on mount options. The
     harness measures whether atime moves on this filesystem and says so, rather than
     reporting "no reads" from a clock that never ticks.

Named with underscores, unlike the other dev scripts, because the oracle imports it:
it is a module as well as a command.

Usage:
    python3 dev/bundle_sentinels.py --self-test        # prove the harness can fail
    python3 dev/bundle_sentinels.py --describe <dir>   # build a world, print its layout
"""

import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys
import time

# Every escape target the corpus names, which is the only reason any of these is here.
# Relative escapes land one level above the extraction root (a member called
# "app/../../escape.txt" resolves to <root>/../escape.txt once "app/" is the payload
# root), and the absolute ones are written out in full by the traversal and link fixtures.
#
#   trav-dotdot, trav-embedded        <world>/escape.txt
#   trav-pax-override                 <world>/pax-escape.txt
#   trav-absolute                     /etc/skald-escape.txt
#   link-symlink-file, link-hardlink-outside, link-chained   /etc/passwd
#   link-symlink-dir-then-child       /tmp/escape.txt via a symlink to /tmp
SENTINEL_DIRS = ("/etc", "/tmp")
SENTINEL_FILES = ("/etc/passwd",)

# A bound that is an error when hit, not a quieter snapshot.
MAX_ENTRIES = 20000
HASH_LIMIT = 4 * 1024 * 1024


class SnapshotTooLarge(Exception):
    """The walk hit its bound. Reported, never swallowed: a snapshot that stops early
    still compares equal to itself, which is the shape of a check that cannot fail."""


def _entry(path):
    """One path's observable state. Symlinks are described, never followed."""
    st = os.lstat(path)
    kind = ("dir" if stat.S_ISDIR(st.st_mode) else
            "link" if stat.S_ISLNK(st.st_mode) else
            "file" if stat.S_ISREG(st.st_mode) else "other")
    # ctime is recorded because it is the one timestamp the writer cannot set. Above
    # HASH_LIMIT there is no digest to compare, and mtime can be restored with utime --
    # which advances ctime, so the rewrite is still visible (finding 6d7b790-F1).
    rec = {"kind": kind, "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid,
           "gid": st.st_gid, "nlink": st.st_nlink, "atime_ns": st.st_atime_ns,
           "ctime_ns": st.st_ctime_ns}
    if kind == "link":
        rec["target"] = os.readlink(path)
    elif kind == "file":
        rec["size"] = st.st_size
        rec["mtime_ns"] = st.st_mtime_ns
        rec["ino"] = st.st_ino
        # Hashed when small enough to be sure. Above the bound, size+mtime+inode is what
        # is recorded, and `hashed` says so rather than implying a comparison that did
        # not happen.
        if st.st_size <= HASH_LIMIT:
            h = hashlib.sha256()
            try:
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
            except OSError as e:
                rec["unreadable"] = type(e).__name__
            else:
                rec["sha256"] = h.hexdigest()
            # Hashing IS a read, so it moves the clock reads() watches. Where it left it
            # is recorded, for the same reason the directory walk records its own effect.
            try:
                rec["atime_after_ns"] = os.lstat(path).st_atime_ns
            except OSError:
                pass
        rec["hashed"] = "sha256" in rec
    return rec


def snapshot(roots):
    """Map every path under `roots` to its observable state.

    Reading a file changes its atime, so the hash is taken and the atime recorded from
    the lstat that preceded it -- the snapshot must not be the thing that moves the clock
    it is watching. That is why _entry() lstats first and reads second, and why two
    snapshots of an untouched tree compare equal on everything except atime, which is
    compared separately and only as a hint.
    """
    out, seen = {}, 0
    for root in roots:
        root = str(root)
        if not os.path.lexists(root):
            out[root] = {"kind": "absent"}
            continue
        stack = [root]
        while stack:
            path = stack.pop()
            seen += 1
            if seen > MAX_ENTRIES:
                raise SnapshotTooLarge(
                    "more than %d entries under %s; the snapshot would be partial"
                    % (MAX_ENTRIES, ", ".join(map(str, roots))))
            try:
                rec = _entry(path)
            except OSError as e:
                rec = {"kind": "error", "error": type(e).__name__}
            out[path] = rec
            if rec["kind"] == "dir":
                try:
                    stack.extend(os.path.join(path, n) for n in os.listdir(path))
                except OSError:
                    pass
                else:
                    # Where our own listing left this directory's atime. See reads().
                    try:
                        rec["atime_after_ns"] = os.lstat(path).st_atime_ns
                    except OSError:
                        pass
    return out


def _compare(before, after, key):
    """What changed about one path, ignoring atime, which is handled separately."""
    b, a = before.get(key), after.get(key)
    if b is None:
        return "created"
    if a is None:
        return "deleted"
    if b["kind"] != a["kind"]:
        return "kind %s -> %s" % (b["kind"], a["kind"])
    fields = [f for f in ("mode", "uid", "gid", "target", "size", "sha256", "ino", "nlink")
              if f in b or f in a]
    diffs = ["%s %r -> %r" % (f, b.get(f), a.get(f)) for f in fields if b.get(f) != a.get(f)]
    if diffs:
        return ", ".join(diffs)
    # Nothing certain changed. An inode whose ctime advanced was still written to or
    # re-moded by somebody, and ctime is not settable -- restoring mtime after a
    # same-size overwrite leaves it behind. For an entry too large to hash this is the
    # only evidence there is, so it is reported as its own, weaker finding rather than
    # dropped into silence.
    if b.get("ctime_ns") != a.get("ctime_ns"):
        return ("ctime advanced (unhashed, too large to compare content)"
                if b["kind"] == "file" and not b.get("hashed")
                else "ctime advanced")
    return ""


def changes(before, after):
    """Every certain change between two snapshots, as (path, description)."""
    out = []
    for key in sorted(set(before) | set(after)):
        what = _compare(before, after, key)
        if what:
            out.append((key, what))
    return out


def reads(before, after):
    """Paths whose atime advanced: a HINT that something read them, not proof.

    relatime, noatime and lazytime all make this silent, which is why
    atime_is_observable() exists and why the caller is expected to report the answer
    alongside any claim that nothing was read.

    The baseline is the atime AFTER the earlier snapshot touched the path, not before.
    Taking the picture is itself a read -- listing a directory, hashing a file -- so
    comparing pre-access atimes reported every watched path as read by whatever ran in
    between, including nothing at all (finding 6d7b790-F2). Re-lstatting after the access
    in both snapshots does not fix it either, because the later snapshot's own access
    moves the clock again; the comparison has to be "after the earlier walk" against
    "before the later walk", which is what these two fields are.

    That removes the false positives. It does not make the signal useful under the
    default relatime mount, where our own access consumes the single update a file gets
    and a subsequent read by the subject leaves nothing behind. read_detection() measures
    which regime is in force, and a caller must report "no reads observed" only when it
    says "strictatime". Anything stronger needs a different mechanism -- tracing the
    extractor's syscalls -- which belongs with the extractor, not here.
    """
    out = []
    for key in sorted(set(before) & set(after)):
        b, a = before[key], after[key]
        base = b.get("atime_after_ns", b.get("atime_ns"))
        if base is not None and a.get("atime_ns", 0) > base:
            out.append(key)
    return out


def read_detection(where):
    """Whether reads() can see anything on this filesystem. Measured, not assumed.

    Two questions, because the first one on its own is misleading. "Does a read move
    atime?" is usually yes. The question that decides whether reads() works is "does a
    read move atime when atime is already recent?", because the snapshot itself reads
    every file it hashes and lists every directory it walks. Under the default relatime,
    the answer is no: our own picture consumes the one update, and a subject that reads
    the same file afterwards leaves no trace.

    Returns "strictatime", "relatime" or "off".
    """
    probe = pathlib.Path(where) / ".atime-probe"
    probe.write_bytes(b"x")
    os.utime(probe, ns=(0, 0))
    time.sleep(0.01)
    probe.read_bytes()
    first = os.lstat(probe).st_atime_ns
    time.sleep(0.01)
    probe.read_bytes()
    second = os.lstat(probe).st_atime_ns
    probe.unlink()
    if first == 0:
        return "off"
    return "strictatime" if second > first else "relatime"


class World:
    """A disposable filesystem to extract into, plus the things around it that must not
    move.

    Layout, and why each piece is here:

        <world>/root/               the extraction root, private (0700), empty
        <world>/escape.txt          where a relative traversal lands, pre-created so both
                                    "created" and "overwritten" are exercised
        <world>/pax-escape.txt      the same for the PAX override fixture
        <world>/via-symlink         a symlink to a real directory, so an extractor can be
                                    handed a root whose own path is a link -- the plan's
                                    "pre-existing symlinked parent/root"
        <world>/via-symlink-target/ what it points at
        <world>/neighbour/keep.txt  an ordinary sibling of the root, to catch a walk that
                                    escapes sideways rather than upward
    """

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.root = self.path / "root"
        self.path.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(mode=0o700)
        (self.path / "escape.txt").write_bytes(b"sentinel: must not be overwritten\n")
        (self.path / "pax-escape.txt").write_bytes(b"sentinel: must not be overwritten\n")
        target = self.path / "via-symlink-target"
        target.mkdir(mode=0o700)
        os.symlink(target, self.path / "via-symlink")
        neighbour = self.path / "neighbour"
        neighbour.mkdir()
        (neighbour / "keep.txt").write_bytes(b"sentinel: an ordinary sibling\n")

    def watched(self):
        """Everything a snapshot must cover: the world around the root, and the absolute
        targets the corpus names. The root itself is deliberately NOT watched -- an
        extractor is supposed to write there."""
        return [self.path / "escape.txt", self.path / "pax-escape.txt",
                self.path / "neighbour", self.path / "via-symlink",
                self.path / "via-symlink-target"] + \
               [pathlib.Path(p) for p in SENTINEL_DIRS] + \
               [pathlib.Path(p) for p in SENTINEL_FILES]

    def destroy(self):
        shutil.rmtree(self.path, ignore_errors=True)


# ------------------------------------------------------------------ the harness's own tests
#
# The plan requires a positive control for every protected target: proof that the harness
# could have created or changed the thing it reports as unchanged. Without these, a
# sentinel over a directory this process cannot write to reports success forever.

def _probe(label, fn, results):
    try:
        fn()
        results.append((label, True, ""))
    except Exception as e:
        results.append((label, False, "%s: %s" % (type(e).__name__, e)))


def self_test(base):
    import tempfile
    ok = True
    print("== sentinel harness self-test ==")

    with tempfile.TemporaryDirectory(dir=base) as tmp:
        w = World(pathlib.Path(tmp) / "world")
        watched = w.watched()

        # 1. A snapshot of an untouched world compares equal to itself.
        before = snapshot(watched)
        after = snapshot(watched)
        drift = changes(before, after)
        if drift:
            ok = False
            print("  FAIL an untouched world reports changes: %r" % (drift[:3],))
        else:
            print("  ok   an untouched world reports no changes")

        # 2. Each kind of change the harness claims to detect, performed by the harness.
        def overwrite(x):
            (x.path / "escape.txt").write_bytes(b"owned\n")

        def create(x):
            (x.path / "neighbour" / "new.txt").write_bytes(b"owned\n")

        def delete(x):
            (x.path / "neighbour" / "keep.txt").unlink()

        def remode(x):
            os.chmod(x.path / "pax-escape.txt", 0o777)

        def retarget(x):
            os.remove(x.path / "via-symlink")
            os.symlink("/tmp", x.path / "via-symlink")

        def swap_kind(x):
            (x.path / "pax-escape.txt").unlink()
            (x.path / "pax-escape.txt").mkdir()

        def stealth_small(x):
            # Same size, mtime put back. The digest catches this one.
            f = x.path / "escape.txt"
            st = os.lstat(f)
            f.write_bytes(b"X" * st.st_size)
            os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))

        def stealth_large(x):
            # The same trick above HASH_LIMIT, where there is no digest to compare. Only
            # ctime survives it, and ctime is not settable (finding 6d7b790-F1).
            f = x.path / "neighbour" / "large.bin"
            st = os.lstat(f)
            with open(f, "r+b") as fh:
                fh.write(b"owned")
            os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))

        def through_symlinked_root(x):
            # An extractor handed <world>/via-symlink as its root writes through a link.
            # Anything it creates lands in via-symlink-target, which is watched.
            (x.path / "via-symlink" / "planted.txt").write_bytes(b"owned\n")

        cases = [("overwrite an outside file", overwrite),
                 ("create a file outside the root", create),
                 ("delete an outside file", delete),
                 ("change an outside mode", remode),
                 ("retarget an outside symlink", retarget),
                 ("replace an outside file with a directory", swap_kind),
                 ("same-size rewrite, mtime restored (hashed)", stealth_small),
                 ("same-size rewrite, mtime restored (too large to hash)", stealth_large),
                 ("write through a symlinked root", through_symlinked_root)]
        for i, (label, mutate) in enumerate(cases):
            fresh = World(pathlib.Path(tmp) / ("w%d" % i))
            # An outside file too large to hash, so the unhashed path is exercised by a
            # real sentinel rather than only in theory.
            (fresh.path / "neighbour" / "large.bin").write_bytes(b"\0" * (HASH_LIMIT + 4096))
            paths = fresh.watched()
            b = snapshot(paths)
            mutate(fresh)
            # Judged on the world this case owns. /etc and /tmp are shared with whatever
            # else runs in the container, and the world itself lives under one of them,
            # so the filter has to be "inside my world", not a prefix like "/tmp".
            got = [c for c in changes(b, snapshot(paths))
                   if str(c[0]).startswith(str(fresh.path) + os.sep)]
            # A create or delete also advances the parent directory's ctime, and that
            # parent usually sorts first. Report the strongest evidence, not the first.
            got.sort(key=lambda c: c[1].startswith("ctime advanced"))
            if got:
                print("  ok   detected: %-42s (%s)" % (label, got[0][1][:44]))
            else:
                ok = False
                print("  FAIL NOT detected: %s" % label)
            fresh.destroy()

        # 3. The absolute targets: can this process actually touch them? A sentinel over
        #    something unwritable is a check that cannot fail, and the answer depends on
        #    whether the container runs as root.
        results = []
        _probe("/etc/skald-escape.txt is creatable",
               lambda: (open("/etc/skald-escape.txt", "wb").write(b"probe\n"),
                        os.remove("/etc/skald-escape.txt")), results)
        _probe("/tmp/escape.txt is creatable",
               lambda: (open("/tmp/escape.txt", "wb").write(b"probe\n"),
                        os.remove("/tmp/escape.txt")), results)
        _probe("/etc/passwd is writable", _passwd_probe, results)
        for label, good, why in results:
            print("  %s %s%s" % ("ok  " if good else "WEAK", label,
                                 "" if good else "  -- " + why))
        vacuous = [l for l, good, _ in results if not good]
        if vacuous:
            ok = False
            print("  FAIL %d sentinel target(s) this process cannot touch, so watching "
                  "them proves nothing. Run the oracle as root in a disposable "
                  "container." % len(vacuous))

        # 4. Read detection, measured rather than claimed, and checked in both
        #    directions: silent when nothing read, and not silent when something did.
        regime = read_detection(tmp)
        print("  note atime regime: %s -- read detection is %s here"
              % (regime, "available" if regime == "strictatime" else
                 "UNAVAILABLE, so no caller may report 'nothing was read'"))

        quiet = World(pathlib.Path(tmp) / "reads")
        qpaths = [quiet.path / "escape.txt", quiet.path / "neighbour"]
        r0 = snapshot(qpaths)
        spurious = reads(r0, snapshot(qpaths))
        if spurious:
            ok = False
            print("  FAIL two back-to-back snapshots report %d read(s): %s"
                  % (len(spurious), spurious[0]))
        else:
            print("  ok   taking the picture is not itself reported as a read")

        time.sleep(0.01)
        (quiet.path / "escape.txt").read_bytes()
        os.listdir(quiet.path / "neighbour")
        got = set(reads(r0, snapshot(qpaths)))
        missed = [q for q in (quiet.path / "escape.txt", quiet.path / "neighbour")
                  if str(q) not in got]
        if regime == "strictatime":
            if missed:
                ok = False
                print("  FAIL a real read was not reported: %s" % missed[0])
            else:
                print("  ok   a real read of a file and of a directory is reported")
        elif not missed:
            # Worth knowing, and worth failing on: it would mean the regime measurement
            # is wrong, and a wrong measurement is how a blind check gets believed.
            ok = False
            print("  FAIL reads were reported although the regime says they cannot be")
        else:
            print("  ok   under %s a real read is invisible, and the harness says so "
                  "rather than reporting 'no reads'" % regime)
        quiet.destroy()

        # 5. The bound is an error, not a quieter snapshot.
        deep = pathlib.Path(tmp) / "many"
        deep.mkdir()
        for i in range(MAX_ENTRIES + 2):
            (deep / ("f%05d" % i)).write_bytes(b"")
        try:
            snapshot([deep])
        except SnapshotTooLarge:
            print("  ok   a snapshot that would be partial raises instead of truncating")
        else:
            ok = False
            print("  FAIL an oversized tree was snapshotted silently")

        w.destroy()

    print()
    print("RESULT:", "the harness can detect every change it watches for" if ok
          else "MISMATCH")
    return 0 if ok else 1


def _passwd_probe():
    """Append and restore, so the probe proves writability without leaving a change."""
    with open("/etc/passwd", "rb") as fh:
        original = fh.read()
    try:
        with open("/etc/passwd", "ab") as fh:
            fh.write(b"# skald sentinel probe\n")
    finally:
        with open("/etc/passwd", "wb") as fh:
            fh.write(original)


def main(argv):
    if "--self-test" in argv:
        base = os.environ.get("SKALD_WORLD_BASE", "/tmp")
        return self_test(base)
    if "--describe" in argv:
        where = argv[argv.index("--describe") + 1]
        w = World(where)
        print(json.dumps({"root": str(w.root),
                          "watched": [str(p) for p in w.watched()]}, indent=2))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
