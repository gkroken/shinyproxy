#!/usr/bin/env python3
"""Builds the adversarial bundle corpus (WORKPLAN-BUNDLES.md T2).

Written BEFORE the extractor and deliberately independent of it: standard library only, no
import of any Skald class, path validator or manifest validator, not even indirectly. A
fixture generated through the same normaliser being tested establishes nothing, which is the
whole reason this file exists separately from the thing it will be pointed at.

**Archives are generated, not checked in.** The plan asks for the generator, the hashes and
the expectations; storing the bytes as well would add multi-megabyte blobs for the expansion
bombs and a second place for the corpus to drift. Every archive's SHA-256 is recorded in
expectations.json instead, so generation is reproducible and a change to this file that
alters any fixture fails loudly rather than silently redefining the test.

Nothing here decompresses anything. The bombs are written, hashed and left alone; deciding
what they do is the oracle's job, under bounds, in T2b.

Usage:
    python3 dev/fixtures/bundles/generate.py <outdir> [--write-expectations]
"""

import gzip
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import unicodedata

# Default operator limits from WORKPLAN-BUNDLES.md. Boundary fixtures are parameterised off
# these rather than hard-coding 20000, so an operator who changes a limit regenerates a
# corpus whose N/N+1 pairs still straddle the real value.
LIMITS = {
    "max_entries": 20000,
    "max_expanded_bytes": 2 * 1024 * 1024 * 1024,
    "max_file_bytes": 512 * 1024 * 1024,
    "max_path_bytes": 1024,
    "max_segment_bytes": 255,
    "max_depth": 32,
    "max_manifest_bytes": 4 * 1024 * 1024,
}

R_APP = b'library(shiny)\nshinyApp(ui = fluidPage("hi"), server = function(input, output) {})\n'
R_UI = b'library(shiny)\nfluidPage("hi")\n'
R_SERVER = b'library(shiny)\nfunction(input, output) {}\n'
RENV = b'{\n  "R": {"Version": "4.4.1"},\n  "Packages": {}\n}\n'
PY_APP = b'from shiny import App, ui\n\napp = App(ui.page_fluid("hi"), None)\n'
PY_EXPRESS = b'from shiny.express import ui\n\nui.h1("hi")\n'
REQS = b"shiny==1.2.1 --hash=sha256:" + b"0" * 64 + b"\n"

FIXTURES = []


def fixture(name, group, expect, rule, why):
    """Register a fixture. `build` receives a Builder and adds members to it."""
    def register(build):
        FIXTURES.append({
            "name": name, "group": group, "expect": expect, "rule": rule,
            "why": why, "build": build,
        })
        return build
    return register


class Builder:
    """A tar.gz under construction.

    Deliberately thin. tarfile is used for well-formed members; anything a well-behaved
    writer refuses to emit -- a NUL in a name, a negative size, a bad checksum -- is written
    as raw header bytes, because those are precisely the cases a corpus built only with a
    polite library would silently omit.
    """

    def __init__(self):
        self.raw = io.BytesIO()
        self.tar = tarfile.open(fileobj=self.raw, mode="w", format=tarfile.GNU_FORMAT)
        self.closed = False
        self.manifest_written = False

    def add(self, name, data=b"", mode=0o644, typ=tarfile.REGTYPE, linkname="", size=None):
        info = tarfile.TarInfo(name)
        info.type = typ
        info.mode = mode
        info.linkname = linkname
        info.size = len(data) if size is None else size
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        if typ in (tarfile.REGTYPE, tarfile.AREGTYPE):
            self.tar.addfile(info, io.BytesIO(data))
        else:
            self.tar.addfile(info)
        return self

    def add_dir(self, name, mode=0o755):
        return self.add(name.rstrip("/") + "/", mode=mode, typ=tarfile.DIRTYPE)

    def add_manifest(self, doc):
        body = json.dumps(doc, indent=2).encode()
        self.manifest_written = True
        return self.add("manifest.json", body)

    def add_raw(self, header, payload=b""):
        """Bytes straight into the stream, past tarfile's own validation."""
        self.tar.fileobj.write(header)
        if payload:
            self.tar.fileobj.write(payload)
            pad = (512 - len(payload) % 512) % 512
            self.tar.fileobj.write(b"\0" * pad)
        self.tar.offset += len(header) + len(payload) + ((512 - len(payload) % 512) % 512)
        return self

    def bytes(self, truncate_tar=False, skip_gzip=False, append=b""):
        if not self.closed:
            self.tar.close()
            self.closed = True
        body = self.raw.getvalue()
        if truncate_tar:
            body = body[:len(body) // 2]
        if skip_gzip:
            return body + append
        out = io.BytesIO()
        # mtime=0 so the gzip header is byte-stable and the recorded hash means something.
        with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
            gz.write(body)
        return out.getvalue() + append


def raw_header(name, size_field, typeflag=b"0", mode=b"0000644", bad_checksum=False):
    """A 512-byte ustar header, assembled by hand.

    `size_field` is written verbatim, so a negative or overflowing size can be expressed --
    something no tar writer will do for you, and exactly what an extractor's arithmetic has
    to survive.
    """
    def field(value, width):
        b = value if isinstance(value, bytes) else value.encode()
        return b[:width].ljust(width, b"\0")

    header = bytearray(512)
    header[0:100] = field(name, 100)
    header[100:108] = field(mode + b"\0", 8)
    header[108:116] = field(b"0000000\0", 8)
    header[116:124] = field(b"0000000\0", 8)
    header[124:136] = field(size_field, 12)
    header[136:148] = field(b"00000000000\0", 12)
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    if bad_checksum:
        header[148:156] = field(b"9999999\0", 8)
    else:
        # The checksum is computed with the checksum field itself read as eight spaces.
        chksum = sum(0x20 if 148 <= i < 156 else header[i] for i in range(512))
        header[148:156] = field(("%06o\0 " % chksum).encode(), 8)
    return bytes(header)


def manifest(language="r", entrypoint=".", files=None, **over):
    dep = {"format": "renv", "path": "renv.lock"} if language == "r" \
        else {"format": "pip-hashed", "path": "requirements.lock"}
    doc = {
        "schema_version": 1,
        "type": "shiny",
        "runtime": {"language": language, "version": "4.4.1" if language == "r" else "3.12"},
        "entrypoint": entrypoint,
        "dependencies": dep,
        "files": files if files is not None else [],
    }
    doc.update(over)
    return doc


def entry(path, data):
    return {"path": path, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


# --------------------------------------------------------------------- positive controls

@fixture("pos-r-root", "positive", "accept", "-",
         "the ordinary case: a root R app, entrypoint '.', app.R and renv.lock")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("pos-r-two-file", "positive", "accept", "S5",
         "the other layout shiny::runApp accepts: ui.R plus server.R")
def _(b):
    b.add_manifest(manifest(files=[entry("ui.R", R_UI), entry("server.R", R_SERVER),
                                   entry("renv.lock", RENV)]))
    b.add("app/ui.R", R_UI).add("app/server.R", R_SERVER).add("app/renv.lock", RENV)


@fixture("pos-r-nested", "positive", "accept", "S5",
         "an R app in a subdirectory, addressed by a nested entrypoint")
def _(b):
    b.add_manifest(manifest(entrypoint="dashboards/sales",
                            files=[entry("dashboards/sales/app.R", R_APP),
                                   entry("renv.lock", RENV)]))
    b.add("app/dashboards/sales/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("pos-py-core", "positive", "accept", "S4",
         "Python Shiny Core, entrypoint naming a .py file")
def _(b):
    b.add_manifest(manifest("python", "app.py",
                            [entry("app.py", PY_APP), entry("requirements.lock", REQS)]))
    b.add("app/app.py", PY_APP).add("app/requirements.lock", REQS)


@fixture("pos-py-express", "positive", "accept", "S4",
         "Python Shiny Express, which the plan requires alongside Core so a Core-only "
         "import wrapper is not mistaken for general Shiny behaviour")
def _(b):
    b.add_manifest(manifest("python", "app.py",
                            [entry("app.py", PY_EXPRESS), entry("requirements.lock", REQS)]))
    b.add("app/app.py", PY_EXPRESS).add("app/requirements.lock", REQS)


@fixture("pos-unicode-and-spaces", "positive", "accept", "-",
         "names a naive path handler mangles: spaces, accents, CJK")
def _(b):
    assets = {"www/a file with spaces.css": b"body{}\n",
              "www/r\u00e9sum\u00e9.txt": b"resume\n",
              "www/\u65e5\u672c\u8a9e.txt": b"ja\n"}
    files = [entry("app.R", R_APP), entry("renv.lock", RENV)]
    files += [entry(p, d) for p, d in assets.items()]
    b.add_manifest(manifest(files=files))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    for p, d in assets.items():
        b.add("app/" + p, d)


@fixture("pos-empty-file", "positive", "accept", "-",
         "a zero-byte member, which off-by-one size handling drops or rejects")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV),
                                   entry("www/empty.txt", b"")]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV).add("app/www/empty.txt", b"")


@fixture("pos-executable-bit", "positive", "accept", "-",
         "the one mode a publisher may influence, declared and set")
def _(b):
    script = b"#!/bin/sh\necho hi\n"
    e = entry("bin/run.sh", script)
    e["executable"] = True
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV), e]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/bin/run.sh", script, mode=0o755)


@fixture("pos-explicit-dir-headers", "positive", "accept", "-",
         "directory headers present; they are optional and must not be required")
def _(b):
    b.add_manifest(manifest(entrypoint="sub",
                            files=[entry("sub/app.R", R_APP), entry("renv.lock", RENV)]))
    b.add_dir("app").add_dir("app/sub")
    b.add("app/sub/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("pos-implicit-dirs-only", "positive", "accept", "-",
         "no directory headers at all; directories exist only via member paths, which is "
         "the common shape and the one the entrypoint rule is written against")
def _(b):
    b.add_manifest(manifest(entrypoint="sub",
                            files=[entry("sub/app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/sub/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("pos-exact-limit-path", "positive", "accept", "-",
         "a path exactly at the segment and depth limits, the accepted half of the "
         "boundary pair")
def _(b):
    seg = "s" * LIMITS["max_segment_bytes"]
    path = "www/" + seg + ".txt"
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV),
                                   entry(path, b"x")]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV).add("app/" + path, b"x")


# --------------------------------------------------------------------- traversal

def _traversal(name, member, why):
    @fixture(name, "traversal", "reject", "S1", why)
    def _(b, member=member):
        b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
        b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
        b.add(member, b"owned\n")


_traversal("trav-dotdot", "app/../../escape.txt", "the plain case")
_traversal("trav-embedded", "app/a/b/../../../../escape.txt",
           "traversal that only escapes after several segments, so a check of the first "
           "component alone misses it")
_traversal("trav-absolute", "/etc/skald-escape.txt", "an absolute path")
_traversal("trav-drive", "C:\\escape.txt", "a Windows drive path")
_traversal("trav-unc", "\\\\server\\share\\escape.txt", "a UNC path")
_traversal("trav-backslash", "app\\escape.txt",
           "a backslash separator, which is a literal character on Linux and a separator to "
           "anything that later handles the path on Windows")
_traversal("trav-dot-segment", "app/./escape.txt", "a dot segment")
_traversal("trav-empty-segment", "app//escape.txt", "an empty segment")
_traversal("trav-url-encoded", "app/%2e%2e/%2e%2e/escape.txt",
           "percent-encoded traversal, which is literal text in a tar name and must NOT be "
           "decoded; a validator that URL-decodes here creates the escape it is checking for")


@fixture("trav-pax-override", "traversal", "reject", "S1",
         "a benign ustar name with a PAX extended header overriding `path` to a traversal, "
         "so a validator that reads the wrong one of the two names is fooled")
def _(b):
    pax = b"30 path=app/../../pax-escape.txt\n"
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header("app/innocent.txt", b"%011o\0" % len(pax), typeflag=b"x"), pax)
    b.add("app/innocent.txt", b"owned\n")


# --------------------------------------------------------------------- links

@fixture("link-symlink-file", "links", "reject", "-",
         "a symlink to a file outside the root; following it on write escapes, and reading "
         "it leaks")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/passwd", typ=tarfile.SYMTYPE, linkname="/etc/passwd")


@fixture("link-symlink-dir-then-child", "links", "reject", "-",
         "a symlinked DIRECTORY followed by a member beneath it. The child's own name is "
         "innocent, so a lexical check of each name in turn accepts both and the write "
         "lands outside the root")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/out", typ=tarfile.SYMTYPE, linkname="/tmp")
    b.add("app/out/escape.txt", b"owned\n")


@fixture("link-chained", "links", "reject", "-",
         "two symlinks in sequence, the second relative, so resolving only one level is "
         "not enough")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/a", typ=tarfile.SYMTYPE, linkname="b")
    b.add("app/b", typ=tarfile.SYMTYPE, linkname="/tmp")
    b.add("app/a/escape.txt", b"owned\n")


@fixture("link-hardlink-outside", "links", "reject", "-",
         "a hardlink to a file outside the root, which needs no follow to read")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/shadow", typ=tarfile.LNKTYPE, linkname="/etc/passwd")


@fixture("link-symlink-inside", "links", "reject", "-",
         "a symlink whose target IS inside the tree. Still rejected: nothing in a bundle "
         "needs one, and 'inside' is a property of the moment it is checked, not of the "
         "moment it is used")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/alias.R", typ=tarfile.SYMTYPE, linkname="app.R")


# --------------------------------------------------------------------- bombs and sizes

@fixture("bomb-entries-at-limit", "bombs", "accept", "-",
         "exactly the configured entry cap: the accepted half of the N/N+1 pair")
def _(b):
    files = [entry("app.R", R_APP), entry("renv.lock", RENV)]
    n = LIMITS["max_entries"] - len(files) - 1  # -1 for manifest.json itself
    for i in range(n):
        files.append(entry("www/f%05d.txt" % i, b""))
    b.add_manifest(manifest(files=files))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    for i in range(n):
        b.add("app/www/f%05d.txt" % i, b"")


@fixture("bomb-entries-over-limit", "bombs", "reject", "-",
         "one member past the cap, counted as physical headers including metadata")
def _(b):
    files = [entry("app.R", R_APP), entry("renv.lock", RENV)]
    n = LIMITS["max_entries"] - len(files)
    for i in range(n):
        files.append(entry("www/f%05d.txt" % i, b""))
    b.add_manifest(manifest(files=files))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    for i in range(n):
        b.add("app/www/f%05d.txt" % i, b"")


@fixture("bomb-expanded-over-limit", "bombs", "reject", "-",
         "one highly compressible member past the expanded cap: small on disk, ruinous to "
         "anyone who decompresses before checking")
def _(b):
    size = LIMITS["max_expanded_bytes"] + 1
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    info = tarfile.TarInfo("app/www/zeros.bin")
    info.size = size
    info.mtime = 0
    b.tar.addfile(info, _ZeroStream(size))


@fixture("bomb-file-over-limit", "bombs", "reject", "-",
         "a single member past the per-file cap, under the total cap")
def _(b):
    size = LIMITS["max_file_bytes"] + 1
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    info = tarfile.TarInfo("app/www/big.bin")
    info.size = size
    info.mtime = 0
    b.tar.addfile(info, _ZeroStream(size))


@fixture("bomb-declared-size-negative", "bombs", "reject", "-",
         "a negative size written straight into the header. No tar writer emits this, and "
         "arithmetic that trusts it underflows a running total")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header("app/neg.bin", b"-0000000001\0"))


@fixture("bomb-declared-size-overflow", "bombs", "reject", "-",
         "a size field of all sevens in octal, near 2^36, to break a total kept in a "
         "too-small integer")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header("app/huge.bin", b"77777777777\0"))


@fixture("bomb-bad-checksum", "bombs", "reject", "-",
         "a header whose checksum does not match, which a lenient parser may skip past "
         "into attacker-chosen bytes")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header("app/bad.txt", b"00000000004\0", bad_checksum=True), b"oops")


@fixture("bomb-huge-pax-field", "bombs", "reject", "-",
         "a PAX extended header far past the per-header cap, which a parser that buffers "
         "the whole record reads into memory before deciding anything")
def _(b):
    value = b"x" * (256 * 1024)
    record = b"%d comment=%s\n" % (len(b" comment=\n") + len(value) + 7, value)
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header("pax.header", b"%011o\0" % len(record), typeflag=b"x"), record)
    b.add("app/after-pax.txt", b"x")


@fixture("bomb-sparse-claimed", "bombs", "reject", "-",
         "a GNU sparse member. The encoding lets declared and stored size disagree by "
         "design, which is the one thing every size check here depends on")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header("app/sparse.bin", b"%011o\0" % (1 << 30), typeflag=b"S"))


@fixture("bomb-many-empty-entries", "bombs", "reject", "-",
         "entries that cost nothing to store and one header each, so a cap counted in "
         "bytes rather than headers never fires")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    for i in range(LIMITS["max_entries"] + 100):
        b.add("app/www/e%06d" % i, b"")


@fixture("bomb-truncated-gzip", "bombs", "reject", "-",
         "the gzip stream stops mid-member")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("bomb-truncated-tar", "bombs", "reject", "-",
         "valid gzip wrapping a tar that ends mid-member, with no end marker")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("bomb-concatenated-members", "bombs", "reject", "-",
         "two gzip members concatenated. Readers disagree about whether the second exists, "
         "so what was validated and what was extracted can differ")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("bomb-trailing-garbage", "bombs", "reject", "-",
         "bytes after the gzip member that are not padding")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


class _ZeroStream(io.RawIOBase):
    """Feeds N zero bytes to tarfile without allocating them."""

    def __init__(self, size):
        self.left = size

    def read(self, n=-1):
        if self.left <= 0:
            return b""
        take = self.left if n is None or n < 0 else min(n, self.left)
        self.left -= take
        return b"\0" * take

    def readable(self):
        return True


# --------------------------------------------------------------------- paths and types

@fixture("type-device", "types", "reject", "-",
         "a character device header; materialising one is a privileged act and a bundle "
         "has no business asking")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/null", typ=tarfile.CHRTYPE)


@fixture("type-fifo", "types", "reject", "-",
         "a FIFO; a later reader blocks on it forever")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/pipe", typ=tarfile.FIFOTYPE)


@fixture("type-block-device", "types", "reject", "-", "a block device header")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/disk", typ=tarfile.BLKTYPE)


def _mode_fixture(name, mode, why):
    @fixture(name, "types", "reject", "-", why)
    def _(b, mode=mode):
        b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
        b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
        b.add("app/tool", b"#!/bin/sh\n", mode=mode)


_mode_fixture("type-setuid", 0o4755, "a setuid bit, which the extractor must never carry over")
_mode_fixture("type-setgid", 0o2755, "a setgid bit")
_mode_fixture("type-sticky", 0o1755, "a sticky bit")


@fixture("path-segment-over-limit", "types", "reject", "-",
         "one segment past the cap: the rejected half of the boundary pair whose accepted "
         "half is pos-exact-limit-path")
def _(b):
    seg = "s" * (LIMITS["max_segment_bytes"] + 1)
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/www/" + seg + ".txt", b"x")


@fixture("path-total-over-limit", "types", "reject", "-",
         "a path past the total cap, assembled from legal segments")
def _(b):
    seg = "s" * 100
    depth = LIMITS["max_path_bytes"] // 101 + 2
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/" + "/".join([seg] * depth) + "/x.txt", b"x")


@fixture("path-depth-over-limit", "types", "reject", "-",
         "one level past the depth cap")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/" + "/".join("d%d" % i for i in range(LIMITS["max_depth"] + 1)) + "/x.txt", b"x")


@fixture("path-nul", "types", "reject", "-",
         "a NUL inside the name field, which truncates the path for anything that treats "
         "it as a C string while the rest of the field is still there")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header(b"app/ok.txt\0../../escape.txt", b"00000000004\0"), b"oops")


@fixture("path-control-char", "types", "reject", "-",
         "a control character in a name, which corrupts any log or terminal that echoes it")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/be" + chr(7) + "ll.txt", b"x")


@fixture("path-invalid-utf8", "types", "reject", "-",
         "a lone continuation byte: not valid UTF-8, so it has no defined normalisation "
         "and two readers can disagree about what the name is")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_raw(raw_header(b"app/bad\xff\xfe.txt", b"00000000004\0"), b"oops")


# --------------------------------------------------------------------- duplicates

@fixture("dup-regular", "duplicates", "reject", "S3",
         "the same path twice. Last-entry-wins means what was validated is not what is on "
         "disk")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/app.R", b"# replaced after validation\n")


@fixture("dup-manifest", "duplicates", "reject", "-",
         "two manifests. A reader that takes the first and a reader that takes the last "
         "are looking at different bundles")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("manifest.json", json.dumps(manifest("python", "app.py", [])).encode())


@fixture("dup-file-then-dir", "duplicates", "reject", "-",
         "a regular file, then a directory at the same path")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/thing", b"x").add_dir("app/thing")


@fixture("dup-dir-then-file", "duplicates", "reject", "-",
         "the same collision the other way round")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_dir("app/thing").add("app/thing", b"x")


@fixture("dup-case-alias", "duplicates", "reject", "S3",
         "App.R beside app.R: distinct on Linux, one file on a case-insensitive filesystem, "
         "so the bundle means different things depending where it lands")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/App.R", b"# shadow\n")


@fixture("dup-nfc-alias", "duplicates", "reject", "S3",
         "the same name in NFC and NFD. Byte-different, identical after normalisation, and "
         "macOS normalises on write")
def _(b):
    nfc = unicodedata.normalize("NFC", "caf\u00e9.txt")
    nfd = unicodedata.normalize("NFD", "caf\u00e9.txt")
    assert nfc != nfd
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/www/" + nfc, b"one\n").add("app/www/" + nfd, b"two\n")


@fixture("dup-file-before-parent", "duplicates", "reject", "-",
         "a file, then a regular file where its parent directory must be; ordering decides "
         "whether an extractor notices")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/parent/child.txt", b"x").add("app/parent", b"now a file\n")


# --------------------------------------------------------------------- manifest/inventory

@fixture("manifest-missing", "manifest", "reject", "-", "no manifest at all")
def _(b):
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("manifest-late", "manifest", "reject", "-",
         "the manifest after the payload. It must be the first logical regular file, or a "
         "streaming reader validates bytes it has already written")
def _(b):
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))


@fixture("manifest-not-json", "manifest", "reject", "-", "a manifest that is not JSON")
def _(b):
    b.add("manifest.json", b"this is not json\n")
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("manifest-duplicate-json-key", "manifest", "reject", "-",
         "the same key twice. Parsers disagree about which wins, so two readers can see "
         "different entrypoints in one document")
def _(b):
    body = b'{"schema_version":1,"type":"shiny","type":"plumber",' \
           b'"runtime":{"language":"r","version":"4.4.1"},"entrypoint":".",' \
           b'"dependencies":{"format":"renv","path":"renv.lock"},"files":[]}'
    b.add("manifest.json", body)
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("manifest-remote-ref", "manifest", "reject", "-",
         "a $ref at a URL. Resolving it would let an upload choose what validates it and "
         "make the platform fetch on its behalf")
def _(b):
    doc = manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)])
    doc["$ref"] = "https://example.invalid/schema.json"
    b.add_manifest(doc)
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("inventory-missing-file", "manifest", "reject", "S11",
         "a payload member absent from the inventory: a file smuggled past a reader that "
         "trusts the manifest")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)
    b.add("app/www/unlisted.txt", b"smuggled\n")


@fixture("inventory-extra-file", "manifest", "reject", "S11",
         "an inventory entry with no member behind it")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV),
                                   entry("www/phantom.txt", b"ghost\n")]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("inventory-hash-mismatch", "manifest", "reject", "S10",
         "a declared hash that does not match the bytes; the publisher's hash is a claim, "
         "not proof")
def _(b):
    e = entry("app.R", R_APP)
    e["sha256"] = "0" * 64
    b.add_manifest(manifest(files=[e, entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("inventory-size-mismatch", "manifest", "reject", "S10",
         "a declared size that does not match the bytes")
def _(b):
    e = entry("app.R", R_APP)
    e["size"] = 1
    b.add_manifest(manifest(files=[e, entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("entrypoint-r-names-a-file", "manifest", "reject", "S5",
         "an R entrypoint naming a regular file")
def _(b):
    b.add_manifest(manifest(entrypoint="app.R",
                            files=[entry("app.R", R_APP), entry("renv.lock", RENV)]))
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("entrypoint-py-names-a-directory", "manifest", "reject", "S4",
         "a Python entrypoint naming a directory")
def _(b):
    b.add_manifest(manifest("python", "src",
                            [entry("src/app.py", PY_APP), entry("requirements.lock", REQS)]))
    b.add("app/src/app.py", PY_APP).add("app/requirements.lock", REQS)


@fixture("entrypoint-r-no-layout", "manifest", "reject", "S5",
         "an R entrypoint directory with neither app.R nor ui.R plus server.R")
def _(b):
    b.add_manifest(manifest(entrypoint="dash",
                            files=[entry("dash/readme.md", b"nope\n"),
                                   entry("renv.lock", RENV)]))
    b.add("app/dash/readme.md", b"nope\n").add("app/renv.lock", RENV)


@fixture("entrypoint-dir-header-only", "manifest", "reject", "S5",
         "an entrypoint evidenced only by a directory header, with no qualifying file "
         "beneath it; a header neither satisfies the rule nor is required by it")
def _(b):
    b.add_manifest(manifest(entrypoint="dash", files=[entry("renv.lock", RENV)]))
    b.add_dir("app/dash").add("app/renv.lock", RENV)


@fixture("lockfile-absent", "manifest", "reject", "S6",
         "a lockfile named by dependencies.path but absent from the inventory")
def _(b):
    b.add_manifest(manifest(files=[entry("app.R", R_APP)]))
    b.add("app/app.R", R_APP)


@fixture("language-format-disagreement", "manifest", "reject", "S7",
         "pip-hashed declared under an R runtime")
def _(b):
    doc = manifest(files=[entry("app.R", R_APP), entry("requirements.lock", REQS)])
    doc["dependencies"] = {"format": "pip-hashed", "path": "requirements.lock"}
    b.add_manifest(doc)
    b.add("app/app.R", R_APP).add("app/requirements.lock", REQS)


@fixture("unsupported-type", "manifest", "reject", "S8",
         "a registered type with no reviewed recipe; being in the enum is not a promise")
def _(b):
    doc = manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)])
    doc["type"] = "quarto_static"
    b.add_manifest(doc)
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


@fixture("manifest-over-limit", "manifest", "reject", "-",
         "a manifest past its own cap, so a parser that reads before bounding allocates it")
def _(b):
    doc = manifest(files=[entry("app.R", R_APP), entry("renv.lock", RENV)])
    doc["files"] += [entry("www/f%07d.txt" % i, b"") for i in range(60000)]
    b.add_manifest(doc)
    b.add("app/app.R", R_APP).add("app/renv.lock", RENV)


# --------------------------------------------------------------------- emit

SPECIAL = {
    "bomb-truncated-gzip": lambda b: b.bytes()[:len(b.bytes()) // 2],
    "bomb-truncated-tar": lambda b: gzip_of(b.bytes(skip_gzip=True)[:1024]),
    "bomb-concatenated-members": lambda b: b.bytes() + b.bytes(),
    "bomb-trailing-garbage": lambda b: b.bytes() + b"trailing, not padding\n",
}


def gzip_of(body):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(body)
    return out.getvalue()


def build_all(outdir):
    outdir = pathlib.Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    produced = []
    for f in FIXTURES:
        b = Builder()
        f["build"](b)
        data = SPECIAL[f["name"]](b) if f["name"] in SPECIAL else b.bytes()
        path = outdir / (f["name"] + ".tar.gz")
        path.write_bytes(data)
        produced.append({
            "name": f["name"], "group": f["group"], "expect": f["expect"],
            "rule": f["rule"], "why": f["why"],
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
        })
    return produced


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    outdir = sys.argv[1]
    produced = build_all(outdir)
    doc = {
        "note": ("Generated by dev/fixtures/bundles/generate.py. Archives are NOT checked in; "
                 "they are regenerated and their SHA-256 compared against this file, so a "
                 "change to the generator that alters a fixture fails loudly instead of "
                 "quietly redefining the test."),
        "limits": LIMITS,
        "fixtures": produced,
    }
    if "--write-expectations" in sys.argv:
        here = pathlib.Path(__file__).resolve().parent
        (here / "expectations.json").write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("wrote expectations for %d fixtures" % len(produced))
    else:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
