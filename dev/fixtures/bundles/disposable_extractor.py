"""A disposable extractor for the bundle corpus (WORKPLAN-BUNDLES.md T2b).

**This is test scaffolding, not the product.** Nothing in `eu.openanalytics.shinyproxy`
may call it, depend on it or copy from it. It exists so the oracle has something to judge
before the real extractor exists, and so each guard can be removed one at a time to prove
the oracle notices.

It is deliberately independent of Skald: standard library only, no import of any Skald
class, and no shared code with `dev/bundle-corpus-check.py`. The checker is the inspector
and this is the subject; a parser shared between them would hide its own bugs from both.

Three modes:

  (default)     every guard on. Reads the archive with tarfile, wrapped in an outer
                validator for the things tarfile cannot express. The plan calls for
                exactly this shape: "any library unable to expose these distinctions is
                unsuitable without an outer validator".
  --without G   one guard removed. This is what proves the oracle detects a weakened
                extractor rather than only a hopeless one.
  --unsafe      tarfile.extractall(filter="fully_trusted"), the textbook vulnerable
                pattern, which really does write to /etc and through symlinks.

Members are checked and written in one streaming pass, and a rejection wipes the root.
Holding the whole payload to freeze the tree first would mean holding two gigabytes for
the fixture that sits exactly at the expanded cap; the property that matters -- a
rejected bundle leaves nothing behind -- is recovered by the wipe, and the oracle asserts
an empty root after every rejection rather than taking this file's word for it.

The decision goes to stdout as JSON and the exit status is 0 whether the bundle is
accepted or rejected. A non-zero exit means the extractor itself fell over, which is a
different thing and must not be read as a rejection.

Usage:
    python3 disposable_extractor.py --root DIR --archive FILE [--limits JSON]
                                    [--without GUARD]... [--unsafe] [--unbounded]
"""

import getopt
import gzip
import hashlib
import json
import os
import pathlib
import stat
import sys
import tarfile
import unicodedata
import warnings

warnings.simplefilter("ignore")

GUARDS = ("framing", "limits", "path", "types", "duplicates", "pax", "manifest")

PAYLOAD_ROOT = "app/"
MANIFEST = "manifest.json"
LANGUAGES = ("r", "python")
TYPES = ("shiny",)

# Mirrors the generator's defaults. Passed in with --limits by the oracle so that the
# extractor and the corpus cannot drift apart; these are only what it falls back to.
DEFAULT_LIMITS = {
    "max_compressed_bytes": 256 * 1024 * 1024,
    "max_entries": 20000,
    "max_expanded_bytes": 2 * 1024 * 1024 * 1024,
    "max_file_bytes": 512 * 1024 * 1024,
    "max_path_bytes": 1024,
    "max_segment_bytes": 255,
    "max_depth": 32,
    "max_manifest_bytes": 4 * 1024 * 1024,
    "max_extended_header_bytes": 64 * 1024,
    "extraction_deadline_seconds": 60,
}

ALLOWED_TYPES = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}


def _read_exactly(fh, n):
    buf = b""
    while len(buf) < n:
        chunk = fh.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


class Reject(Exception):
    def __init__(self, rule, detail):
        super().__init__("%s: %s" % (rule, detail))
        self.rule, self.detail = rule, detail


class Extractor:
    def __init__(self, root, archive, limits, without):
        self.root = pathlib.Path(root)
        self.archive = pathlib.Path(archive)
        self.limits = limits
        self.off = set(without)

    def on(self, guard):
        return guard not in self.off

    # ---------------------------------------------------------------- outer validator
    #
    # Everything tarfile will not tell us, checked on the bytes before tarfile sees them.

    def check_framing(self):
        size = self.archive.stat().st_size
        if self.on("limits") and size > self.limits["max_compressed_bytes"]:
            raise Reject("compressed-cap", "%d bytes over %d"
                         % (size, self.limits["max_compressed_bytes"]))
        if not self.on("framing"):
            return
        with open(self.archive, "rb") as fh:
            if fh.read(2) != b"\x1f\x8b":
                raise Reject("framing", "not a gzip member")
        # Exactly one member, and nothing after it. zlib reports where the member ended
        # and what was left over, which is the distinction the plan requires and which a
        # plain gzip.open() silently hides by reading concatenated members as one file.
        import zlib
        consumed, leftover = 0, b""
        with open(self.archive, "rb") as fh:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                consumed += len(chunk)
                d.decompress(chunk, 1 << 20)
                while not d.eof and d.unconsumed_tail:
                    d.decompress(d.unconsumed_tail, 1 << 20)
                if d.eof:
                    leftover = d.unused_data
                    consumed -= len(leftover)
                    break
            if not d.eof:
                raise Reject("framing", "gzip member does not end")
        if leftover.startswith(b"\x1f\x8b"):
            raise Reject("framing", "concatenated gzip members")
        if leftover.strip(b"\0"):
            raise Reject("framing", "%d bytes of non-padding trailing data" % len(leftover))

    def check_headers(self):
        """Walk the raw 512-byte headers before tarfile ever sees them.

        This is the "outer validator" the plan requires, and the corpus is what proved it
        is not optional. Five fixtures are accepted or crashed by a tarfile-only
        extractor, which is how each of these checks earned its place:

          bomb-bad-checksum            tarfile treats an unparseable header as the end of
          bomb-declared-size-negative  the archive and returns cleanly, so "a lenient
                                       parser may skip past into attacker-chosen bytes"
                                       is exactly what happens -- silently, as an accept
          bomb-huge-pax-field          tarfile never reports an extended header's own
                                       size, so the per-header cap cannot be enforced
          trav-pax-override            tarfile does not apply this hand-written PAX
                                       header, so the EFFECTIVE path is never checked --
                                       and the effective path is the one the plan says
                                       to validate

        Payloads are skipped rather than read, except a PAX record, which IS the content.
        """
        with open(self.archive, "rb") as fh:
            gz = gzip.GzipFile(fileobj=fh)
            try:
                self.walk_headers(gz)
            finally:
                gz.close()

    def walk_headers(self, gz):
        pending_name, ended = None, False
        while True:
            block = _read_exactly(gz, 512)
            if len(block) < 512:
                break
            if block == b"\0" * 512:
                ended = True
                break
            name = block[0:100].rstrip(b"\0")
            typeflag = block[156:157]
            size_field = block[124:136].rstrip(b"\0 ")
            stored = block[148:156].rstrip(b"\0 ")
            if self.on("framing"):
                wanted = sum(0x20 if 148 <= i < 156 else block[i] for i in range(512))
                try:
                    if int(stored, 8) != wanted:
                        raise ValueError
                except ValueError:
                    raise Reject("bad-checksum", "header checksum %r" % stored[:12])
            try:
                size = int(size_field, 8) if size_field else 0
                if size < 0:
                    raise ValueError
            except ValueError:
                raise Reject("declared-size", "size field %r" % size_field[:12])
            padded = ((size + 511) // 512) * 512

            if typeflag in (b"L", b"K"):
                payload = _read_exactly(gz, padded)
                if typeflag == b"L":
                    pending_name = payload[:size].rstrip(b"\0")
                continue
            if typeflag in (b"x", b"g"):
                if self.on("limits") and size > self.limits["max_extended_header_bytes"]:
                    raise Reject("extended-header-cap", "%d bytes" % size)
                if self.on("pax") and typeflag == b"g":
                    raise Reject("pax-global", "a global extended header")
                payload = _read_exactly(gz, padded)[:size]
                if self.on("pax"):
                    self.check_pax_records(payload)
                continue
            if self.on("types") and typeflag not in (b"0", b"\0", b"1", b"2", b"3",
                                                     b"4", b"5", b"6", b"7"):
                raise Reject("type", "typeflag %r" % typeflag.decode("latin-1"))
            pending_name = None
            if len(_read_exactly(gz, padded)) < padded:
                raise Reject("framing", "archive ends mid-member")
        if not ended and self.on("framing"):
            raise Reject("framing", "no end-of-archive marker")

    def check_pax_records(self, payload):
        """A PAX header's records, parsed and judged.

        `path` is allowlisted, and then the path it names is run through the same rules
        as any other member name -- that is what "validate the effective path after any
        approved override" means, and validating the ustar name instead is the exact
        mistake trav-pax-override exists to catch.
        """
        allowed = {b"path", b"mtime", b"atime", b"ctime", b"uid", b"gid", b"uname",
                   b"gname", b"size", b"comment"}
        off = 0
        while off < len(payload):
            sp = payload.find(b" ", off)
            if sp < 0:
                raise Reject("pax-malformed", "no length field")
            try:
                n = int(payload[off:sp])
            except ValueError:
                raise Reject("pax-malformed", repr(payload[off:off + 12]))
            if n <= sp - off or off + n > len(payload):
                raise Reject("pax-malformed", "record length %d" % n)
            key, _, value = payload[sp + 1:off + n].rstrip(b"\n").partition(b"=")
            if key not in allowed:
                raise Reject("pax-unknown-record", key.decode("latin-1")[:40])
            if key == b"path":
                try:
                    effective = value.decode()
                except UnicodeDecodeError:
                    raise Reject("path-invalid-utf8", repr(value[:40]))
                self.check_path(effective, effective.endswith("/"))
            off += n

    # ---------------------------------------------------------------- per-member checks

    def check_path(self, name, is_dir):
        """The path rules, applied to the EFFECTIVE name, inside the payload root."""
        if not self.on("path"):
            return
        raw = name
        try:
            raw.encode()
        except UnicodeEncodeError:
            # tarfile decodes an undecodable name with surrogates. Writing it later
            # raises deep inside os.open, which is a crash, not a rejection.
            raise Reject("path-invalid-utf8", repr(raw[:40]))
        if raw.startswith("/") or raw.startswith("\\\\"):
            raise Reject("path-absolute", raw[:60])
        if len(raw) > 1 and raw[1] == ":":
            raise Reject("path-drive", raw[:60])
        if "\\" in raw:
            raise Reject("path-backslash", raw[:60])
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
            raise Reject("path-control-char", repr(raw[:60]))
        if unicodedata.normalize("NFC", raw) != raw:
            raise Reject("path-not-nfc", raw[:60])
        body = raw[:-1] if raw.endswith("/") and is_dir else raw
        if body == PAYLOAD_ROOT.rstrip("/"):
            return ""          # the payload root's own directory header
        if body != MANIFEST and not body.startswith(PAYLOAD_ROOT):
            raise Reject("path-outside-payload-root", body[:60])
        rel = body[len(PAYLOAD_ROOT):] if body.startswith(PAYLOAD_ROOT) else body
        segments = rel.split("/") if rel else []
        for seg in segments:
            if seg in ("", ".", ".."):
                raise Reject("path-segment", "%r in %s" % (seg, body[:60]))
            if self.on("limits") and len(seg.encode()) > self.limits["max_segment_bytes"]:
                raise Reject("segment-cap", "%d bytes" % len(seg.encode()))
        if self.on("limits"):
            if len(rel.encode()) > self.limits["max_path_bytes"]:
                raise Reject("path-cap", "%d bytes" % len(rel.encode()))
            if len(segments) > self.limits["max_depth"]:
                raise Reject("depth-cap", "%d levels" % len(segments))
        return rel

    def check_type(self, info):
        if not self.on("types"):
            return
        if info.type not in ALLOWED_TYPES:
            raise Reject("type", "typeflag %r" % info.type.decode("latin-1"))
        if info.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise Reject("mode", "setuid/setgid/sticky %o" % info.mode)

    def check_pax(self, info):
        """PAX records: allowlist `path`, refuse anything that changes interpretation."""
        if not self.on("pax"):
            return
        allowed = {"path", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname",
                   "size", "comment"}
        for key in getattr(info, "pax_headers", {}):
            if key not in allowed:
                raise Reject("pax-unknown-record", key)
            if key in ("linkpath", "GNU.sparse.name", "SCHILY.xattr"):
                raise Reject("pax-override", key)

    # ---------------------------------------------------------------- the run

    def run(self):
        self.check_framing()
        self.check_headers()
        try:
            state = self.walk_and_write()
        except Reject:
            self.wipe()
            raise
        if self.on("manifest"):
            try:
                self.check_manifest(state)
            except Reject:
                self.wipe()
                raise
        return {"decision": "accept", "reason": "", "entries": state["entries"],
                "bytes": state["total"]}

    def wipe(self):
        """A rejected bundle leaves nothing behind.

        The contract says delete the tree on every failure path, and the oracle asserts
        an emptied root after every rejection. Only what is UNDER the root is removed --
        anything an unguarded run put outside it is evidence and must survive for the
        sentinels to find.
        """
        import shutil
        for child in sorted(self.root.iterdir()) if self.root.is_dir() else []:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass

    def walk_and_write(self):
        """One streaming pass: check each member, then write it.

        Single pass and write-as-you-go, rather than validate-everything-then-write.
        Holding payload to freeze the tree first would mean holding two gigabytes for the
        fixture that is exactly at the expanded cap. The property that matters is
        recovered by wipe(): a rejection leaves an empty root, which the oracle checks.
        """
        state = {"entries": 0, "total": 0, "paths": {}, "manifest": None,
                 "digests": {}, "sizes": {}, "first_regular": None}
        self.root.mkdir(parents=True, exist_ok=True)
        seen = {}
        try:
            tar = tarfile.open(self.archive, mode="r|gz")
        except Exception as e:
            raise Reject("unreadable", "%s: %s" % (type(e).__name__, str(e)[:80]))
        with tar:
            while True:
                try:
                    info = tar.next()
                except Exception as e:
                    raise Reject("unreadable", "%s: %s" % (type(e).__name__, str(e)[:80]))
                if info is None:
                    break
                state["entries"] += 1
                if self.on("limits") and state["entries"] > self.limits["max_entries"]:
                    raise Reject("entry-cap", "over %d" % self.limits["max_entries"])
                self.check_pax(info)
                self.check_type(info)
                rel = self.check_path(info.name, info.isdir())
                if self.on("limits"):
                    if info.size > self.limits["max_file_bytes"]:
                        raise Reject("file-cap", "%s is %d bytes" % (info.name, info.size))
                    state["total"] += info.size
                    if state["total"] > self.limits["max_expanded_bytes"]:
                        raise Reject("expanded-cap", "over %d bytes"
                                     % self.limits["max_expanded_bytes"])
                else:
                    state["total"] += max(info.size, 0)
                if self.on("duplicates"):
                    key = unicodedata.normalize("NFC", info.name.rstrip("/")).lower()
                    if key in seen:
                        raise Reject("duplicate", info.name[:60])
                    seen[key] = info.name
                if info.isreg() and state["first_regular"] is None:
                    state["first_regular"] = info.name
                self.emit(tar, info, rel, state)
        return state

    def emit(self, tar, info, rel, state):
        """Materialise one member.

        The write path depends on which guards are ON, because a guard that is removed
        has to produce the unsafe behaviour it was preventing -- otherwise `--without
        path` would still be safe and would prove nothing about the oracle.

          path guard on   -> resolved relative to a directory descriptor chain under the
                             root, each step O_NOFOLLOW, so a symlink planted by an
                             earlier member cannot be walked through. A lexical
                             normalize().startsWith(root) would pass that case.
          path guard off  -> os.path.join(root, name), which is what a naive extractor
                             does: an absolute member name replaces the root outright and
                             "../" walks out of it.
          duplicates on   -> O_EXCL, so a second member cannot land on a taken path.
          duplicates off  -> last entry wins, the overwrite the guard exists to stop.
          types off       -> links and devices are actually created.
        """
        name = info.name
        if info.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            self.emit_link(info)
            return
        if info.isdir():
            if not rel:
                return          # the payload root's own header; the root already exists
            if self.on("path"):
                fd = self.open_parent(rel, create_last=True)
                if fd is not None:
                    os.close(fd)
            else:
                os.makedirs(os.path.join(self.root, name), 0o700, exist_ok=True)
            return
        if not info.isreg():
            # Only reachable with the types guard off; a device or FIFO is created so the
            # oracle can see that it was.
            if not self.on("types"):
                target = self.naive_target(name)
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                try:
                    os.mknod(target, 0o600 | (stat.S_IFIFO if info.isfifo()
                                              else stat.S_IFCHR), 0)
                except OSError:
                    pass
            return

        src = tar.extractfile(info)
        digest, written = hashlib.sha256(), 0
        if self.on("path"):
            parent = self.open_parent(rel)
            flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (
                os.O_EXCL if self.on("duplicates") else os.O_TRUNC)
            mode = 0o700 if info.mode & 0o100 else 0o600
            try:
                fd = os.open(rel.split("/")[-1], flags, mode, dir_fd=parent)
            except FileExistsError:
                os.close(parent)
                raise Reject("duplicate", rel[:60])
            except OSError as e:
                os.close(parent)
                raise Reject("write", "%s: %s" % (type(e).__name__, rel[:60]))
            os.close(parent)
        else:
            target = self.naive_target(name)
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = src.read(1 << 20) if src else b""
                if not chunk:
                    break
                digest.update(chunk)
                written += len(chunk)
                out.write(chunk)
        if name == MANIFEST and state["manifest"] is None:
            state["manifest"] = self.read_back(rel, name, written)
            return
        # Bookkeeping must survive --without path. check_path returns the payload-relative
        # key, and with the guard off it returned nothing -- which left the inventory
        # empty, so the manifest guard rejected every traversal fixture before it could
        # escape, and removing the PATH guard showed up as 19 unexpected REJECTS. A
        # weakened guard has to produce its own weakness, not a different one.
        key = rel if rel is not None else (
            name[len(PAYLOAD_ROOT):] if name.startswith(PAYLOAD_ROOT) else None)
        if key:
            state["digests"][key] = digest.hexdigest()
            state["sizes"][key] = written
            state["paths"][key] = True

    def read_back(self, rel, name, written):
        """The manifest is needed as bytes. Read back from what was just written, under a
        hard scaffolding ceiling so that --without limits cannot make this unbounded."""
        if written > 256 * 1024 * 1024:
            raise Reject("manifest-cap", "%d bytes, past the scaffolding ceiling" % written)
        target = (self.root / (rel or name)) if self.on("path") \
            else pathlib.Path(self.naive_target(name))
        try:
            return target.read_bytes()
        except OSError:
            return b""

    def naive_target(self, name):
        """What an extractor with no path guard would compute. os.path.join returns the
        second argument outright when it is absolute, which is the escape."""
        return os.path.join(str(self.root), name)

    def emit_link(self, info):
        if self.on("types"):
            raise Reject("type", "link member %s" % info.name[:50])
        target = self.naive_target(info.name)
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        try:
            if info.type == tarfile.SYMTYPE:
                os.symlink(info.linkname, target)
            else:
                os.link(self.naive_target(info.linkname), target)
        except OSError:
            pass

    def open_parent(self, rel, create_last=False):
        """Walk to rel's parent one component at a time, refusing to follow links."""
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        parts = rel.split("/")
        walk = parts if create_last else parts[:-1]
        for part in walk:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            except OSError as e:
                os.close(fd)
                raise Reject("write", "%s: %s" % (type(e).__name__, rel[:60]))
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            except OSError as e:
                os.close(fd)
                raise Reject("parent-not-a-directory",
                             "%s at %s" % (type(e).__name__, part[:40]))
            os.close(fd)
            fd = nxt
        return fd

    def check_manifest(self, state):
        body = state["manifest"]
        if body is None:
            raise Reject("manifest-missing", "no manifest.json")
        if state["first_regular"] != MANIFEST:
            raise Reject("manifest-late", "first regular member is %r"
                         % state["first_regular"])
        if self.on("limits") and len(body) > self.limits["max_manifest_bytes"]:
            raise Reject("manifest-cap", "%d bytes" % len(body))
        try:
            doc = json.loads(body)
        except Exception as e:
            raise Reject("manifest-not-json", type(e).__name__)
        # json.loads keeps the last of a duplicated key, so the only way to notice is to
        # count them on the way past.
        if _duplicate_json_keys(body):
            raise Reject("manifest-duplicate-key", "a key appears twice")
        if b"$ref" in body and b"://" in body:
            raise Reject("manifest-remote-ref", "a remote $ref")
        if doc.get("schema_version") != 1:
            raise Reject("manifest-schema-version", repr(doc.get("schema_version")))
        if doc.get("type") not in TYPES:
            raise Reject("manifest-type", repr(doc.get("type")))
        language = (doc.get("runtime") or {}).get("language")
        if language not in LANGUAGES:
            raise Reject("manifest-language", repr(language))
        dep = doc.get("dependencies") or {}
        want = "renv" if language == "r" else "pip-hashed"
        if dep.get("format") != want:
            raise Reject("manifest-dependency-format", repr(dep.get("format")))

        declared = {f["path"]: f for f in doc.get("files", [])}
        payload = state["paths"]
        missing = sorted(set(declared) - set(payload))
        extra = sorted(set(payload) - set(declared))
        if missing:
            raise Reject("inventory-missing-file", missing[0])
        if extra:
            raise Reject("inventory-extra-file", extra[0])
        for path, f in declared.items():
            if f.get("size") != state["sizes"][path]:
                raise Reject("inventory-size-mismatch", path)
            if f.get("sha256") != state["digests"][path]:
                raise Reject("inventory-hash-mismatch", path)
        if dep.get("path") not in payload:
            raise Reject("lockfile-absent", repr(dep.get("path")))
        self.check_entrypoint(doc, payload)

    def check_entrypoint(self, doc, payload):
        entry = doc.get("entrypoint")
        if entry is None:
            raise Reject("entrypoint-missing", "no entrypoint")
        language = doc["runtime"]["language"]
        at_root = entry in (".", "")
        prefix = "" if at_root else entry.rstrip("/") + "/"
        here = {p[len(prefix):] for p in payload if p.startswith(prefix)} if prefix \
            else set(payload)
        if language == "r":
            if not at_root and entry in payload:
                raise Reject("entrypoint-kind", "R entrypoint names a file: %s" % entry)
            if not ({"app.R"} <= here or {"ui.R", "server.R"} <= here):
                raise Reject("entrypoint-layout", "no app.R and no ui.R+server.R")
        else:
            if not at_root and entry not in payload:
                raise Reject("entrypoint-kind",
                             "Python entrypoint names a directory: %s" % entry)
            if at_root and "app.py" not in here:
                raise Reject("entrypoint-layout", "no app.py")


def _duplicate_json_keys(body):
    seen = []

    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            seen.append(True)
        return dict(pairs)

    try:
        json.loads(body, object_pairs_hook=hook)
    except Exception:
        return False
    return bool(seen)


def unsafe(root, archive):
    """The textbook vulnerable pattern, kept in one place and clearly labelled.

    filter="fully_trusted" is required: since 3.12 tarfile warns about the default and
    3.14 makes "data" the default, and "data" would quietly make this extractor safe --
    a variant that is not actually unsafe proves nothing about the oracle.
    """
    pathlib.Path(root).mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(root, filter="fully_trusted")
    return {"decision": "accept", "reason": "", "entries": None, "bytes": None}


def main(argv):
    opts, _ = getopt.getopt(argv, "", ["root=", "archive=", "limits=", "without=",
                                       "unsafe", "unbounded"])
    root = archive = None
    limits = dict(DEFAULT_LIMITS)
    without, mode = [], "guarded"
    for key, value in opts:
        if key == "--root":
            root = value
        elif key == "--archive":
            archive = value
        elif key == "--limits":
            limits.update(json.loads(value))
        elif key == "--without":
            if value not in GUARDS:
                print("unknown guard %r; known: %s" % (value, ", ".join(GUARDS)),
                      file=sys.stderr)
                return 2
            without.append(value)
        elif key == "--unsafe":
            mode = "unsafe"
        elif key == "--unbounded":
            without.append("limits")
            mode = "unbounded"
    if not root or not archive:
        print(__doc__)
        return 2

    try:
        if mode == "unsafe":
            verdict = unsafe(root, archive)
        else:
            verdict = Extractor(root, archive, limits, without).run()
    except Reject as r:
        verdict = {"decision": "reject", "rule": r.rule, "reason": r.detail}
    except Exception as e:
        # Distinct from a rejection on purpose. An extractor that crashes on a hostile
        # archive has not rejected it, and the oracle must be able to tell the difference.
        verdict = {"decision": "crash", "rule": type(e).__name__, "reason": str(e)[:200]}
    verdict["mode"] = mode
    verdict["without"] = sorted(set(without))
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
