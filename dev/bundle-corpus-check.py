# Checks the adversarial bundle corpus against itself (WORKPLAN-BUNDLES.md T2).
#
# Three things, none of which is "does the extractor reject it" -- there is no extractor yet,
# and this file must never import one:
#
#   1. Regeneration is deterministic and matches the recorded SHA-256 of every fixture, so a
#      change to the generator that alters a fixture fails here instead of quietly redefining
#      the test.
#   2. Every fixture actually EXHIBITS the property its name claims. A file called
#      trav-dotdot that contains no traversing member is the corpus equivalent of a check
#      that cannot fail, and it is the specific way a corpus rots: someone edits the
#      generator, the fixture becomes benign, and the suite still reports it as covered.
#   3. Every fixture the corpus says to ACCEPT exhibits none of the hostile properties --
#      including being over any configured limit -- so "reject everything" is
#      distinguishable from "works", and a boundary fixture marked accept cannot quietly
#      drift past the boundary it is the accepted half of.
#
# The tar walker below is deliberately hand-written rather than tarfile-based. Several
# fixtures are malformed on purpose -- truncated, bad checksum, NUL in a name -- and a
# library that refuses to parse them would leave exactly those cases uninspectable, which are
# the ones most worth inspecting.

import gzip
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unicodedata

HERE = pathlib.Path("dev/fixtures/bundles")
ok = True


def fail(msg):
    global ok
    ok = False
    print("  FAIL " + msg)


# ----------------------------------------------------------------- a minimal tar reader

def _read_exactly(fh, n):
    buf = b""
    while len(buf) < n:
        chunk = fh.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _skip(fh, n):
    """Consume n bytes without keeping them. Returns False if the stream ran out."""
    left = n
    while left > 0:
        chunk = fh.read(min(left, 1 << 20))
        if not chunk:
            return False
        left -= len(chunk)
    return True


PAX_CAPTURE = 64 * 1024


def walk(source):
    """Yield header dicts from a tar byte STREAM, tolerating malformation.

    `source` is raw bytes or anything with read(n). Streaming rather than slicing a
    buffer is what makes the expansion bombs inspectable at all: a member declaring two
    gigabytes only has to have its header read, and its payload is skipped at constant
    memory. Walking a bounded prefix instead stopped at the first such member, so every
    property that depends on a LATER header -- the total expanded size, a second oversized
    member -- was invisible to a check written to measure exactly those things.

    Returns (members, note). `note` records why walking stopped, which is itself an
    observable property for the truncated and bad-checksum fixtures.
    """
    fh = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source
    members, note = [], None
    pending_name = None      # from a GNU long-name (L) header
    pending_link = None      # from a GNU long-linkname (K) header
    try:
        while True:
            block = _read_exactly(fh, 512)
            if len(block) < 512:
                note = "truncated"
                break
            if block == b"\0" * 512:
                note = "end-marker"
                break
            name = block[0:100].rstrip(b"\0")
            typeflag = block[156:157]
            linkname = block[157:257].rstrip(b"\0")
            mode_field = block[100:108].rstrip(b"\0 ")
            size_field = block[124:136].rstrip(b"\0 ")
            try:
                size = int(size_field, 8) if size_field else 0
            except ValueError:
                size = None  # negative, overflowing or otherwise not octal
            try:
                mode = int(mode_field, 8) if mode_field else 0
            except ValueError:
                mode = 0
            padded = (((size or 0) + 511) // 512) * 512
            # GNU long name/linkname: the real value is this header's PAYLOAD and belongs to
            # the member that follows. Without resolving them, every fixture whose point is a
            # long path is inspected through a placeholder called "././@LongLink" -- which is
            # also why the positive control at the segment limit first tripped the traversal
            # check: the placeholder contains "/./" and the actual name was never read.
            if typeflag in (b"L", b"K"):
                payload = _read_exactly(fh, padded)
                if len(payload) < padded:
                    note = "truncated"
                    break
                payload = payload[:size or 0].rstrip(b"\0")
                if typeflag == b"L":
                    pending_name = payload
                else:
                    pending_link = payload
                continue

            if pending_name is not None:
                name, pending_name = pending_name, None
            if pending_link is not None:
                linkname, pending_link = pending_link, None

            members.append({"name": name, "type": typeflag, "linkname": linkname,
                            "mode": mode, "size": size, "size_field": size_field,
                            "pax": b""})
            # A PAX header's payload IS its content, so it is kept rather than skipped --
            # bounded, because one fixture's whole point is a 256 KiB record. Without it
            # a PAX override can only be substring-matched in the raw prefix, which says
            # some bytes are present, not that an override resolves to anything.
            if typeflag in (b"x", b"g") and padded:
                take = min(padded, PAX_CAPTURE)
                head = _read_exactly(fh, take)
                if len(head) < take:
                    note = "truncated"
                    break
                members[-1]["pax"] = head[:size or 0]
                padded -= take
            if not _skip(fh, padded):
                note = "truncated"
                break
    except Exception as e:
        # A broken gzip stream ends the walk; the members read before it are still real,
        # and `gzip_error` is where that failure is reported as a property.
        note = note or ("stream-error:" + type(e).__name__)
    return members, note


def gunzip(data, limit=64 * 1024 * 1024):
    """Bounded decompression, returning whatever was read before the bound.

    Returning the PREFIX rather than nothing is the point. The expansion bombs are the
    fixtures whose headers most need inspecting, and a reader that discards its buffer on
    hitting a limit cannot see them at all -- which is how bomb-expanded-over-limit first
    appeared not to exhibit its own property. A tar header precedes its payload, so a few
    megabytes is ample to see every header that matters -- 20,000 empty members is about 10 MB
    of headers, so the bound has to clear that -- while still refusing to materialise
    two gigabytes of zeroes.

    Two failures are distinguished: `error` means the gzip stream itself is broken, `capped`
    means it was fine and we chose to stop. Only the first is a property of the fixture.
    """
    out, chunks, error = 0, [], None
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            while True:
                chunk = gz.read(256 * 1024)
                if not chunk:
                    break
                out += len(chunk)
                chunks.append(chunk)
                if out > limit:
                    return b"".join(chunks), None, True
    except Exception as e:
        error = type(e).__name__
    return b"".join(chunks), error, False


PAYLOAD_ROOT = b"app/"

# Every tar type this corpus knows about, so "unknown" is a real question rather than a
# list of the three flags someone happened to think of. L and K are consumed by the
# walker and never reach a member.
KNOWN_TYPEFLAGS = {b"0", b"\0", b"1", b"2", b"3", b"4", b"5", b"6", b"7",
                   b"x", b"g", b"S"}


def payload_path(m):
    """The member's path inside the payload root, which is what the limits apply to.

    The "app/" prefix is the bundle's own wrapper, not something a publisher chose, so
    counting it makes every limit four bytes and one level tighter than documented.
    """
    n = m["name"]
    return n[len(PAYLOAD_ROOT):] if n.startswith(PAYLOAD_ROOT) else n


def segments(m):
    return payload_path(m).rstrip(b"/").split(b"/")


def longest_segment(m):
    return max((len(s) for s in segments(m)), default=0)


def names(members):
    return [m["name"] for m in members]


def decoded(members):
    for m in members:
        try:
            yield m["name"].decode()
        except UnicodeDecodeError:
            continue


# ----------------------------------------------------------------- property predicates
#
# One per fixture, keyed by name. Each answers: does this archive really contain the thing
# the fixture is named after? Written per fixture rather than per group because "a traversal
# fixture" and "a fixture with `..` in a member name" are different claims, and only the
# second is checkable.

def has_member(pred):
    return lambda ctx: any(pred(m) for m in ctx["members"])


def name_contains(needle):
    b = needle if isinstance(needle, bytes) else needle.encode()
    return has_member(lambda m: b in m["name"])


def name_starts(prefix):
    b = prefix if isinstance(prefix, bytes) else prefix.encode()
    return has_member(lambda m: m["name"].startswith(b))


def typeflag(flag):
    return has_member(lambda m: m["type"] == flag)


def mode_bit(bit):
    return has_member(lambda m: m["mode"] & bit)


def duplicate_names(normalise=lambda s: s):
    def check(ctx):
        seen, dupes = set(), False
        for n in decoded(ctx["members"]):
            k = normalise(n.rstrip("/"))
            if k in seen:
                dupes = True
            seen.add(k)
        return dupes
    return check


def over_limit(measure, key):
    """A member measuring past a CONFIGURED limit.

    Reading ctx["limits"] rather than repeating the number is the whole point: a
    predicate that hard-codes 255 or 20000 stops policing its fixture the moment an
    operator changes that limit, and then accuses the fixture of being the stale one.
    """
    return lambda ctx: any(measure(m) > ctx["limits"][key] for m in ctx["members"])


def at_limit(measure, key):
    return lambda ctx: any(measure(m) == ctx["limits"][key] for m in ctx["members"])


def size_of(m):
    return m["size"] or 0


PREDICATES = {
    # accepted fixtures that pin a property. A hostile sweep can only say what a fixture
    # is NOT; these say what it IS, so a boundary half cannot be edited until it stops
    # straddling its limit while the suite stays green (finding 3438045-F1).
    "pos-exact-limit-segment": at_limit(longest_segment, "max_segment_bytes"),
    "pos-exact-limit-depth": at_limit(lambda m: len(segments(m)), "max_depth"),
    "pos-exact-limit-total-path": at_limit(
        lambda m: len(payload_path(m)), "max_path_bytes"),
    "pos-pax-filename": lambda ctx: _pax_path_resolves(ctx),

    # traversal -- the member name itself must carry the escape
    "trav-dotdot": name_contains("app/../.."),
    "trav-embedded": name_contains("../../../.."),
    "trav-absolute": name_starts("/"),
    "trav-drive": name_contains("C:\\"),
    "trav-unc": name_starts("\\\\"),
    "trav-backslash": name_contains("app\\"),
    "trav-dot-segment": name_contains("/./"),
    "trav-empty-segment": name_contains("//"),
    "trav-url-encoded": name_contains("%2e%2e"),
    "trav-pax-override": lambda ctx: (
        any(m["type"] == b"x" for m in ctx["members"])
        and b"path=app/../.." in ctx["raw"]),

    # links -- a symlink or hardlink header must be present, with the target claimed
    "link-symlink-file": has_member(lambda m: m["type"] == b"2" and m["linkname"].startswith(b"/")),
    "link-symlink-dir-then-child": lambda ctx: (
        any(m["type"] == b"2" and m["linkname"] == b"/tmp" for m in ctx["members"])
        and any(m["name"] == b"app/out/escape.txt" for m in ctx["members"])),
    "link-chained": lambda ctx: sum(1 for m in ctx["members"] if m["type"] == b"2") >= 2,
    "link-hardlink-outside": has_member(lambda m: m["type"] == b"1" and m["linkname"].startswith(b"/")),
    "link-symlink-inside": has_member(lambda m: m["type"] == b"2" and not m["linkname"].startswith(b"/")),
    "link-hardlink-inside": has_member(
        lambda m: m["type"] == b"1" and m["linkname"].startswith(PAYLOAD_ROOT)
        and b".." not in m["linkname"]),

    # bombs -- the excess must be real, not merely asserted in the name
    "bomb-entries-at-limit": lambda ctx: len(ctx["members"]) == ctx["limits"]["max_entries"],
    "bomb-entries-over-limit": lambda ctx: len(ctx["members"]) == ctx["limits"]["max_entries"] + 1,
    # The expanded caps are asked of the TOTAL, which is what "expanded" means and what an
    # extractor has to keep a running count of. Only a streaming walk can answer it: the
    # last of these members sits two gigabytes into the stream.
    "bomb-expanded-at-limit": lambda ctx: (
        ctx["declared_total"] == ctx["limits"]["max_expanded_bytes"]
        and max((size_of(m) for m in ctx["members"]), default=0)
        <= ctx["limits"]["max_file_bytes"]),
    "bomb-expanded-over-limit": lambda ctx: (
        ctx["declared_total"] > ctx["limits"]["max_expanded_bytes"]),
    "bomb-file-at-limit": at_limit(size_of, "max_file_bytes"),
    "bomb-file-over-limit": lambda ctx: (
        over_limit(size_of, "max_file_bytes")(ctx)
        and ctx["declared_total"] <= ctx["limits"]["max_expanded_bytes"]),
    "bomb-declared-size-negative": has_member(lambda m: m["size_field"].startswith(b"-")),
    "bomb-declared-size-overflow": has_member(lambda m: m["size_field"] == b"77777777777"),
    "bomb-bad-checksum": lambda ctx: b"9999999" in ctx["raw"],
    "bomb-huge-pax-field": lambda ctx: any(
        m["type"] == b"x" and (m["size"] or 0) > 64 * 1024 for m in ctx["members"]),
    "bomb-sparse-claimed": typeflag(b"S"),
    "bomb-many-empty-entries": lambda ctx: len(ctx["members"]) > ctx["limits"]["max_entries"],
    "bomb-truncated-gzip": lambda ctx: ctx["gzip_error"] is not None,
    # No "and not capped" guard any more: that existed because a truncated walk could be
    # an artifact of our own decompression bound. The streaming walk reads to the archive's
    # end, so truncation is now a property of the fixture and nothing else.
    "bomb-truncated-tar": lambda ctx: ctx["note"] == "truncated",
    "bomb-concatenated-members": lambda ctx: ctx["gzip_members"] >= 2,
    "bomb-trailing-garbage": lambda ctx: ctx["trailing"] > 0,

    # types and path limits
    "type-device": typeflag(b"3"),
    "type-fifo": typeflag(b"6"),
    "type-block-device": typeflag(b"4"),
    "type-setuid": mode_bit(0o4000),
    "type-setgid": mode_bit(0o2000),
    "type-sticky": mode_bit(0o1000),
    "type-unknown-typeflag": has_member(lambda m: m["type"] not in KNOWN_TYPEFLAGS),
    "path-segment-over-limit": over_limit(longest_segment, "max_segment_bytes"),
    "path-total-over-limit": over_limit(lambda m: len(payload_path(m)), "max_path_bytes"),
    "path-depth-over-limit": over_limit(lambda m: len(segments(m)), "max_depth"),
    "path-nul": lambda ctx: b"app/ok.txt\0../../escape.txt" in ctx["raw"],
    "path-control-char": has_member(lambda m: any(c < 0x20 for c in m["name"])),
    "path-invalid-utf8": has_member(
        lambda m: _not_utf8(m["name"])),

    # duplicates
    "dup-regular": duplicate_names(),
    "dup-manifest": lambda ctx: names(ctx["members"]).count(b"manifest.json") == 2,
    "dup-file-then-dir": duplicate_names(),
    "dup-dir-then-file": duplicate_names(),
    "dup-case-alias": duplicate_names(str.lower),
    "dup-nfc-alias": duplicate_names(lambda s: unicodedata.normalize("NFC", s)),
    "dup-repeated-directory": lambda ctx: _repeated_directory(ctx),
    "dup-file-before-parent": lambda ctx: (
        any(m["name"] == b"app/parent/child.txt" for m in ctx["members"])
        and any(m["name"] == b"app/parent" and m["type"] == b"0" for m in ctx["members"])),

    # manifest and inventory
    "manifest-missing": lambda ctx: b"manifest.json" not in names(ctx["members"]),
    "manifest-unsupported-schema-version": lambda ctx: (
        _manifest(ctx).get("schema_version") != 1),
    "manifest-unsupported-language": lambda ctx: (
        _manifest(ctx).get("runtime", {}).get("language") not in ("r", "python")),
    "manifest-late": lambda ctx: _manifest_index(ctx) > 0,
    "manifest-not-json": lambda ctx: _manifest_body(ctx) is not None and not _is_json(ctx),
    "manifest-duplicate-json-key": lambda ctx: (_manifest_body(ctx) or b"").count(b'"type"') == 2,
    "manifest-remote-ref": lambda ctx: b"https://" in (_manifest_body(ctx) or b""),
    "inventory-missing-file": lambda ctx: _inventory_vs_payload(ctx)[0],
    "inventory-extra-file": lambda ctx: _inventory_vs_payload(ctx)[1],
    "inventory-hash-mismatch": lambda ctx: _hash_mismatch(ctx),
    "inventory-size-mismatch": lambda ctx: _size_mismatch(ctx),
    "entrypoint-r-names-a-file": lambda ctx: _manifest(ctx).get("entrypoint") == "app.R",
    "entrypoint-py-names-a-directory": lambda ctx: _manifest(ctx).get("entrypoint") == "src",
    "entrypoint-r-no-layout": lambda ctx: not any(
        n.endswith(("app.R", "ui.R", "server.R")) for n in decoded(ctx["members"])),
    "entrypoint-dir-header-only": lambda ctx: (
        any(m["type"] == b"5" and m["name"].rstrip(b"/").endswith(b"dash")
            for m in ctx["members"])
        and not any(b"dash/" in m["name"] and m["type"] == b"0" for m in ctx["members"])),
    "lockfile-absent": lambda ctx: b"app/renv.lock" not in names(ctx["members"]),
    "language-format-disagreement": lambda ctx: (
        _manifest(ctx).get("runtime", {}).get("language") == "r"
        and _manifest(ctx).get("dependencies", {}).get("format") == "pip-hashed"),
    "unsupported-type": lambda ctx: _manifest(ctx).get("type") == "quarto_static",
    "manifest-over-limit": lambda ctx: len(_manifest_body(ctx) or b"") > 4 * 1024 * 1024
                                       or len(_manifest(ctx).get("files", [])) > 50000,
}


def _pax_records(m):
    """The key/value records in a PAX extended header payload.

    Each record is "<length> <key>=<value>\n", where length counts the whole record
    including its own digits. Parsed rather than substring-matched, because the question
    a PAX fixture has to answer is what the override RESOLVES to.
    """
    out, buf, off = {}, m.get("pax") or b"", 0
    while off < len(buf):
        sp = buf.find(b" ", off)
        if sp < 0:
            break
        try:
            n = int(buf[off:sp])
        except ValueError:
            break
        if n <= sp - off or off + n > len(buf):
            break
        key, _, value = buf[sp + 1:off + n].rstrip(b"\n").partition(b"=")
        out[key] = value
        off += n
    return out


def _pax_path_resolves(ctx):
    """A PAX path override naming a member that is really there, under a UTF-8 name.

    This fixture exists so that an extractor mishandling PAX cannot pass the corpus, so
    the record itself is what has to be asserted. Emptying it leaves the GNU long name
    behind and the archive still looks right from the outside: the fixture degrades from
    "a long UTF-8 filename carried in a PAX override" to "a long name beside an empty PAX
    header", which is the silent rot this suite exists to catch.

    Length is deliberately not asserted. Whether the name exceeds the 100-byte ustar
    field depends on max_segment_bytes, and a predicate that stops holding when an
    operator lowers a limit is the defect this corpus keeps finding in itself.
    """
    present = set(names(ctx["members"]))
    for m in ctx["members"]:
        if m["type"] != b"x":
            continue
        value = _pax_records(m).get(b"path")
        if not value or value not in present:
            continue
        try:
            text = value.decode()
        except UnicodeDecodeError:
            continue
        if any(ord(c) > 127 for c in text):
            return True
    return False


def _repeated_directory(ctx):
    seen = set()
    for m in ctx["members"]:
        if m["type"] == b"5":
            k = m["name"].rstrip(b"/")
            if k in seen:
                return True
            seen.add(k)
    return False


def _not_utf8(raw):
    try:
        raw.decode()
        return False
    except UnicodeDecodeError:
        return True


def _manifest_index(ctx):
    regular = [m for m in ctx["members"] if m["type"] in (b"0", b"\0")]
    for i, m in enumerate(regular):
        if m["name"] == b"manifest.json":
            return i
    return -1


def _manifest_body(ctx):
    off = 0
    raw = ctx["raw"]
    while off + 512 <= len(raw):
        block = raw[off:off + 512]
        if block == b"\0" * 512:
            break
        name = block[0:100].rstrip(b"\0")
        try:
            size = int(block[124:136].rstrip(b"\0 ") or b"0", 8)
        except ValueError:
            size = 0
        if name == b"manifest.json":
            return raw[off + 512:off + 512 + size]
        off += 512 + ((size + 511) // 512) * 512
    return None


def _is_json(ctx):
    try:
        json.loads(_manifest_body(ctx) or b"")
        return True
    except Exception:
        return False


def _manifest(ctx):
    try:
        return json.loads(_manifest_body(ctx) or b"{}")
    except Exception:
        return {}


def _payload_paths(ctx):
    return {m["name"].decode()[len("app/"):] for m in ctx["members"]
            if m["type"] in (b"0", b"\0") and m["name"].startswith(b"app/")
            and not _not_utf8(m["name"])}


def _inventory_vs_payload(ctx):
    declared = {f["path"] for f in _manifest(ctx).get("files", [])}
    actual = _payload_paths(ctx)
    return bool(actual - declared), bool(declared - actual)


def _hash_mismatch(ctx):
    return any(f.get("sha256") == "0" * 64 for f in _manifest(ctx).get("files", []))


def _size_mismatch(ctx):
    for f in _manifest(ctx).get("files", []):
        if f["path"] == "app.R" and f["size"] == 1:
            return True
    return False


# An ACCEPTED fixture must exhibit NONE of these, or "rejects everything" looks like
# "works". The limit entries are here because of finding 29857f7-F1: the only at-limit
# positive control in the corpus was four bytes OVER the segment cap, and nothing noticed,
# because every hostile property was about the shape of a member and none about its size.
# A positive control that violates a documented limit forces a correct extractor to fail
# the suite, which is the worst outcome this corpus can produce.
HOSTILE = {
    "a traversing or absolute name": lambda ctx: any(
        b".." in m["name"] or m["name"].startswith(b"/") or b"\\" in m["name"]
        or b"//" in m["name"] or b"/./" in m["name"] for m in ctx["members"]),
    "a link member": lambda ctx: any(m["type"] in (b"1", b"2") for m in ctx["members"]),
    "a device, fifo or socket": lambda ctx: any(
        m["type"] in (b"3", b"4", b"6") for m in ctx["members"]),
    "a setuid, setgid or sticky bit": lambda ctx: any(
        m["mode"] & 0o7000 for m in ctx["members"]),
    "a duplicate path": duplicate_names(),
    "a non-UTF-8 name": lambda ctx: any(_not_utf8(m["name"]) for m in ctx["members"]),
    "a control character in a name": lambda ctx: any(
        any(c < 0x20 for c in m["name"]) for m in ctx["members"]),
    "a segment over the configured limit": over_limit(longest_segment, "max_segment_bytes"),
    "a path over the configured length limit": over_limit(
        lambda m: len(payload_path(m)), "max_path_bytes"),
    "a path deeper than the configured limit": over_limit(
        lambda m: len(segments(m)), "max_depth"),
    "a member over the configured per-file limit": over_limit(size_of, "max_file_bytes"),
    "more entries than the configured limit": lambda ctx: (
        len(ctx["members"]) > ctx["limits"]["max_entries"]),
    "more expanded bytes than the configured limit": lambda ctx: (
        ctx["declared_total"] > ctx["limits"]["max_expanded_bytes"]),
    "a payload file the manifest never declares": lambda ctx: _inventory_vs_payload(ctx)[0],
    "a declared file the payload never ships": lambda ctx: _inventory_vs_payload(ctx)[1],
}


def context(data, limits):
    trailing, gzip_members = 0, 0
    body, gzip_error, _capped = gunzip(data)
    # Two passes over the same bytes, deliberately. `body` is a bounded prefix, held in
    # memory, and answers the questions that are about raw bytes rather than headers
    # ("does a PAX record say path=app/../.."). The members come from a second, streaming
    # pass that reads every header to the end of the archive at constant memory, so a
    # fixture whose point is the FOURTH half-gigabyte member is still fully inspected.
    gz = gzip.GzipFile(fileobj=io.BytesIO(data))
    try:
        members, note = walk(gz)
    finally:
        try:
            gz.close()
        except Exception:
            pass
    # Count gzip members and any bytes after the last one, without decompressing twice.
    pos, count = 0, 0
    while pos < len(data) and data[pos:pos + 2] == b"\x1f\x8b":
        try:
            d = zlib_skip(data, pos)
        except Exception:
            break
        count += 1
        pos = d
    gzip_members = count
    trailing = len(data) - pos if pos < len(data) else 0
    return {"raw": body or b"", "members": members, "note": note, "limits": limits,
            "gzip_error": gzip_error,
            "declared_total": sum(max(size_of(m), 0) for m in members),
            "gzip_members": gzip_members, "trailing": trailing}


def zlib_skip(data, start):
    """Return the offset just past the gzip member beginning at `start`."""
    import zlib
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    d.decompress(data[start:], 1 << 20)
    while not d.eof:
        if not d.unconsumed_tail and not d.unused_data:
            d.decompress(b"", 1 << 20)
            if not d.eof and not d.unconsumed_tail:
                break
        d.decompress(d.unconsumed_tail, 1 << 20)
    if not d.eof:
        raise ValueError("member did not end")
    return len(data) - len(d.unused_data)


def main():
    exp = json.loads((HERE / "expectations.json").read_text())
    limits = exp["limits"]

    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([sys.executable, str(HERE / "generate.py"), tmp],
                           capture_output=True)
        if r.returncode != 0:
            fail("the generator failed: " + r.stderr.decode()[-400:])
            return 1

        print("== corpus integrity ==")
        produced = sorted(p.name for p in pathlib.Path(tmp).glob("*.tar.gz"))
        recorded = sorted(f["name"] + ".tar.gz" for f in exp["fixtures"])
        if produced != recorded:
            fail("generated set differs from expectations: only-generated=%s only-recorded=%s"
                 % (sorted(set(produced) - set(recorded)), sorted(set(recorded) - set(produced))))
            return 1
        if not exp["fixtures"]:
            fail("expectations.json lists no fixtures, so every check below passes over nothing")
            return 1

        for f in exp["fixtures"]:
            data = (pathlib.Path(tmp) / (f["name"] + ".tar.gz")).read_bytes()
            got = hashlib.sha256(data).hexdigest()
            if got != f["sha256"]:
                fail("%s: regenerated bytes differ from the recorded hash" % f["name"])
                return 1
        print("  ok   %d fixtures regenerated, every SHA-256 matches" % len(exp["fixtures"]))
        print()

        print("== each fixture exhibits its claimed property ==")
        # Keyed on `expect` and `pins`, not on `group`. Three accepted fixtures live in
        # the bombs group because that is where their pair is, and keying on the group
        # name silently exempted them from both halves of this check. `pins` then covers
        # the other direction: an accepted fixture that exists to hold one property must
        # assert it, or the sweep can only report what it is not.
        missing = [f["name"] for f in exp["fixtures"]
                   if (f["expect"] != "accept" or f.get("pins"))
                   and f["name"] not in PREDICATES]
        if missing:
            fail("no property predicate for: %s" % ", ".join(sorted(missing)))
            return 1

        asserted, swept = 0, 0
        for f in exp["fixtures"]:
            data = (pathlib.Path(tmp) / (f["name"] + ".tar.gz")).read_bytes()
            ctx = context(data, limits)
            # A predicate and the hostile sweep are not alternatives. An accepted boundary
            # fixture wants both: that it really sits AT the limit, and that it is over
            # none of the others.
            if f["name"] in PREDICATES:
                if not PREDICATES[f["name"]](ctx):
                    fail("%s does not exhibit the property it is named for: %s"
                         % (f["name"], f["why"]))
                    return 1
                asserted += 1
            if f["expect"] == "accept":
                for label, hostile in HOSTILE.items():
                    if hostile(ctx):
                        fail("accepted fixture %s contains %s" % (f["name"], label))
                        return 1
                if not ctx["members"]:
                    fail("accepted fixture %s has no members" % f["name"])
                    return 1
                swept += 1

        print("  ok   %d fixtures each carry their claimed property" % asserted)
        print("  ok   %d accepted fixtures carry none of the %d hostile properties"
              % (swept, len(HOSTILE)))
        print()

    by_group = {}
    for f in exp["fixtures"]:
        by_group[f["group"]] = by_group.get(f["group"], 0) + 1
    print("  groups: " + ", ".join("%s %d" % kv for kv in sorted(by_group.items())))
    print()
    print("RESULT:", "corpus is internally consistent" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
