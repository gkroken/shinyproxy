#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Regenerates the seed inputs for BundleFuzzTest from the corpus and the manifest fixtures.

The seeds are what Jazzer starts from, and what plain `make test` runs each target on as a
regression. They are derived rather than hand-made so they carry the corpus's structure --
real PAX headers, real directory headers, real manifests -- which is what lets coverage
guidance reach the deep branches quickly. Deterministic: the corpus generator is, and this
sorts. Only small fixtures are taken, so the checked-in seeds stay small.

Usage: python3 dev/fuzz/seeds.py      (writes under src/test/resources/...)
"""

import gzip
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "src/test/resources/eu/openanalytics/shinyproxy/publisher/bundle/BundleFuzzTestInputs"
MAX_GZ, MAX_TAR = 8 * 1024, 32 * 1024
# The same reduced profile the oracle uses, so boundary fixtures stay small.
LIMITS = ["max_compressed_bytes=4194304", "max_expanded_bytes=50331648",
          "max_file_bytes=12582912", "max_entries=400", "max_manifest_bytes=524288"]


# Files Jazzer writes when it finds something. They are regression inputs in their own
# right and must survive a regeneration; everything else in the tree is derived and is not.
FINDINGS = ("crash-", "timeout-", "oom-", "slow-unit-")


def main():
    dirs = {name: OUT / name for name in ("gzipMember", "tarStream", "extractor", "manifest",
                                          "tarHeader", "paxRecords", "memberPath")}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
        for f in d.iterdir():
            if not f.name.startswith(FINDINGS):
                f.unlink()
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(REPO / "dev/fixtures/bundles/generate.py"), tmp,
                        "--limit"] + LIMITS, check=True, capture_output=True)
        for archive in sorted(pathlib.Path(tmp).glob("*.tar.gz")):
            raw = archive.read_bytes()
            if len(raw) > MAX_GZ:
                continue
            name = archive.name[:-len(".tar.gz")]
            (dirs["gzipMember"] / name).write_bytes(raw)
            try:
                tar = gzip.decompress(raw)
            except Exception:
                continue          # the malformed-gzip fixtures seed the gzip target only
            if len(tar) > MAX_TAR:
                continue
            (dirs["tarStream"] / name).write_bytes(tar)
            (dirs["extractor"] / name).write_bytes(tar)
            (dirs["tarHeader"] / name).write_bytes(tar[:512])
            # Every PAX payload in the archive, walked with the same framing the parser uses.
            offset = 0
            while offset + 512 <= len(tar):
                header = tar[offset:offset + 512]
                if header == bytes(512):
                    break
                try:
                    size = int(header[124:136].strip(b"\0 ") or b"0", 8)
                except ValueError:
                    break
                body = tar[offset + 512: offset + 512 + size]
                if header[156:157] in (b"x", b"g"):
                    (dirs["paxRecords"] / ("%s-%d" % (name, offset))).write_bytes(body)
                elif header[156:157] in (b"0", b"\0", b"5"):
                    # The flag byte FIRST: BundleFuzzTest.parseMemberPathInput defines
                    # the layout (byte 0's low bit, then the name). It used to be read
                    # through a FuzzedDataProvider, which takes a boolean from the END,
                    # so every name here began with this byte -- a NUL, or 0x01.
                    directory = b"\x01" if header[156:157] == b"5" else b"\x00"
                    (dirs["memberPath"] / ("%s-%d" % (name, offset))).write_bytes(
                        directory + header[:100].rstrip(b"\0"))
                offset += 512 + ((size + 511) // 512) * 512
    # A handful of well-formed PAX records beside the two the corpus carries, so the record
    # grammar (length, keyword, '=', value, newline) is reachable from the first run.
    for i, (key, value) in enumerate([(b"path", b"app/www/r\xc3\xa9sum\xc3\xa9.txt"),
                                      (b"mtime", b"1726000000.5"), (b"size", b"12"),
                                      (b"comment", b"x" * 40)]):
        body = key + b"=" + value + b"\n"
        n = len(body) + 1
        while len(str(n).encode()) + 1 + len(body) != n:
            n += 1
        (dirs["paxRecords"] / ("record-%d" % i)).write_bytes(str(n).encode() + b" " + body)
    # Every Cc code point in a member name, each its own seed, so the regression run
    # exercises the control rule at every point and the fuzzer starts from both sides of
    # each range edge (t5-e5e3071-F1). Plus the neighbours, which must be accepted.
    for cp in list(range(0x00, 0x20)) + list(range(0x7F, 0xA0)) + [0x20, 0x7E, 0xA0]:
        (dirs["memberPath"] / ("codepoint-%04X" % cp)).write_bytes(
            b"\x00" + ("app/a%sb.txt" % chr(cp)).encode("utf-8"))
    for fixture in sorted((REPO / "dev/fixtures/manifests").glob("*/*.json")):
        (dirs["manifest"] / (fixture.parent.name + "-" + fixture.stem)).write_bytes(
            fixture.read_bytes())
    for d in sorted(dirs.values()):
        files = list(d.iterdir())
        print("%-12s %3d seeds, %6d bytes" % (d.name, len(files),
                                              sum(f.stat().st_size for f in files)))


if __name__ == "__main__":
    main()
