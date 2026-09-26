#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Generates publisher/names/UnicodeTables.java from pinned Unicode Character Database files.

The name rule (WORKPLAN-BUNDLES.md, extraction contract, "Invisible characters") refuses
code points that render as nothing, except the two joiners where RFC 5892's ContextJ rules
allow them. That needs three properties the JDK does not expose: Default_Ignorable_Code_Point,
Canonical_Combining_Class = 9 (virama) and Joining_Type. They are generated from the
Unicode files rather than copied by hand, so the table is reproducible and reviewable.

Pinned to Unicode 15.0.0, the version JDK 21 (the build image) implements, so the table and
Character.getType agree about which code points exist. Each file is checked against its
SHA-256 and the run stops on a mismatch.

Unicode data is under the Unicode License v3 (permissive, OSI-approved). The generated
file names it and points at licenses/UNICODE-LICENSE-V3.txt, the full copyright and
permission notice, which is what the license asks for with copies of derived data.

Usage: python3 dev/unicode/generate_invisible_tables.py [--check] [--cache DIR]
  --check   regenerate into memory and fail if the committed file differs
  --cache   where the downloaded files live (default ~/.cache/skald/unicode/15.0.0)
"""

import hashlib
import pathlib
import sys
import urllib.request

VERSION = "15.0.0"
BASE = "https://www.unicode.org/Public/%s/ucd/" % VERSION
FILES = {
    "DerivedCoreProperties.txt": ("DerivedCoreProperties.txt",
        "d367290bc0867e6b484c68370530bdd1a08b6b32404601b8c7accaf83e05628d"),
    "UnicodeData.txt": ("UnicodeData.txt",
        "806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73"),
    "DerivedJoiningType.txt": ("extracted/DerivedJoiningType.txt",
        "c4870b11e2b8b7d0eb70b99ce85608e5c28a399efa316cca97238a58ae160e5e"),
    "DerivedCombiningClass.txt": ("extracted/DerivedCombiningClass.txt",
        "ca54f6360cd288ad92113415bf1f77749015abe11cbd6798d21f7fa81f04205d"),
}
REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "src/main/java/eu/openanalytics/shinyproxy/publisher/names/UnicodeTables.java"


def fetch(cache):
    cache.mkdir(parents=True, exist_ok=True)
    texts = {}
    for name, (path, digest) in FILES.items():
        local = cache / name
        if not local.exists():
            with urllib.request.urlopen(BASE + path, timeout=60) as response:
                local.write_bytes(response.read())
        data = local.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise SystemExit("%s: sha256 %s, expected %s; refusing to generate from it"
                             % (name, actual, digest))
        texts[name] = data.decode("utf-8")
    return texts


def ranges_of(text, keep):
    """(first, last) ranges of the data lines whose property field satisfies keep."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        if not keep(fields[1:]):
            continue
        span = fields[0].split("..")
        out.append((int(span[0], 16), int(span[-1], 16)))
    return merge(out)


def merge(ranges):
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def general_category(text, categories):
    """UnicodeData.txt, including its <..., First>/<..., Last> range pairs."""
    out, start = [], None
    for line in text.splitlines():
        fields = line.split(";")
        cp, name, cat = int(fields[0], 16), fields[1], fields[2]
        if name.endswith(", First>"):
            start = cp
            continue
        first = start if name.endswith(", Last>") else cp
        start = None
        if cat in categories:
            out.append((first, cp))
    return merge(out)


def java_ranges(ranges):
    lines, row = [], []
    for first, last in ranges:
        row.append("0x%04X, 0x%04X," % (first, last))
        if len(row) == 4:
            lines.append("            " + " ".join(row))
            row = []
    if row:
        lines.append("            " + " ".join(row))
    return "\n".join(lines)


def generate(texts):
    ignorable = ranges_of(texts["DerivedCoreProperties.txt"],
                          lambda f: f[0] == "Default_Ignorable_Code_Point")
    invisible_categories = general_category(texts["UnicodeData.txt"], {"Cf", "Zl", "Zp"})
    refused = merge(ignorable + invisible_categories)
    virama = ranges_of(texts["DerivedCombiningClass.txt"], lambda f: f[0] == "9")
    joining = {t: ranges_of(texts["DerivedJoiningType.txt"], lambda f, t=t: f[0] == t)
               for t in ("L", "D", "R", "T")}
    return TEMPLATE % {
        "version": VERSION,
        "refused": java_ranges(refused),
        "virama": java_ranges(virama),
        "left": java_ranges(merge(joining["L"] + joining["D"])),
        "right": java_ranges(merge(joining["R"] + joining["D"])),
        "transparent": java_ranges(joining["T"]),
    }


TEMPLATE = """/*
 * Skald
 *
 * Copyright (C) 2026 Gard Kroken
 *
 * Built on ShinyProxy, Copyright (C) 2016-2026 Open Analytics NV.
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.shinyproxy.publisher.names;

/**
 * GENERATED by dev/unicode/generate_invisible_tables.py from the Unicode Character Database
 * %(version)s. Do not edit; change the generator and rerun it (--check verifies).
 *
 * <p>Derived from Unicode data files. Copyright (C) 1991-2022 Unicode, Inc. Distributed under
 * the Unicode License v3, whose full text is licenses/UNICODE-LICENSE-V3.txt in this
 * repository (https://www.unicode.org/license.txt).
 *
 * <p>Each table is sorted, non-overlapping, inclusive {@code first, last} pairs.
 */
final class UnicodeTables {

    private UnicodeTables() {
    }

    static final String UNICODE_VERSION = "%(version)s";

    /** Default_Ignorable_Code_Point, and general categories Cf, Zl and Zp. */
    static final int[] REFUSED = {
%(refused)s
    };

    /** Canonical_Combining_Class = 9 (Virama). */
    static final int[] VIRAMA = {
%(virama)s
    };

    /** Joining_Type L or D: joins to the character after it. */
    static final int[] JOINS_FORWARD = {
%(left)s
    };

    /** Joining_Type R or D: joins to the character before it. */
    static final int[] JOINS_BACKWARD = {
%(right)s
    };

    /** Joining_Type T: transparent, skipped when deciding what a joiner sits between. */
    static final int[] TRANSPARENT = {
%(transparent)s
    };
}
"""


def main(argv):
    cache = pathlib.Path.home() / ".cache/skald/unicode" / VERSION
    if "--cache" in argv:
        cache = pathlib.Path(argv[argv.index("--cache") + 1])
    text = generate(fetch(cache))
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("UnicodeTables.java differs from what the generator produces")
            return 1
        print("UnicodeTables.java matches Unicode %s" % VERSION)
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print("wrote %s" % OUT.relative_to(REPO))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
