#!/usr/bin/env bash
# Measures what extracting the corpus costs the shipped extractor (WORKPLAN-BUNDLES.md T5:
# "run the untouched T2 corpus and resource measurements"; the bombs group: "reject within
# measured memory/time/disk bounds").
#
# The oracle already ENFORCES a wall-clock deadline and a disk budget per fixture; this
# RECORDS, per fixture, wall time, the JVM's peak resident memory and the most bytes the
# extraction root held at any 20 ms sample, and summarises the worst of each. It runs the
# same oracle over the same corpus as dev/validate-oracle-java.sh, with the adapter in its
# measuring mode (SKALD_MEASURE), and it still fails if the oracle does.
#
# The disk figure is sampled, so it is a floor: a peak between two samples is missed.
# Memory is the whole JVM (getrusage of the child), under the adapter's -Xmx256m.
#
# Usage: bash dev/measure-extraction.sh [--full] [ORACLE ARGS...]
#        (--full: the documented default limits, where the bombs are large; slower)

set -uo pipefail
cd "$(dirname "$0")/.."

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
chmod 777 "$out"     # the oracle container runs as root, this script as the user

M2="$HOME/.cache/skald/m2"
bash dev/validate-oracle-java.sh --compile-only \
    || { echo "  FAIL could not compile or build the runner image"; exit 1; }
docker run --rm --user 0:0 --network none -v "$PWD":/ws:ro -v "$M2":/m2:ro \
    -v "$out":/measure -w /ws -e HOME=/tmp -e SKALD_WORLD_BASE=/work \
    -e SKALD_MEASURE=/measure/extraction.jsonl skald-oracle-java \
    python dev/bundle-oracle.py --extractor dev/fixtures/bundles/skald_extractor.py "$@"
status=$?

python3 - "$out/extraction.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
print()
print("== measured: %d extractions ==" % len(rows))
def top(key, unit, scale):
    print("  worst %s:" % key)
    for r in sorted(rows, key=lambda r: -r[key])[:5]:
        print("    %10.1f %s  %-7s %s" % (r[key] / scale, unit, r["decision"],
                                           r["archive"].replace(".tar.gz", "")))
top("seconds", "s  ", 1)
top("peak_rss_kib", "MiB", 1024)
top("peak_root_bytes", "MiB", 1024 * 1024)
by = {}
for r in rows:
    by.setdefault(r["decision"], []).append(r)
for decision, group in sorted(by.items()):
    print("  %-7s n=%-3d  max %.1f s, max %.1f MiB RSS, max %.1f MiB on disk" % (
        decision, len(group), max(r["seconds"] for r in group),
        max(r["peak_rss_kib"] for r in group) / 1024,
        max(r["peak_root_bytes"] for r in group) / (1024 * 1024)))
PY
exit $status
