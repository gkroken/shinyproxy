#!/usr/bin/env bash
# Traces every extraction in the corpus and checks that none touched a traversal target
# (WORKPLAN-BUNDLES.md T5; "no reads outside the root", deferred from T2). The oracle
# proves nothing outside the root CHANGED; this proves nothing there was even named.
#
# Same oracle, same corpus, same shipped extractor as dev/validate-oracle-java.sh, with the
# adapter in its tracing mode (SKALD_TRACE): each JVM runs under `strace -f -y`, and
# dev/trace-check.py reads the traces. strace (GPL-2.0-or-later) lives only in the
# throwaway image dev/oracle-java-trace, never shipped -- see its Dockerfile.
#
# Order matters: the checker's --self-test runs first, in the same image with the same
# strace flags, and must catch a real touch of every target before any "clean" below means
# anything.
#
# Modes: the reduced profile, --full (the documented limits, where the bombs are large),
# and --symlinked-root. Not --rename-race: its racer swaps the root with the neighbour
# directory on purpose, so the extractor's own descriptors legitimately resolve to
# "neighbour" mid-run and the rule this checks does not apply; the oracle's own
# containment check covers that mode.
#
# Usage: bash dev/trace-extraction.sh [MODE...]   (default: reduced full symlinked-root)

set -uo pipefail
cd "$(dirname "$0")/.."

modes=("$@")
[ ${#modes[@]} -eq 0 ] && modes=(reduced full symlinked-root)

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
chmod 777 "$out"     # the oracle container runs as root, this script as the user

M2="$HOME/.cache/skald/m2"
IMAGE=skald-oracle-java-trace
bash dev/validate-oracle-java.sh --compile-only \
    || { echo "  FAIL could not compile or build the runner image"; exit 1; }
docker build -q -t "$IMAGE" dev/oracle-java-trace >/dev/null \
    || { echo "  FAIL could not build $IMAGE"; exit 1; }

run() {
    docker run --rm --user 0:0 --network none -v "$PWD":/ws:ro -v "$M2":/m2:ro \
        -v "$out":/out -w /ws -e HOME=/tmp -e SKALD_WORLD_BASE=/work "$@"
}

run "$IMAGE" python dev/trace-check.py --self-test \
    || { echo "  FAIL the checker's self-test failed; nothing below would mean anything"
         exit 1; }
echo

status=0
for mode in "${modes[@]}"; do
    case "$mode" in
        reduced)        args=() ;;
        full)           args=(--full) ;;
        symlinked-root) args=(--symlinked-root) ;;
        *) echo "  FAIL unknown mode $mode"; exit 2 ;;
    esac
    echo "######## $mode"
    mkdir -p "$out/$mode" && chmod 777 "$out/$mode"
    # The oracle's own verdict still counts: a trace of a run the oracle failed is no pass.
    run -e SKALD_TRACE="/out/$mode" "$IMAGE" sh -c '
        python dev/bundle-oracle.py --extractor dev/fixtures/bundles/skald_extractor.py "$@" \
            > /out/oracle.txt 2>&1
        oracle=$?
        tail -3 /out/oracle.txt
        n=$(sed -n "s/^== oracle: \([0-9]*\) fixtures.*/\1/p" /out/oracle.txt)
        python dev/trace-check.py "/out/'"$mode"'" --expect "${n:-0}" --world-base /work
        checked=$?
        [ "$oracle" -eq 0 ] && [ "$checked" -eq 0 ]' sh "${args[@]}" \
        || status=1
    echo
done
exit $status
