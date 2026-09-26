#!/usr/bin/env bash
# What build code cannot do from a RUN step (WORKPLAN-BUNDLES.md T5, gate finding
# t5-e5e3071-F6 part 2; decision 6's isolation table).
#
# Under the worker the shipping profile launches, each attempt in the table is made from
# inside a real RUN and must be refused, with an allow control beside it. See
# dev/run-attack-probe.py.
#
# Builds the worker image, an internal network, a registry behind the egress gateway and
# one worker, runs the attempts, and removes all of it including on failure.
#
# Usage: bash dev/validate-run-attacks.sh [--json]
#        bash dev/validate-run-attacks.sh --self-test   (each judge catches an escape)
set -uo pipefail
cd "$(dirname "$0")/.."
exec python3 dev/run-attack-probe.py "$@"
