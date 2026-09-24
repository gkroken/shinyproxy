#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

# The Java oracle runner plus strace, for dev/trace-extraction.sh and nothing else.
#
# strace is GPL-2.0-or-later (LGPL-2.1-or-later for parts). It is installed here, in a
# throwaway test image that is built locally and never pushed, and it is run as a separate
# program that watches the extractor from outside. Nothing of it is linked into, copied
# into or shipped with Skald. Approved by the user on 2026-09-24 on exactly those terms.
#
# Built FROM the image dev/validate-oracle-java.sh builds, which must exist first; the
# script that uses this one builds both.
FROM skald-oracle-java
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*
