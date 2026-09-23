#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""Points the corpus oracle at the extractor that ships (WORKPLAN-BUNDLES.md T5).

The oracle runs its subject as `<python> <subject> --root DIR --archive FILE --limits
JSON`, so a subject has to be a Python file. This one is nothing but that: it replaces
itself with the JVM running BundleExtractorCli (test tree), passes the arguments through
untouched and adds nothing to the verdict. Anything it decided would be a second opinion
the oracle then mistakes for the extractor's.

The classpath comes from target/oracle-classpath.txt, which dev/validate-oracle-java.sh
writes with Maven before the oracle runs. The heap is capped so that "bounded parser
memory" is judged rather than assumed. -XX:+ExitOnOutOfMemoryError ends the JVM at once,
before BundleExtractorCli can print anything, so a bomb that makes the extractor buffer
comes back from the oracle as "no-verdict" -- not "crash" (finding af58f2e-F2). Neither is
ever counted as a rejection.

Usage (by the oracle, not by hand):
    python3 skald_extractor.py --root DIR --archive FILE --limits JSON
"""

import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
HEAP = os.environ.get("SKALD_ORACLE_HEAP", "256m")


def main(argv):
    listing = REPO / "target" / "oracle-classpath.txt"
    if not listing.is_file():
        print("no %s; run dev/validate-oracle-java.sh, which writes it" % listing,
              file=sys.stderr)
        return 2
    classpath = os.pathsep.join([str(REPO / "target" / "test-classes"),
                                 str(REPO / "target" / "classes"),
                                 listing.read_text().strip()])
    java = os.path.join(os.environ.get("JAVA_HOME", "/opt/java/openjdk"), "bin", "java")
    # -XX:-UsePerfData: otherwise the JVM itself writes /tmp/hsperfdata_<user> on every
    # start, and the sentinels -- correctly -- report a write outside the root on every
    # fixture. That file is the runtime's, not the extractor's; with it off, any write
    # outside the root that remains is the extractor's.
    os.execv(java, [java, "-Xmx" + HEAP, "-XX:+ExitOnOutOfMemoryError", "-XX:-UsePerfData",
                    "-cp", classpath,
                    "eu.openanalytics.shinyproxy.publisher.bundle.BundleExtractorCli"]
             + argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
