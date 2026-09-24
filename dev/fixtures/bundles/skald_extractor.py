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
    command = [java, "-Xmx" + HEAP, "-XX:+ExitOnOutOfMemoryError", "-XX:-UsePerfData",
               "-cp", classpath,
               "eu.openanalytics.shinyproxy.publisher.bundle.BundleExtractorCli"] + argv
    measurements = os.environ.get("SKALD_MEASURE")
    if not measurements:
        os.execv(java, command)
    return measured(command, argv, measurements)


def measured(command, argv, measurements):
    """Runs the extractor as a child and appends what it cost to `measurements`.

    Used by dev/measure-extraction.sh, never by an ordinary oracle run, which execs the JVM
    and so adds nothing between the oracle and the subject. Three numbers per fixture:
    wall time; the child's peak resident memory (getrusage, so the whole JVM, not the heap
    alone); and the most bytes the root held at any sample. That last one is sampled every
    20 ms DURING the run because a bomb that is written and then deleted on refusal leaves
    nothing for an after-the-fact check to see; a sample can miss a peak between two
    samples, so it is a floor, and the script says so.
    """
    import json
    import resource
    import subprocess
    import threading
    import time

    root = pathlib.Path(argv[argv.index("--root") + 1])
    peak = {"bytes": 0}
    done = threading.Event()

    def sample():
        while not done.is_set():
            total = 0
            for dirpath, _, files in os.walk(root):
                for name in files:
                    try:
                        total += os.lstat(os.path.join(dirpath, name)).st_size
                    except OSError:
                        pass   # renamed or deleted between the listing and the stat
            peak["bytes"] = max(peak["bytes"], total)
            done.wait(0.02)

    sampler = threading.Thread(target=sample, daemon=True)
    started = time.monotonic()
    child = subprocess.Popen(command, stdout=subprocess.PIPE)
    sampler.start()
    verdict, _ = child.communicate()
    elapsed = time.monotonic() - started
    done.set()
    sampler.join()
    rss_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    try:
        decision = json.loads(verdict.decode()).get("decision")
    except ValueError:
        decision = "no-verdict"
    with open(measurements, "a") as out:
        out.write(json.dumps({"archive": pathlib.Path(argv[argv.index("--archive") + 1]).name,
                              "decision": decision, "seconds": round(elapsed, 3),
                              "peak_rss_kib": rss_kib, "peak_root_bytes": peak["bytes"]})
                  + "\n")
    sys.stdout.buffer.write(verdict)
    sys.stdout.flush()
    return child.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
