"""Publishes the trusted bases: builds every catalog entry through the mirror, checks it as
dev/bases-probe.py does, pushes it to the operator's registry, and writes the published bases
file that publisher.recipe.BaseCatalog loads (T7, part 3e; 4dd3f76 review N1).

A built base is not byte-reproducible (timestamps, package state), so its digest exists only
once someone has built and pushed it. That is the operator's act, and its record is the
deployment's, not the repository's: the file names the catalog it was built from by
SHA-256, and BaseCatalog refuses it against any other catalog.

Nothing is published that failed a check: the static checks run for every entry first, and
an entry is pushed only after its live checks pass. If anything fails, no file is written.

Usage:
  python3 dev/publish-bases.py --push-to HOST:PORT --registry NAME[:PORT] --out FILE [--only ID]...

  --push-to   where this host pushes (e.g. localhost:5000); log in to it first if it needs it
  --registry  the same registry as the build worker reaches it (e.g. skald-registry:5000);
              the references in the file use this name
  --only      publish only these catalog ids (default: all)
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "bases_probe", pathlib.Path(__file__).resolve().parent / "bases-probe.py")
bases = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bases)

REGISTRY = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[0-9]{1,5})?")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--push-to", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", action="append", default=[])
    a = ap.parse_args(argv)
    for name in (a.push_to, a.registry):
        if not REGISTRY.fullmatch(name):
            raise SystemExit("not a registry host[:port]: %r" % name)
    catalog_bytes = bases.CATALOG.read_bytes()
    catalog_sha = hashlib.sha256(catalog_bytes).hexdigest()
    entries = json.loads(catalog_bytes)["bases"]
    unknown = set(a.only) - {e["id"] for e in entries}
    if unknown:
        raise SystemExit("not in the catalog: %s" % sorted(unknown))
    entries = [e for e in entries if not a.only or e["id"] in a.only]

    print("== publishing %d base(s) from catalog %s ==" % (len(entries), catalog_sha[:12]))
    for e in entries:
        ok, detail = bases.judge_static(e, (bases.REPO / e["dockerfile"]).read_text())
        print("  %s  static: %s  %s" % ("ok  " if ok else "FAIL", e["id"], detail))
        if not ok:
            return 1
    published, local = {}, []
    try:
        bases.start_forge()
        for e in entries:
            tag = "skald-base/%s:publish" % e["id"]
            built = bases.build(e, tag)
            if built.returncode != 0:
                print("  FAIL  built: %s  %s" % (e["id"], (built.stdout + built.stderr).strip()[-300:]))
                return 1
            local.append(tag)
            bases.docker(["pull", "-q", e["upstream"]], timeout=900)
            ok, detail = bases.judge_live(e, bases.facts_of(tag, e["language"]), bases.facts_of(e["upstream"]))
            print("  %s  live: %s  %s" % ("ok  " if ok else "FAIL", e["id"], detail))
            if not ok:
                return 1
            repo = "%s/skald/base/%s" % (a.push_to, e["id"])
            pushed = "%s:c%s" % (repo, catalog_sha[:12])
            bases.docker(["tag", tag, pushed])
            local.append(pushed)
            push = bases.docker(["push", "-q", pushed], timeout=1800)
            if push.returncode != 0:
                print("  FAIL  pushed: %s  %s" % (e["id"], push.stderr.strip()[-300:]))
                return 1
            digests = json.loads(bases.docker(["inspect", "--format", "{{json .RepoDigests}}", pushed]).stdout)
            digest = next((d.split("@", 1)[1] for d in digests if d.startswith(repo + "@")), None)
            if not digest or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                print("  FAIL  pushed: %s  no digest for %s in %s" % (e["id"], repo, digests))
                return 1
            published[e["id"]] = "%s/skald/base/%s@%s" % (a.registry, e["id"], digest)
            print("  ok    pushed: %s  %s" % (e["id"], published[e["id"]]))
    finally:
        bases.docker(["rm", "-f", "-v", bases.FORGE])
        for t in local:
            bases.docker(["rmi", "-f", t])
    out = {"layout_version": 1, "catalog_sha256": catalog_sha, "registry": a.registry, "bases": published}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=2) + "\n")
    print("\nwrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
