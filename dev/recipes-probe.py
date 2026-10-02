#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The generated recipes, built and run (WORKPLAN-BUNDLES.md T7, part 2).

Builds EXACTLY the golden recipes under dev/fixtures/recipes/ -- which RecipeGeneratorTest
holds equal to RecipeGenerator's output -- for the two fixture apps under dev/fixtures/apps/,
through forge, on the trusted bases built from images/. The only text substituted is the FROM
line's placeholder digest: the bases are built here, pushed to a throwaway registry, and
named by the digest that push returns, as a build names its base.

Checked for each app, in the real container:
  built     the generated Dockerfile builds, with the app's OWN copy of its lockfile
            replaced by garbage. The recipe installs skald/<lock> (the policy's rendering);
            if any instruction read app/<lock>, the restore would fail (1a66ae7 review N1)
  served    GET / on the published port answers 200 with Shiny's page
  user      every process in the container runs as uid 10001, PID 1 included
  read-only the app cannot write its own directory (/app is copied root-owned)

The run is hardened the way a content container will be (--cap-drop ALL,
no-new-privileges); the full runtime projection is T9's. Builds here use docker build with
--network host, as bases-probe does; the isolated rootless BuildKit driver is T7 part 3.

Usage: python3 dev/recipes-probe.py [--self-test]
  --self-test also runs live mutants on the Python recipe: no USER line (caught by the user
  check), a recipe that installs the app's own (poisoned) lock (caught at build), a lock
  missing a dependency (caught by pip check at build), a wrong hash (caught by
  --require-hashes at build).
"""

import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO / "dev/fixtures/recipes"
APPS = REPO / "dev/fixtures/apps"
PLACEHOLDER = "@sha256:" + "0" * 64
REGISTRY, REGISTRY_PORT = "skald-recipes-registry", 18084

_spec = importlib.util.spec_from_file_location("bases_probe", REPO / "dev/bases-probe.py")
bases = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bases)
docker = bases.docker

# name -> (catalog language, the placeholder reference in the golden FROM line, lock name)
APPS_UNDER_TEST = {
    "r-shiny": ("r", "skald-probe.invalid/base/r-shiny" + PLACEHOLDER, "renv.lock"),
    "python-shiny": ("python", "skald-probe.invalid/base/python-shiny" + PLACEHOLDER,
                     "requirements.lock"),
}
GARBAGE = {"renv.lock": '{"broken": ', "requirements.lock":
           "--index-url http://evil.invalid/simple\nnot a lock at all\n"}

results = []


def record(name, observed, ok):
    results.append({"name": name, "observed": observed, "ok": ok})
    print("  %-6s %-40s %s" % ("ok" if ok else "FAIL", name, observed))


def from_line(dockerfile, placeholder, reference):
    """The golden Dockerfile with its one placeholder reference replaced."""
    if dockerfile.count(placeholder) != 1:
        raise SystemExit("the golden FROM placeholder %s appears %d times"
                         % (placeholder, dockerfile.count(placeholder)))
    return dockerfile.replace(placeholder, reference)


def context(name, reference, dockerfile=None, lock=None):
    """(tmp, context dir, Dockerfile path): app/ is the fixture with its own lock poisoned,
    skald/ the golden rendering (or a mutant's), the Dockerfile outside the context."""
    _, placeholder, lock_name = APPS_UNDER_TEST[name]
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="skald-recipe-"))
    ctx = tmp / "ctx"
    shutil.copytree(APPS / name, ctx / "app")
    (ctx / "app" / lock_name).write_text(GARBAGE[lock_name])
    shutil.copytree(GOLDEN / name / "skald", ctx / "skald")
    if lock is not None:
        (ctx / "skald" / lock_name).write_text(lock)
    text = dockerfile if dockerfile is not None else (GOLDEN / name / "Dockerfile").read_text()
    (tmp / "Dockerfile").write_text(from_line(text, placeholder, reference))
    return tmp, ctx, tmp / "Dockerfile"


def build(tag, ctx, dockerfile):
    return docker(["build", "--progress", "plain", "--network", "host", "-t", tag,
                   "-f", str(dockerfile), str(ctx)], timeout=3600)


def serve(tag, container):
    """(ok, detail) for served, user and read-only, on a running container of tag."""
    docker(["rm", "-f", container])
    run = docker(["run", "-d", "--name", container, "--cap-drop", "ALL", "--security-opt",
                  "no-new-privileges", "-p", "127.0.0.1::3838", tag])
    if run.returncode != 0:
        return {"served": (False, "did not start: " + run.stderr.strip()[-200:])}
    port = docker(["port", container, "3838/tcp"]).stdout.strip().splitlines()[0].rsplit(":", 1)[1]
    status, body, deadline = None, "", time.time() + 180
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:%s/" % port, timeout=5) as r:
                status, body = r.status, r.read().decode("utf-8", "replace")
                break
        except Exception:
            time.sleep(2)
    out = {}
    shiny_page = status == 200 and "shiny" in body.lower()
    out["served"] = (shiny_page, "HTTP %s, %d bytes%s" % (status, len(body),
                     ", a Shiny page" if shiny_page else ": " + docker(
                         ["logs", "--tail", "5", container]).stderr.strip()[-200:]))
    top = docker(["top", container, "-eo", "pid,uid,args"]).stdout.strip().splitlines()[1:]
    uids = sorted({line.split()[1] for line in top})
    out["user"] = (bool(top) and uids == ["10001"],
                   "%d process(es), uid(s) %s" % (len(top), ",".join(uids) or "none"))
    touch = docker(["exec", container, "sh", "-c", "touch /app/written 2>&1"])
    out["read-only"] = (touch.returncode != 0, "touch /app/written: "
                        + (touch.stdout.strip()[-80:] or "SUCCEEDED"))
    docker(["rm", "-f", container])
    return out


def bases_in_registry():
    """{language: digest reference} for every catalog base, built through forge and pushed."""
    docker(["rm", "-f", REGISTRY])
    docker(["run", "-d", "--name", REGISTRY, "-p", "127.0.0.1:%d:5000" % REGISTRY_PORT,
            "registry:2"])
    refs = {}
    for entry in bases.catalog()["bases"]:
        tag = "skald-base/%s:probe" % entry["id"]
        built = bases.build(entry, tag)
        if built.returncode != 0:
            raise SystemExit("base %s did not build: %s" % (entry["id"], built.stderr[-300:]))
        pushed = "localhost:%d/skald/base/%s:probe" % (REGISTRY_PORT, entry["id"])
        docker(["tag", tag, pushed])
        push = docker(["push", "-q", pushed], timeout=900)
        if push.returncode != 0:
            raise SystemExit("push failed: " + push.stderr[-300:])
        digests = json.loads(docker(["inspect", "--format", "{{json .RepoDigests}}",
                                     pushed]).stdout)
        ref = next(d for d in digests if d.startswith("localhost:%d/" % REGISTRY_PORT))
        refs[entry["language"]] = ref
        docker(["rmi", "-f", tag, pushed])
    return refs


def main(argv):
    print("== the generated recipes, built through forge and run ==")
    print()
    tags = []
    try:
        bases.start_forge()
        refs = bases_in_registry()
        for name, (language, _, _) in APPS_UNDER_TEST.items():
            tag = "skald-app/%s:probe" % name
            tmp, ctx, dockerfile = context(name, refs[language])
            try:
                built = build(tag, ctx, dockerfile)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            record("built: " + name, "from %s, app's own lock poisoned" % refs[language]
                   if built.returncode == 0 else "BUILD FAILED: "
                   + (built.stdout + built.stderr).strip()[-300:], built.returncode == 0)
            if built.returncode != 0:
                continue
            tags.append(tag)
            for check, (ok, detail) in serve(tag, "skald-recipe-" + name).items():
                record("%s: %s" % (check, name), detail, ok)
        if "--self-test" in argv:
            self_test(refs["python"])
    finally:
        docker(["rm", "-f", bases.FORGE, REGISTRY])
        for tag in tags:
            docker(["rmi", "-f", tag])
    bad = [r for r in results if not r["ok"]]
    print()
    print("RESULT:", "both recipes build, serve and run unprivileged" if not bad
          else "%d check(s) FAILED" % len(bad))
    return 0 if not bad else 1


def self_test(python_ref):
    """Each live check must catch what it exists for, on a real build."""
    print()
    print("== self-test (live, Python recipe) ==")
    name = "python-shiny"
    golden = (GOLDEN / name / "Dockerfile").read_text()
    lock = (GOLDEN / name / "skald/requirements.lock").read_text()

    def mutant(label, dockerfile=None, lock_text=None, expect_build_failure=None, check=None):
        tag = "skald-app/selftest:probe"
        tmp, ctx, df = context(name, python_ref, dockerfile, lock_text)
        try:
            built = build(tag, ctx, df)
            log = built.stdout + built.stderr
            if expect_build_failure:
                ok = built.returncode != 0 and expect_build_failure in log
                record("self-test: " + label, "build refused (%s)" % expect_build_failure
                       if ok else "NOT refused as expected: " + log.strip()[-200:], ok)
            else:
                if built.returncode != 0:
                    record("self-test: " + label, "mutant did not build: " + log[-200:], False)
                    return
                ok, detail = serve(tag, "skald-recipe-selftest")[check]
                record("self-test: " + label, ("caught: " + detail) if not ok
                       else "NOT caught: " + detail, not ok)
        finally:
            docker(["rmi", "-f", tag])
            shutil.rmtree(tmp, ignore_errors=True)

    no_user = golden.replace("USER 10001:10001\n", "")
    if no_user == golden:
        record("self-test: no USER line", "the mutant did not apply", False)
    else:
        mutant("no USER line", dockerfile=no_user, check="user")
    starlette = [i for i, l in enumerate(lock.splitlines()) if l.startswith("starlette==")]
    lines = lock.splitlines()
    incomplete = "\n".join(lines[:starlette[0]] + lines[starlette[0] + 2:]) + "\n"
    if incomplete == lock or "starlette" in incomplete:
        record("self-test: a lock missing starlette", "the mutant did not apply", False)
    else:
        mutant("a lock missing starlette", lock_text=incomplete,
               expect_build_failure="which is not installed")
    # The "built" check's own mutant: a recipe that installs the app's copy of the lock (the
    # poisoned one) instead of the rendering must fail to build, or "built" proves nothing.
    reads_upload = golden.replace("COPY skald/requirements.lock ", "COPY app/requirements.lock ")
    if reads_upload == golden:
        record("self-test: installs the upload", "the mutant did not apply", False)
    else:
        mutant("installs the upload", dockerfile=reads_upload,
               expect_build_failure="Invalid requirement: 'not a lock at all'")
    first_hash = lock.split("--hash=sha256:", 1)[1][:64]
    mutant("a wrong hash", lock_text=lock.replace(first_hash, "0" * 64),
           expect_build_failure="DO NOT MATCH THE HASHES")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
