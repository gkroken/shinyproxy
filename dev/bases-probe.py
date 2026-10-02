#!/usr/bin/env python3
#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The trusted bases, built and checked (WORKPLAN-BUNDLES.md T7; "Base images, recipes and
runtime projection").

images/catalog.json records, for every base, the upstream digest it is FROM, the language
version, the package-manager version, the OS and the unprivileged user. This builds every
entry from its reviewed Dockerfile through the configured mirror -- forge (github.com/gkroken/
forge), the user's choice of 2026-10-02 -- and checks each recorded fact against the BUILT
image, not against the Dockerfile's text. A catalog that says renv 1.3.0 over an image that
has 1.2.x is the kind of record this project keeps catching.

Two kinds of check:
  static  the catalog and the Dockerfiles agree (upstream digest, renv version and hash, the
          system packages apt installs, a licence for every added package), every upstream
          is digest-pinned, and no package-manager invocation is in a form this cannot read
  live    inside each built image: exact language version, package-manager version, OS, the
          uid 10001 user, the EXACT set of OS packages the base adds over its upstream
          (explicit plus pulled in, so a transitive surprise is caught too), and for R that NO repository is configured -- rocker defaults to
          Posit Package Manager (p3m.dev), which the user does not want, and a default baked
          into the base is one a build could silently resolve against

Usage: python3 dev/bases-probe.py [--json] [--self-test]
"""

import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
CATALOG = REPO / "images/catalog.json"
# forge, pinned. Its eval mode (no flags) seeds cran-public (hosted + a proxy of CRAN) and
# pypi-public (hosted + a proxy of PyPI), which is all a base build needs.
FORGE_IMAGE = ("ghcr.io/gkroken/forge@sha256:"
               "fe3a82e5d96084238de8c6871193a1d0af8659eb5f80c22a5f35c223628a3757")
FORGE, FORGE_PORT = "skald-bases-forge", 18081
MIRROR = "http://localhost:%d/repository/cran-public/" % FORGE_PORT

results = []


def record(name, expectation, observed, ok, note=""):
    results.append({"name": name, "expectation": expectation, "observed": observed, "ok": ok,
                    "note": note})
    print("  %-6s %-46s %s" % ("ok" if ok else "FAIL", name, observed))
    if note:
        print("         %s" % note)


def docker(args, **kw):
    return subprocess.run(["docker"] + args, capture_output=True, text=True, **kw)


def catalog():
    return json.loads(CATALOG.read_text())


def arg_default(dockerfile_text, name):
    m = re.search(r"^ARG %s=(\S+)\s*$" % re.escape(name), dockerfile_text, re.M)
    return m.group(1) if m else None


# ------------------------------------------------------------------ judges (pure)

def judge_static(entry, dockerfile_text):
    """(ok, detail): the catalog entry and its Dockerfile agree, and the upstream is pinned."""
    problems = []
    upstream = arg_default(dockerfile_text, "UPSTREAM")
    if upstream != entry["upstream"]:
        problems.append("Dockerfile UPSTREAM %s != catalog %s" % (upstream, entry["upstream"]))
    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", entry["upstream"]):
        problems.append("upstream %s is not digest-pinned" % entry["upstream"])
    renv = entry["package_manager"].get("renv")
    if renv is not None and arg_default(dockerfile_text, "RENV_VERSION") != renv:
        problems.append("Dockerfile RENV_VERSION %s != catalog %s"
                        % (arg_default(dockerfile_text, "RENV_VERSION"), renv))
    if renv is not None:
        # The toolchain's BYTES are pinned, not only its version (4dd3f76-F1).
        sha = entry.get("package_manager_sha256", {}).get("renv")
        if not sha or not re.fullmatch(r"[0-9a-f]{64}", sha):
            problems.append("catalog gives no SHA-256 for renv")
        elif arg_default(dockerfile_text, "RENV_SHA256") != sha:
            problems.append("Dockerfile RENV_SHA256 %s != catalog %s"
                            % (arg_default(dockerfile_text, "RENV_SHA256"), sha))
    installed = apt_installed(dockerfile_text)
    if installed != sorted(entry["system_packages"]):
        problems.append("Dockerfile apt-installs %s != catalog system_packages %s"
                        % (installed, sorted(entry["system_packages"])))
    problems += unreadable_package_commands(dockerfile_text)
    added = set(entry["system_packages"]) | set(entry["system_packages_pulled_in"])
    if set(entry["system_package_licenses"]) != added:
        problems.append("system_package_licenses covers %s, the base adds %s"
                        % (sorted(entry["system_package_licenses"]), sorted(added)))
    return not problems, "; ".join(problems) or "Dockerfile and catalog agree"


# The only package-manager forms a base may use: what apt_installed reads, and the index
# refresh before it. Anything else -- `apt install`, `apt-get -y install`, dpkg -i, aptitude
# -- would install packages apt_installed cannot see, so it is refused rather than parsed
# (9a21ce5 review N1).
READABLE_PACKAGE_COMMANDS = ("apt-get update", "apt-get install -y --no-install-recommends ")


def unreadable_package_commands(dockerfile_text):
    instructions = "\n".join(l for l in dockerfile_text.splitlines()
                             if not l.lstrip().startswith("#"))
    problems = []
    # A path-qualified command (/usr/bin/apt-get) is matched from its first '/', so it can
    # never start a readable form and is refused (6774bde review). A path that merely
    # CONTAINS "apt" as a directory (/var/lib/apt/lists) is not a command: the name must not
    # be followed by '/'.
    for m in re.finditer(r"(?<![\w/.-])(?:/[\w.-]+)*/?(?<![\w.-])(apt-get|apt|aptitude|dpkg)"
                         r"(?![\w/.-])", instructions):
        if not instructions.startswith(READABLE_PACKAGE_COMMANDS, m.start()):
            problems.append("a package-manager command this cannot read: %r"
                            % instructions[m.start():m.start() + 40].split("\n")[0])
    return problems


def apt_installed(dockerfile_text):
    """The package names every `apt-get install` in the Dockerfile names, sorted."""
    names = []
    for m in re.finditer(r"apt-get install((?:\s+(?:\\\n)?\s*[^\s&\\]+)+)", dockerfile_text):
        names += [w for w in m.group(1).split() if not w.startswith("-") and w != "\\"]
    return sorted(names)


def judge_live(entry, facts, upstream_facts=None):
    """(ok, detail): what the built image reports, against the catalog."""
    problems = []
    if facts.get("version") != entry["version"]:
        problems.append("%s version %s, catalog %s" % (entry["language"], facts.get("version"),
                                                      entry["version"]))
    for tool, want in entry["package_manager"].items():
        if facts.get(tool) != want:
            problems.append("%s %s, catalog %s" % (tool, facts.get(tool), want))
    if not str(facts.get("os", "")).startswith(entry["os"]):
        problems.append("os %s, catalog %s" % (facts.get("os"), entry["os"]))
    have = installed_packages(facts)
    for pkg in entry["system_packages"]:
        if pkg not in have:
            problems.append("system package %s is not installed" % pkg)
    if upstream_facts is not None:
        added = set(have) - set(installed_packages(upstream_facts))
        recorded = set(entry["system_packages"]) | set(entry["system_packages_pulled_in"])
        if added - recorded:
            problems.append("the base adds OS packages the catalog does not record: %s"
                            % sorted(added - recorded))
        if recorded - added:
            problems.append("the catalog records OS packages the base does not add: %s"
                            % sorted(recorded - added))
    if facts.get("uid") != entry["user"].split(":")[0]:
        problems.append("user skald has uid %s, catalog %s" % (facts.get("uid"), entry["user"]))
    if entry["language"] == "r":
        repos = facts.get("repos", "")
        if "p3m" in repos or "rspm" in repos.lower() or "packagemanager" in repos:
            problems.append("R is configured to use Posit Package Manager: %s" % repos)
        elif repos not in ("@CRAN@", ""):
            problems.append("R has a default repository baked in: %s" % repos)
        # R's own default agent is "R (<version> <platform> ...)"; PPM's binary-selecting one,
        # which rocker sets, prefixes "R/<version> ".
        if facts.get("agent", "").startswith("R/"):
            problems.append("R sends PPM's binary-selecting user agent: %s" % facts.get("agent"))
    if problems:
        return False, "; ".join(problems)
    added = sorted(set(have) - set(installed_packages(upstream_facts or {"dpkg": ""}))) \
        if upstream_facts is not None else []
    return True, "every recorded fact holds" + (
        "; adds " + ", ".join("%s=%s" % (p, have[p]) for p in added) if added else "")


def installed_packages(facts):
    """{name: version} from the dpkg fact ("name=version" tokens)."""
    return dict(tok.split("=", 1) if "=" in tok else (tok, "")
                for tok in facts.get("dpkg", "").split())


# ------------------------------------------------------------------ the run

FACTS = {
    "r": ("R --version | head -1 | awk '{print \"version=\"$3}';"
          " Rscript --vanilla -e 'cat(\"renv=\", as.character(packageVersion(\"renv\")), \"\\n\", sep=\"\")';"
          " R --quiet --no-echo -e 'cat(\"repos=\", paste(getOption(\"repos\"), collapse=\",\"), \"\\n\", sep=\"\");"
          " cat(\"agent=\", getOption(\"HTTPUserAgent\"), \"\\n\", sep=\"\")';"),
    "python": ("python -c 'import platform; print(\"version=\" + platform.python_version())';"
               " pip --version | awk '{print \"pip=\"$2}';"),
}
COMMON = ". /etc/os-release; echo os=$NAME $VERSION_ID; echo uid=$(id -u skald);"
# Names of the packages dpkg reports fully installed (not merely known or config-files).
DPKG = (" echo dpkg=$(dpkg-query -W -f='${db:Status-Status} ${Package}=${Version}\\n'"
        " | awk '$1 == \"installed\" {print $2}' | tr '\\n' ' ')")


def facts_of(image, language=None):
    """The image's facts; with no language, only the OS-level ones (for an upstream)."""
    script = (FACTS[language] + COMMON + DPKG) if language else DPKG
    out = docker(["run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c",
                  script], timeout=300)
    facts = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            facts[k.strip()] = v.strip()
    if facts.get("os"):
        facts["os"] = facts["os"].replace("Debian GNU/Linux", "Debian").replace(" LTS", "")
    return facts


def start_forge():
    docker(["rm", "-f", "-v", FORGE])
    docker(["run", "-d", "--name", FORGE, "-p", "%d:8080" % FORGE_PORT, "--read-only",
            "--tmpfs", "/data:uid=65532,gid=65532", FORGE_IMAGE])
    for _ in range(30):
        if docker(["exec", FORGE, "/forge", "-healthcheck", "-addr", ":8080"]).returncode == 0:
            return
        subprocess.run(["sleep", "1"])
    raise SystemExit("forge did not become healthy: %s" % docker(["logs", FORGE]).stdout[-300:])


def build(entry, tag, dockerfile=None):
    path = REPO / (dockerfile or entry["dockerfile"])
    args = ["build", "-q", "--network", "host", "-t", tag, "-f", str(path)]
    if entry["language"] == "r":
        args += ["--build-arg", "CRAN_MIRROR=" + MIRROR]
    return docker(args + [str(path.parent)], timeout=1800)


def main(argv):
    print("== the trusted bases, built through forge and checked ==")
    print()
    entries = catalog()["bases"]
    ids = [e["id"] for e in entries]
    record("catalog ids are unique", "", "%d entries" % len(ids), len(ids) == len(set(ids)))
    for entry in entries:
        ok, detail = judge_static(entry, (REPO / entry["dockerfile"]).read_text())
        record("static: " + entry["id"], "", detail, ok)
    if "--self-test" in argv:
        return self_test()
    tags = []
    try:
        start_forge()
        for entry in entries:
            tag = "skald-base/%s:probe" % entry["id"]
            built = build(entry, tag)
            if built.returncode != 0:
                record("built: " + entry["id"], "", "BUILD FAILED: %s"
                       % (built.stdout + built.stderr).strip()[-300:], False)
                continue
            tags.append(tag)
            # The upstream's own package set, for the exact-difference check. Pulled by
            # digest: the build's copy lives in BuildKit's store, not necessarily docker's.
            docker(["pull", "-q", entry["upstream"]], timeout=900)
            ok, detail = judge_live(entry, facts_of(tag, entry["language"]),
                                    facts_of(entry["upstream"]))
            record("live: " + entry["id"], "", detail, ok)
    finally:
        docker(["rm", "-f", "-v", FORGE])
        for tag in tags:
            docker(["rmi", "-f", tag])
    bad = [r for r in results if not r["ok"]]
    print()
    print("RESULT:", "every base is what the catalog says" if not bad
          else "%d check(s) FAILED" % len(bad))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    return 0 if not bad else 1


def self_test():
    """Each judge must catch what it exists for, and one live case: rocker's own Rprofile
    left in place must be caught on a real image, not only on a string."""
    print()
    print("== self-test ==")
    missed = []
    r = next(e for e in catalog()["bases"] if e["language"] == "r")
    good = {"version": r["version"], "renv": "1.3.0", "os": "Ubuntu 24.04", "uid": "10001",
            "repos": "@CRAN@", "agent": "R (4.6.1 x86_64-pc-linux-gnu x86_64 linux-gnu)",
            "dpkg": "base-files=13 libuv1-dev=1 pkg-config=1 zlib1g-dev=1 libpkgconf3=1"
                    " libuv1t64=1 pkgconf=1 pkgconf-bin=1"}
    upstream = {"dpkg": "base-files=13"}

    def expect(label, judged, want):
        ok, detail = judged
        print("  %s %s (%s)" % ("ok  " if ok == want else "FAIL", label, detail[:90]))
        if ok != want:
            missed.append(label)

    clean = good
    expect("PPM's user agent is caught", judge_live(r, dict(clean, agent=
           "R/4.6.1 R (4.6.1 x86_64-pc-linux-gnu x86_64 linux-gnu)")), False)
    expect("a PPM repository is caught", judge_live(r, dict(clean, repos=
           "https://p3m.dev/cran/__linux__/noble/latest")), False)
    expect("any baked-in repository is caught", judge_live(r, dict(clean, repos=
           "https://cloud.r-project.org")), False)
    expect("a wrong renv is caught", judge_live(r, dict(clean, renv="1.2.0")), False)
    expect("a wrong R is caught", judge_live(r, dict(clean, version="4.6.0")), False)
    expect("a root or missing user is caught", judge_live(r, dict(clean, uid="")), False)
    expect("a missing system package is caught", judge_live(r, dict(clean, dpkg=
           clean["dpkg"].replace(" zlib1g-dev=1", "")), upstream), False)
    expect("an unrecorded added package is caught (transitive surprise)", judge_live(
           r, dict(clean, dpkg=clean["dpkg"] + " libssl-dev=3"), upstream), False)
    expect("a recorded package the base does not add is caught", judge_live(
           r, clean, {"dpkg": "base-files=13 pkgconf=1"}), False)
    expect("the clean facts pass", judge_live(r, clean, upstream), True)
    text = (REPO / r["dockerfile"]).read_text()
    expect("an unpinned upstream is caught", judge_static(dict(r, upstream="rocker/r-ver:4.6.1"),
           text.replace(r["upstream"], "rocker/r-ver:4.6.1")), False)
    expect("a Dockerfile/catalog renv mismatch is caught",
           judge_static(r, text.replace("RENV_VERSION=1.3.0", "RENV_VERSION=1.2.0")), False)
    expect("a Dockerfile/catalog renv hash mismatch is caught",
           judge_static(r, text.replace(r["package_manager_sha256"]["renv"], "0" * 64)), False)
    expect("a Dockerfile installing less than the catalog records is caught",
           judge_static(r, text.replace(" libuv1-dev pkg-config", " pkg-config")), False)
    expect("a Dockerfile installing more than the catalog records is caught",
           judge_static(r, text.replace(" zlib1g-dev", " zlib1g-dev libcurl4-openssl-dev")),
           False)
    run_line = "RUN apt-get update \\\n && apt-get install -y --no-install-recommends "
    for form in ("apt-get update && apt-get -y install libfoo", "apt install -y libbar",
                 "/usr/bin/apt-get -y install libqux", "apt-get update && /usr/bin/apt-get "
                 "install -y --no-install-recommends libquux",
                 "dpkg -i /tmp/x.deb", "aptitude install libbaz"):
        expect("an unreadable install form is caught: " + form, judge_static(
               r, text.replace(run_line, "RUN %s \\\n && apt-get install -y "
                               "--no-install-recommends " % form)), False)
    expect("a licence map missing a package is caught", judge_static(
           dict(r, system_package_licenses={k: v for k, v in
                r["system_package_licenses"].items() if k != "pkgconf"}), text), False)
    expect("the shipped Dockerfile and catalog agree", judge_static(r, text), True)
    expect("a catalog with no renv hash is caught",
           judge_static(dict(r, package_manager_sha256={}), text), False)

    # Live: a base build whose pinned hash does not match what the mirror serves must FAIL
    # -- the bytes of the toolchain every R build runs are checked, not their version string.
    tmp_hash = pathlib.Path(tempfile.mkdtemp(prefix="skald-bases-hash-"))
    try:
        start_forge()
        (tmp_hash / "Dockerfile").write_text(
            text.replace(r["package_manager_sha256"]["renv"], "1" * 64))
        # Plain progress, not -q: with -q the failing step's own output is not printed, and
        # "where did it fail" is the point of this case.
        built = docker(["build", "--progress", "plain", "--network", "host",
                        "-t", "skald-base/selftest-hash:probe",
                        "--build-arg", "CRAN_MIRROR=" + MIRROR, "-f", str(tmp_hash / "Dockerfile"),
                        str(tmp_hash)], timeout=1800)
        if built.returncode == 0:
            print("  FAIL a base with a WRONG renv hash built")
            missed.append("live wrong hash")
        elif "computed checksum did NOT match" not in (built.stdout + built.stderr):
            print("  FAIL the build failed, but not at the hash check: %s"
                  % (built.stdout + built.stderr).strip()[-200:])
            missed.append("live wrong hash reason")
        else:
            print("  ok   live: a wrong renv hash fails the base build at sha256sum --check")
    finally:
        docker(["rm", "-f", "-v", FORGE])
        docker(["rmi", "-f", "skald-base/selftest-hash:probe"])
        shutil.rmtree(tmp_hash, ignore_errors=True)

    # Live: the R base WITHOUT the line that replaces rocker's Rprofile.site.
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="skald-bases-"))
    tag = "skald-base/selftest-ppm:probe"
    try:
        start_forge()
        mutant = text.replace("RUN printf 'options(download.file.method = \"libcurl\")\\n' >"
                              " /usr/local/lib/R/etc/Rprofile.site", "")
        if mutant == text:
            print("  FAIL the mutant did not apply; the live case proves nothing")
            missed.append("live mutant")
        else:
            (tmp / "Dockerfile").write_text(mutant)
            built = docker(["build", "-q", "--network", "host", "-t", tag, "--build-arg",
                            "CRAN_MIRROR=" + MIRROR, "-f", str(tmp / "Dockerfile"), str(tmp)],
                           timeout=1800)
            if built.returncode != 0:
                print("  FAIL the mutant base did not build: %s" % built.stderr[-200:])
                missed.append("live mutant build")
            else:
                expect("live: rocker's PPM default left in place is caught",
                       judge_live(r, facts_of(tag, "r")), False)
    finally:
        docker(["rm", "-f", "-v", FORGE])
        docker(["rmi", "-f", tag])
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if missed:
        print("RESULT: self-test FAILED: %s" % ", ".join(missed))
        return 1
    print("RESULT: self-test passed -- every check catches what it exists for")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
