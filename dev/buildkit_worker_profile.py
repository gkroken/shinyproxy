#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

"""The seccomp profile a rootless BuildKit worker runs under -- one definition, two probes.

dev/rootless-buildkit-probe.py and dev/launcher-contract-probe.py each used to carry their
own copy of the syscall list, "kept in step deliberately". They were not in step (two
syscalls against three), and neither copy was right, so the list lives here.

**The base is Docker's default profile, pinned.** Deny-by-default, ~300 syscalls allowed,
and the namespace-management calls granted only to a process holding CAP_SYS_ADMIN. It was
fetched from the `main` branch until 2026-09-24; that branch changed twice in August 2026,
so a set measured "minimal" against it was minimal against a profile nobody could name.
It is fetched at a commit and its hash is checked, because T7 owns what a deployment
actually ships and a vendored copy here would be a second answer to that question.
Apache-2.0, same as the rest.

**The additions, and why they are these.** A rootless worker runs runc inside its own user
namespace, and runc builds the RUN step's container there: it clones and unshares the
namespaces, joins the new mount namespace from a helper thread, mounts and unmounts,
pivots into the rootfs and sets the hostname.

Six of those -- clone, mount, umount2, unshare, setns, sethostname -- the default profile
grants to a container holding CAP_SYS_ADMIN, which the worker's container does not hold in
the host's user namespace and does hold, as far as the kernel is concerned, inside the user
namespace it creates. Adding them gives the worker what Docker would give a CAP_SYS_ADMIN
container, and no more; the kernel still checks each against the owning namespace.

**pivot_root is different, and was signed off separately.** Docker's default does not list
it at all, so it denies it to EVERY container, whatever its capabilities (finding
98c00fb-F1, which corrected this docstring's earlier claim that all seven were
CAP_SYS_ADMIN-gated). runc cannot jail a RUN container without it; the alternative, runc's
no-pivot mode (a move-mount plus chroot), is a weaker jail and BuildKit exposes no switch
for it. The kernel requires CAP_SYS_ADMIN in the worker's own user namespace for it, and
the build's own code runs under BuildKit's second, stricter filter, where pivot_root is
denied -- which the probes now demonstrate rather than assume (98c00fb-F2). The user
approved it on 2026-09-24. Any further addition outside Docker's default needs the same.

None of these is seccomp=unconfined, apparmor=unconfined or --oci-worker-no-process-sandbox,
which decision 6 rejects by name, and the process sandbox stays on.

**What the build's own code gets: none of it.** These additions are the WORKER's filter --
rootlesskit, buildkitd and runc. BuildKit installs its own profile on each RUN container,
so a RUN step runs under two filters and cannot unshare, mount, setns, pivot_root,
sethostname or keyctl. That is load-bearing for everything above, so it is asserted: both
probes run a hostile RUN that tries each call and requires every one denied under two
filters, and the rootless probe's self-test shows the check fails when BuildKit's inner
profile is dropped (the security.insecure entitlement, which the probes also forbid on any
real launch).

Measured one at a time on 2026-09-24, each failure naming the next call (see the commit
that introduced this file): unshare ("failed to unshare remaining namespaces"), setns
("join container mntns: setns"), pivot_root ("error jailing process inside rootfs"),
sethostname. clone and mount are what rootlesskit itself needs to start; umount2 is what
the mount-and-pivot path needs. `--self-test` in dev/rootless-buildkit-probe.py removes
each one in turn and requires the RUN step to stop working.

**keyctl stays denied; only its errno changes.** runc joins a fresh session keyring for
each container, and treats ENOSYS as "keyrings unsupported, carry on" but EPERM as fatal.
The default profile answers keyctl with EPERM. Allowing keyctl was the other way through,
and it was not taken: the keyring interface is kernel attack surface with its own history
of vulnerabilities, and nothing in a build needs it. Answering ENOSYS keeps it denied to runc and everything
else in the worker, and is the same device Docker's own profile uses for clone3. Build code
is denied keyctl by BuildKit's inner filter as well, as above.
"""

import hashlib
import json
import pathlib
import subprocess

DEFAULT_PROFILE_COMMIT = "65adc7e022c97f55e45c054ff012988027733b87"
DEFAULT_PROFILE_SHA256 = "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"
DEFAULT_PROFILE_URL = ("https://raw.githubusercontent.com/moby/profiles/%s/seccomp/default.json"
                       % DEFAULT_PROFILE_COMMIT)

# Granted outright on top of the default. Order is the order runc needs them in.
ALLOWED = ["clone", "mount", "umount2", "unshare", "setns", "pivot_root", "sethostname"]

# Still denied, but with ENOSYS instead of the default's EPERM.
ENOSYS = ["keyctl"]
ENOSYS_ERRNO = 38


def fetch_default(directory):
    """Docker's default profile at the pinned commit, or a refusal to go on without it."""
    path = pathlib.Path(directory) / "default.json"
    got = subprocess.run(["curl", "-sS", "-o", str(path), "-w", "%{http_code}",
                          DEFAULT_PROFILE_URL], capture_output=True, text=True, timeout=120)
    if got.stdout.strip() != "200":
        raise SystemExit(
            "could not fetch Docker's default seccomp profile (HTTP %s) from %s.\n"
            "The probes compare against it and will not substitute something weaker."
            % (got.stdout.strip(), DEFAULT_PROFILE_URL))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != DEFAULT_PROFILE_SHA256:
        raise SystemExit("the default profile at %s hashes to %s, not the pinned %s"
                         % (DEFAULT_PROFILE_URL, digest, DEFAULT_PROFILE_SHA256))
    return json.loads(path.read_text())


def write(directory, base, allowed=None, enosys=None, name="profile.json"):
    """The default plus `allowed` (default ALLOWED) and `enosys` (default ENOSYS).

    Either can be passed reduced, which is how the self-test shows each member is needed.
    """
    allowed = ALLOWED if allowed is None else allowed
    enosys = ENOSYS if enosys is None else enosys
    profile = json.loads(json.dumps(base))
    if allowed:
        profile["syscalls"].append({"names": list(allowed), "action": "SCMP_ACT_ALLOW"})
    for syscall in enosys:
        profile["syscalls"].append({"names": [syscall], "action": "SCMP_ACT_ERRNO",
                                    "errnoRet": ENOSYS_ERRNO})
    path = pathlib.Path(directory) / name
    path.write_text(json.dumps(profile))
    path.chmod(0o644)
    return str(path)


# ------------------------------------------------------------------ the build's own code
#
# A RUN step that tries each namespace call the worker's profile allows, and records what
# happened. Busybox only, so it runs on the plain alpine base both probes already build
# from. keyctl is not here: the worker's own filter already denies it (ENOSYS), so its
# denial does not depend on the inner profile this checks.
#
# Measured 2026-09-24 against the rootless worker: under BuildKit's normal RUN profile all
# six are denied with EPERM and /proc/self/status shows Seccomp_filters: 2; with the
# security.insecure entitlement (BuildKit's inner profile dropped) five succeed, pivot_root
# reaches the kernel's own argument check (EINVAL), and Seccomp_filters is 1. So a
# denial here is the filter, not a malformed call.
HOSTILE_SCRIPT = r"""t() { n=$1; shift; if out=$("$@" 2>&1); then echo "$n=ok"; else echo "$n=$(echo "$out" | tr '\n' ' ')"; fi; }
t unshare_user unshare -U true
t unshare_mount unshare -m true
t mount mount -t tmpfs none /mnt
t sethostname hostname hostile
t setns nsenter -t 1 -u true
t pivot_root pivot_root / /
grep '^Seccomp' /proc/self/status | tr -d '\t '
"""
HOSTILE_CALLS = ["unshare_user", "unshare_mount", "mount", "sethostname", "setns",
                 "pivot_root"]
# busybox's own wording for EPERM, per applet: mount says "permission denied".
_DENIED = ("Operation not permitted", "permission denied")


def judge_hostile(text):
    """(ok, detail) for the hostile RUN's output: every call denied, under >= 2 filters.

    Anything but a denial counts against it -- success, and also an error such as EINVAL,
    which means the call reached the kernel's own argument checks and the filter did not
    stop it.
    """
    seen = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line
                  and "=" not in line)
    reached = [c for c in HOSTILE_CALLS
               if c not in seen or not any(d in seen[c] for d in _DENIED)]
    try:
        filters = int(fields.get("Seccomp_filters", "0"))
    except ValueError:
        filters = 0
    if reached or filters < 2:
        return False, "reached: %s; Seccomp_filters %d" % (
            ", ".join("%s (%s)" % (c, seen.get(c, "no result").strip()[:40])
                      for c in reached) or "none", filters)
    return True, "all %d denied under %d filters" % (len(HOSTILE_CALLS), filters)
