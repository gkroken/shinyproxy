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
pivots into the rootfs and sets the hostname. Each of those is a syscall the default
profile grants only with CAP_SYS_ADMIN, which the worker's container does not hold in the
host's user namespace -- and does hold, as far as the kernel is concerned, inside the user
namespace it creates. So these are the calls that let a process manage namespaces it owns;
the kernel still checks each one against that namespace's credentials. None of them is
seccomp=unconfined, apparmor=unconfined or --oci-worker-no-process-sandbox, which decision
6 rejects by name, and the process sandbox stays on.

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
of vulnerabilities, and nothing in a build needs it. Answering ENOSYS keeps the call denied to everything in
the worker, runc and the build's own code alike, and is the same device Docker's own
profile uses for clone3.
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
