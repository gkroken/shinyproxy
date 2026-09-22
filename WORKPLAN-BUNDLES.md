# WORKPLAN — Spine #2: Bundles + builds

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

**Status: planning only, 2026-09-17. No implementation or security claim is certified by
this document.** Prepared against branch `skald`, commit `475651f`, and ContainerProxy
tag `v1.2.4`. Implementation stays on `skald`, not `master`.

Model: **Opus 5** for the manifest, extraction, isolation contract, lifecycle and review;
**Sonnet 5** for driver and log plumbing after those contracts and the isolation proof
are accepted. Extraction **and build isolation** require an independent Opus 5 security
review mid-track, by a session that did not implement them. Neither delegation nor a
passing author-written suite constitutes that review.

**Who performs it, decided 2026-09-18 by the user: the independent reviewer agent, not a
human.** The coding agent implements and does **not** perform it; the two-session split in
`code_review/` is the mechanism. See T5 for what that does and does not buy, and for the
conditions that make it worth anything.

The LOCKED section distinguishes inherited constraints from decisions made by this plan.
Items marked **OPEN / sign-off** are not locked by implication; task 0 records their
decision gates and each is resolved before dependent work. In particular, the concrete BuildKit sandbox configuration is not yet
proven. Do not weaken an inherited invariant to make a demo work.

## Problem

Spine #1 can register an image and run it. It cannot accept source, decide whether a bundle
is safe to unpack, restore dependencies, produce an image, or explain a failed build.
This track connects **bundle → build attempt → immutable image → content version → explicit
activation**, without changing content identity, ACL semantics or the serving address.

The actual handoff, verified in code rather than inferred from older workplan prose:

| Existing behavior | Consequence for #2 |
|---|---|
| `V1__content_registry.sql` has `content`, `content_version`, `content_acl`, `content_env`, `content_path`, `audit_event` in `skald`; `content_version.image` is NOT NULL | Add **V2**, never edit V1 or repair its checksum to make tests pass. A failed build need not be a runnable version. |
| `ContentAdminService.addVersion` allocates under a content-row lock and activates unless `activate=false` | Reuse/refactor allocation and auditing, but do not call its default-activating path from a background build. |
| `ContentSpecRepository.toProxySpec` reads `spec_json` in SQL but does not use it, and fixes port 3838 | Define a small server-generated runtime contract; merely writing arbitrary JSON does nothing. Include every consumed runtime field in the spec fingerprint. |
| Spec IDs are `c<content UUID without hyphens>--v<n>`; paths are independent | No path, title or owner name belongs in durable storage keys or registry repository identity. |
| `findSpec` resolves active versions and superseded versions with live proxies | Preserve this. Image cleanup must protect **all retained versions**, not only the active one. |
| `ContentAdminService.delete` refuses live proxies; versions otherwise cascade on deletion | Add build/deletion coordination and durable cleanup records before introducing external artifacts. Do not lose their keys in a cascade. |
| `content_env` is a table only | No assumed encryption or secret injection. This track does not write it. |

Engine source anchors are under `~/projects/containerproxy/src/main/java/eu/openanalytics/containerproxy/`:
`service/ProxyService.getUserProxies` resolves specs through `canAccess`;
`stopProxy` needs the dispatcher, not a fresh spec; `startProxy(...).run()` starts
synchronously. `backend/docker/DockerEngineBackend.startContainer` consumes the image,
user, CPU/memory limits, network and volume fields from `model/spec/ContainerSpec`.
Its default image pull policy is `IfNotPresent`. Use immutable image digests, not a tag
whose meaning changes under that policy. #2 uses a separate build driver, not
ContainerProxy's interactive-proxy lifecycle as a job scheduler.

Older counts and the “not yet reviewed” paragraph in `WORKPLAN.md` are historical, not
acceptance evidence. The serving layer has since been reviewed and fixed. Task 0 records
new executions, their commit and environment; no recorded green is carried forward.

## Decisions (LOCKED)

### 1. Keep the spine boundaries and the existing identity model

**Inherited:** our own `.tar.gz` plus `manifest.json`, no Connect/rsconnect/pins API
(ADR-0003); Docker single-host v1 with backend-independent storage/build interfaces
(ADR-0004); S3-compatible durable storage from the start (ADR-0007); immutable content
and version identity, renameable `/c/<path>` addresses (ADR-0011).

**Rejected:** Git checkout as a second input path (#3 follow-on, already deferred), a
filesystem storage fallback, a new ContainerProxy fork, API keys or publisher UI in #2.
These either contradict locked scope or expand the track without proving its core path.
If a second ContainerProxy override becomes necessary, stop and bring back ADR-0001's
fork decision. Do not conceal it in the build driver.

**User-confirmed scope (2026-09-16): both R and Python Shiny now.** Each gets its own
real upload/build/activate/rollback acceptance, not just an image or a schema branch.
R/Python base-image contracts for later tracks are also specified below. No static
serving, anonymous access, API sharing or artifact-serving feature is marked delivered here.

### 2. A versioned, declarative manifest; no publisher-selected build program

**Plan decision, contract detailed below:** `schemas/manifest.schema.json` is the
authoritative JSON Schema, dialect 2020-12, with an integer `schema_version`. Freeze the
first supported format after task 1's contract review and before accepting durable bundles.
Keep every released schema readable; changed meanings require a new schema version.
Keep immutable versioned schema copies and select by `schema_version`; a future change
to the convenience file at `schemas/manifest.schema.json` cannot alter validation of v1.
Unknown properties and unsupported versions fail explicitly. There is no remote schema
or `$ref` fetching from an upload.

The manifest selects a supported type, exact language version, entrypoint and lockfile;
the server chooses a digest-pinned base and generates the recipe. The file inventory
binds the manifest to bytes. The server verifies it; a publisher's hash is not trusted
as proof of authenticity or as authorization.

**Rejected:** publisher Dockerfiles, shell build commands, arbitrary base images, package
manager flags, OS-package lists, remote context URLs and raw ContainerProxy/SpEL fields.
They expose additional execution/configuration surfaces and make a platform policy
unenforceable. Dependency install hooks and application code are still **untrusted code**;
rejecting Dockerfiles is not itself a sandbox. Evidence: T2, T3, T5, T7.

### 3. Immutable S3 objects addressed by IDs; layouts are explicitly versioned

**Plan decision:** use the three existing configurable bucket roles and the `v1/` key
layout below. UUIDs are lowercase canonical UUID strings; a content version's DB UUID
and its display number are different fields. Bucket names/endpoints are deployment
configuration, not bundle fields. Object keys never depend on a content path or title.

**Rejected:** mutable `latest/` objects as the authority, a single appendable log object,
keys derived from URLs, and direct S3 credentials for content or builds. Renames must not
move artifacts; concurrent writers need immutable results; S3 multipart uploads are not
a live append stream. The DB owns current pointers; completion descriptors own complete
artifact inventories. The layout is documented sufficiently for later R/Python helpers
to interpret authorized objects without Java classes or a Connect board protocol.
Evidence: T4, T8, T10.

### 4. Build attempts are not content versions

**Plan decision:** server-generated `bundle_id` identifies one accepted upload;
`build_id` identifies **one execution attempt**, independently of the bundle hash, content
version and worker/container ID. A retry creates a new build ID with `retry_of`; it can
reuse the same immutable validated bundle. The request's idempotency key prevents an
HTTP retry from accidentally becoming a new execution attempt.

Create **no `content_version` row before success**. Only after image publication and
verification, runtime validation and final log persistence does one DB transaction insert
the version, link it uniquely to its build, and mark the attempt successful. Preserve
`image NOT NULL`. Failed/cancelled/timed-out/interrupted attempts retain their status and
logs and create no version or spec ID. Version numbers follow successful publication
order, not upload/start order. Never renumber or reuse a published version number.

**Rejected:** placeholder image strings, making pending versions resolvable, overwriting a
failed attempt on retry, and implicitly activating the build that happens to finish last.
These mix diagnostics with runnable state and permit slow older builds to displace a
newer deployment. Evidence: T6, T9, T10.

### 5. Digest-pinned images; retention follows references, not “active”

**Plan decision:** generated images use a configured registry authority and repository
`skald/content/<content-uuid>`, unique tag `build-<build-uuid>`, and an OCI digest recorded
as `<authority>/skald/content/<content-uuid>@sha256:<digest>` in `content_version.image`.
Record tag and digest in the artifact ledger. No `latest` tag is used for execution.
Architecture is recorded explicitly; #2 produces one native Linux architecture per build,
not an accidentally platform-dependent multi-architecture manifest.

Use one registry authority that the host Docker daemon and build exporter can both reach.
`localhost:5000` inside a builder is not the host registry, and Compose `registry:5000`
is not automatically resolvable by the host daemon. Task 5 must prove push **and a cold
ContainerProxy pull** using the chosen name, TLS/auth and any dev-only configuration.

Retain every successfully published version's image and bundle until explicit content
deletion or a future explicit version-retention policy. Superseded is not disposable.
An artifact collector handles unreferenced failed-build images, expired caches and
abandoned objects; the registry's native GC reclaims blobs in a maintenance window.

**Rejected:** build ID as spec ID, slug-based repositories, moving release tags, blind
registry age policies and `docker system prune` as application GC. They respectively
break #1 identity, rename independence, reproducibility or rollback. Evidence: T9, T10.

### 6. Isolation is an acceptance contract, not the word “rootless”

**Inherited minimum, made testable here:** no Docker socket or TCP daemon access from
untrusted code; no privileged build, host filesystem bind mount, host PID/IPC/network
namespace, host-root identity or access to another workload; bounded CPU, memory, PIDs,
disk, logs and lifetime. No platform, database, MinIO admin or registry-admin credentials
in a dependency install or application process. This applies to extraction helpers,
dependency hooks and smoke-started images, not only the final `RUN` instruction.

**Plan decision:** one disposable rootless BuildKit worker per attempt, no worker reused
across publishers; a trusted launcher controls its lifecycle. **The worker runtime is a
configuration seam, decided 2026-09-18 by the user** — the launcher selects a runtime
(`runc`, `runsc`, a microVM runtime) and receives the isolation profile as one policy
object, rather than having one runtime and a scatter of flags compiled into it. Rootless
BuildKit under `runc` is the **default and the only profile #2 ships**; the seam exists so
that an operator whose publisher population is wider than "people we issued accounts to",
or whose host has KVM, can raise the boundary without a redesign. **A runtime that cannot
enforce every bound in the configured profile must refuse to start, never run weaker** —
a seam that silently degrades is worse than no seam, because the profile then describes an
intention rather than a state. The launcher may use the
platform's existing Docker control-plane access, but that socket is never mounted into
the worker or exposed through a worker-callable Docker API proxy. Transfer inputs through
a bounded BuildKit session/stream, not a bind mount of the repository, platform temp
directory or home. Driver handles stay opaque outside the Docker implementation.

**Rejected:** Docker-in-Docker with `--privileged`, mounting `docker.sock`, a shared
rootful build daemon, a flag-reading “isolation test”, and silently adding
`--oci-worker-no-process-sandbox` to get nested builds working. The last option weakens
process separation and process cleanup; rootless is not evidence to the contrary.

**Required gate; Q2 DECIDED 2026-09-18, the profile still owes its proof:** the precise rootless worker, namespace, seccomp/AppArmor,
cgroup and storage configuration must pass T3/T5 and the T5 agent review **before** the
production build driver is connected; a human review of the deployment profile remains
owed to the operator and is not discharged by that gate. No unrestricted profile or host-wide security
disablement is pre-approved by this plan. A requirement for one is a concrete proposal
to bring back, not an implementation detail. The same applies if a separate VM becomes
necessary: that changes the Docker single-host deployment contract and needs sign-off.

### 7. Lockfile caching is scoped reuse, not a reproducibility promise

**Plan decision:** the dependency-layer key is a SHA-256 of a canonical, domain-separated
record containing recipe revision, exact base digest, target architecture, language and
package-manager versions, repository/mirror policy revision, exact lockfile bytes and
hashes of any local dependency inputs. BuildKit cache references are scoped to content
UUID plus that key. No cross-content writable cache or secret-bearing cache mount.

Restore dependencies before copying changing application sources. For permitted local
dependencies, include their full trees in the dependency input and key; never exclude
them merely because they are “source”. Reject unsupported local/VCS dependency forms
clearly rather than caching an incomplete key. Full build provenance additionally binds
the validated bundle inventory, generated recipe and effective isolation/limit policy.

**Repository policy is configuration (Q3).** The "repository/mirror policy revision" in the
cache key is the identity of the *configured* repository set, not a fixed list: changing
which mirror a deployment resolves against must miss the cache, because the same lockfile
can resolve differently against a different mirror.

**Rejected:** a bare lockfile hash as a global cache key, caller-supplied cache refs, and
claiming equal lockfiles guarantee byte-identical images. R/package repositories and
install scripts can change behavior or disappear. Save resolved package checksums and
sources; use controlled repositories and exact bases; describe the achievable guarantee
as recorded inputs plus immutable published output. Rollback uses the existing digest,
never a rebuild. Evidence: T7, T10.

### 8. Explicit activation; no environment-secret feature in #2

**Plan decision:** success stages a version. Activation/rollback is the existing explicit
content-scoped operation and changes only `content.active_version_id`, transactionally
with its audit event. No build-completion callback starts/stops/replaces user proxies.
The direct-image admin endpoint remains an explicitly trusted legacy/admin path; preserve
its existing API behavior and distinguish its versions from managed build artifacts.
The new pipeline never inherits its default `activate=true` behavior.

`content_env` encryption stays with **spine #3, before its first write or read/injection
feature**; #4 can expose the resulting feature. #2 accepts no secret values, private
repository credentials, secret build arguments or environment-setting manifest fields.
Operator credentials for S3/registry are separate service configuration, never content
environment values, bundle bytes, image layers or user-visible logs.

**Rejected:** storing plaintext “temporarily”, putting decryption into an image, trying
to scrub arbitrary publisher secrets after executing them, or delaying mandatory
encryption until after a write API ships. Without an injected secret there is no promise
to detect a secret a publisher deliberately includes in source or prints. Source and
logs remain private regardless. Evidence: T7, T8, T9.

## Design

### Components and boundaries

New implementation stays under `eu.openanalytics.shinyproxy.publisher.*`:

| Component | Responsibility |
|---|---|
| `bundle/ManifestValidator`, `BundleValidator`, `SafeExtractor` | Bounded parsing, schema and inventory checks, private extraction; never run bundle code in the JVM |
| `storage/ArtifactStore`, S3 implementation | Immutable put/get/head/delete, multipart abort, bounded streams; no `File` or Docker types in its public contract |
| `build/BuildService`, `BuildRepository`, `BuildCoordinator` | Admission, durable status, idempotency, leases, completion and cancellation |
| `build/BuildDriver`, Docker/BuildKit implementation | `submit`, `observe`, `cancel`, `reconcile`; immutable input/result descriptors and opaque execution handle |
| `build/RecipeCatalog`, `BuildLogStore` | Server-owned recipes/base digests; sequenced durable log chunks and replay |
| `registry/VersionPublicationService` | Shared locked version allocation, managed runtime projection, audit; no automatic activation |
| `admin/` additions | Admin upload/build/status/log/cancel operations, using existing authorization service |
| `images/`, `schemas/`, `dev/` | Trusted image recipes/catalog, released schemas, runnable acceptance tools and fixtures |

No interface pretends that DB + S3 + registry form a distributed transaction. The
coordinator is a durable state machine with idempotent steps and reconciliation. Never
hold a JDBC transaction, servlet thread or servlet authentication object for a build.
Persist the initiating actor and target explicitly for background work and audit.

### Manifest contract (R and Python Shiny are both required)

One gzip member containing one POSIX tar archive. Root `manifest.json` is the first
logical regular file; payload entries are under `app/`. Optional directory headers are
permitted subject to the same limits and duplicate rules. PAX support is narrowly
specified in the extractor contract below, not delegated implicitly to library defaults.

| Field | Format/version-1 meaning |
|---|---|
| `schema_version` | Required integer `1`; unknown versions fail before execution |
| `type` | Required registered content type; must equal the target `content.type` and be enabled by the reviewed recipe matrix |
| `runtime` | Required for executable source: `language` (`r` or `python`) and exact `version`; no `latest`, ranges or download URL |
| `entrypoint` | Recipe-specific validated path relative to `app/`. **Python Shiny names a regular `.py` file; R Shiny names a directory** (`.`, meaning the payload root, allowed here only). Never a shell command or import expression. A directory entrypoint is never itself an inventory member — see the resolution rule below |
| `dependencies` | Required `{format, path}`; `renv` + `renv.lock` for R, `pip-hashed` + `requirements.lock` for Python; semantics below |
| `files` | Required inventory of every regular payload file: relative `path`, integer `size`, lowercase hex SHA-256, boolean `executable` default false; excludes `manifest.json` |

No fields for content ID, owner, visibility, public path, version number, image, registry,
privilege, mounts, network, build flags or secrets. Those belong to authenticated requests
or server policy. All objects reject unknown keys. Reject duplicate JSON keys, invalid
UTF-8, non-integer sizes, overflow, deep nesting, duplicate inventory paths and manifest
type/runtime disagreement. Schema validation alone does not prove filesystem containment.
**Resolving the entrypoint against the inventory.** `files` lists regular payload files
only, so a directory entrypoint can never appear in it. Requiring every entrypoint to be an
inventory member would make a valid root-level R application unrepresentable — entrypoint
`.` with `app/app.R` and `app/renv.lock` — and the only way to satisfy it would be to put a
directory into a regular-file inventory, which this same table forbids. The rule is
therefore split by what the entrypoint denotes:

- **`dependencies.path`**, for both languages, names a regular file that must be present in
  the verified inventory. No exception.
- **A file entrypoint** (Python Shiny) must be present in the verified inventory and end in
  `.py`. An entrypoint that resolves to a directory is rejected for this language.
- **A directory entrypoint** (R Shiny) is validated *through* the inventory rather than by
  its own entry. It must be `.` or a contained relative directory path, and the inventory
  must carry, relative to it, either `app.R`, or **both** `ui.R` and `server.R` — the two
  layouts `shiny::runApp` accepts. Exact lower-case names: payload paths are
  case-preserving, case collisions are already rejected, and the runtime container is
  case-sensitive. An entrypoint that resolves to a regular file is rejected for this
  language.

**Implicit directories are sufficient, and are the expected case.** Directory headers are
optional in the archive, so a directory exists for validation purposes exactly when the
inventory contains a file beneath it. A directory header neither satisfies this rule nor is
required by it, and an entrypoint whose only evidence is a directory header with no
qualifying files beneath it is rejected. Do not add directory objects to `files` to make a
validator simpler; that changes an irreversible contract to avoid writing one predicate.

The first enabled branches are `shiny` + `r` + `renv` and `shiny` + `python` +
`pip-hashed`. Include Python Core and Express application fixtures; do not silently
mistake a Core-only import wrapper for general Shiny CLI behavior. A DB enum is not a
promise that a bundle type is supported. Other types return an explicit unsupported-type
error until their reviewed manifest branch/recipe exists. Future formats extend through
versioned schemas, not a permissive `additionalProperties` escape hatch. Do not ship
guessed Quarto/data/API field semantics that their owning tracks must later live with.

### Image references

`spec/image-references-v1.json` fixes the strings: the configured authority, the repository
`skald/content/<content-uuid>`, the per-attempt tag `build-<build-uuid>`, and the
digest-pinned execution reference stored in `content_version.image`. Decision 5 fixes the
policy; this fixes the grammar, because a reference that does not parse fails at the one
moment nothing is watching — when ContainerProxy tries to pull.

**The digest pin is a requirement, not a preference.** `DockerEngineBackend`'s default pull
policy is `IfNotPresent`, so a tag whose meaning changed is never re-fetched and a host keeps
running whatever it cached. The runner therefore checks the *negative* that matters: the
execution pattern must refuse a well-formed **tag** reference, and refuse an unpinned one with
no digest at all. Malformed input is the easy case; a perfectly valid tag reference is the one
that would quietly serve a stale image.

**The repository is keyed on identity, never on address.** A rename must not move an image,
and two content items must not share a repository — which is also what makes "retain every
published version of this content" expressible to registry GC. The tag is per *attempt*, so a
retry never overwrites the image of the attempt it retried; tags exist for humans and for GC,
which cannot see an untagged manifest as referenced, and are not how anything executes.

**One authority string, resolvable from both sides.** `localhost:5000` inside a rootless
builder is the builder's own loopback, and a Compose service name is not resolvable by the
host daemon unless the host is on that network. T5 and T7 prove a push *and a cold pull* with
the configured string, not two strings that each work in their own context.

**A bare name is not an authority**, and this is the trap with this repository's name on it.
Docker reads the first path component as a registry domain only when it contains `.` or `:`
or is exactly `localhost`; otherwise it is a repository path on Docker Hub. Verified against
Docker 27.1.2: `docker pull registry/skald/content/<uuid>@sha256:<digest>` answers *"pull
access denied … may require 'docker login'"*, and the configured registry is never contacted,
while `registry:5000/…` resolves the host as intended. The dev stack's Compose service is
named `registry`, so the bare form is the first string an implementer would reach for — and
the grammar refuses it, rather than leaving T5's cold-pull proof as the only thing that would
notice.

### Semantic validation, and what the schema deliberately does not do

JSON Schema decides the *shape* of a manifest. It cannot decide whether a path stays inside
the payload, whether the entrypoint resolves, whether the inventory describes the bytes that
actually arrived, or whether a `renv.lock` makes sense under a Python runtime. Those are the
semantic validator's, and `dev/fixtures/manifests/expectations.json` already classifies
eleven manifests as `semantic_invalid` — structurally valid documents the schema **must
accept**, recorded so that "the schema accepted it" reads as expected rather than as a hole.

This table gives every one of them an owning rule, and names the rules that have no fixture
yet so the gap is visible rather than implied. A rule without a case is a rule nobody has
watched fail.

`dev/schema-fixture-check.py` parses the **Fixture** column of this table and requires every
`semantic_invalid` fixture to be cited by a row whose first cell is a rule id. That is a
narrow parser of one known table, and it is deliberately not a substring search: the first
version asked whether a fixture's name appeared anywhere in this document, which stayed green
after every rule row was deleted so long as the names survived in a note saying they had no
rule. Editing the table therefore has consequences — deleting a row, or removing a rule's id,
fails the run, as does citing a fixture that does not exist or removing the table entirely.

| # | Rule | Rejects | Fixture |
|---|---|---|---|
| S1 | Every `files[].path` resolves inside the payload root after normalisation | `../escape.txt`, and anything whose real target escapes | `path-traversal` |
| S2 | No `.` or `..` segment, no empty segment, no trailing slash on a file | `a/./app.R` | `path-dot-segment` |
| S3 | Inventory paths are unique after NFC normalisation and case folding | a repeated path; `App.R` beside `app.R` | `duplicate-inventory-path`; case and NFC cases **owed** |
| S4 | A file entrypoint is a regular inventory member and matches its language's extension | Python naming a directory, or a path absent from `files` | `python-entrypoint-names-a-directory`, `python-entrypoint-absent` |
| S5 | A directory entrypoint resolves through the inventory: `app.R`, or both `ui.R` and `server.R`, beneath it | R naming a file; a directory with neither layout; `ui.R` alone | `r-entrypoint-names-a-file`, `r-directory-without-layout`, `r-only-ui-no-server` |
| S6 | `dependencies.path` is a regular inventory member | a lockfile named but not listed | `lockfile-absent-from-inventory` |
| S7 | `dependencies.format` agrees with `runtime.language` | `pip-hashed` under an R runtime, or `renv` under Python | `language-format-disagreement` |
| S8 | `type` is enabled by the recipe matrix, not merely registered | `quarto_static` before its recipe exists | `registered-but-unsupported-type` |
| S9 | `type` equals the target `content.type` | a `shiny` bundle uploaded to `plumber` content | **owed** — needs a target, so it belongs with T8's upload path |
| S10 | Each declared `size` and `sha256` matches the bytes actually extracted | a truthful-looking manifest describing different bytes | **owed** — needs real archives, so it belongs with T2/T5 |
| S11 | The inventory and the payload agree exactly: no extracted file missing from `files`, no listed file absent from the archive | a smuggled extra file, or a phantom entry | **owed** — T2/T5 |

S1 and S2 look like duplicates of the extraction contract's path rules and are not. Extraction
validates the *archive's* member names as they stream past; these validate the *manifest's*
claims. A bundle can carry a well-behaved archive and a lying inventory, and only one of the
two checks sees that. Both run, and neither is permitted to assume the other did.

**Ordering matters, and the reason is not performance.** Schema validation runs first, then
S1-S9 against the manifest alone, then extraction under the operator limits, then S10-S11
against what was extracted. Nothing is written outside the private extraction directory until
every one of them has passed, and no build is queued. The point is that S10 and S11 are the
only rules that require having read the payload, so everything cheap and everything hostile
is decided before a single byte of untrusted content is committed anywhere a later step could
mistake for validated.

**A rejection names its rule.** "S5: entrypoint `dashboards` contains neither `app.R` nor both
`ui.R` and `server.R`" is actionable by the publisher who wrote the manifest; "invalid bundle"
sends them to an administrator. This is the same reasoning as Q3's decision to surface a build
log rather than guess at a package name: say precisely what was observed, and do not
editorialise beyond it.

**What the semantic validator must not do.** It does not repair, normalise away or "helpfully"
accept anything in the list above — no stripping a `..`, no lower-casing a colliding path, no
inferring an entrypoint when none resolves. Every one of those turns a rejection into a
silently different bundle, which is how an uploader and a server come to disagree about what
was published. Reject, name the rule, and stop.

### Identifiers and lifecycles

`spec/lifecycle-v1.json` holds the bundle and build state machines and the meaning of every
identifier. It is the single source: T6's tables and CHECK constraints, the coordinator and
the admin API are written from it, and this document explains it rather than repeating it.
Restating a policy in two places is what produced finding `d4f5baf-F1`, where a retention
decision and its collector instructions disagreed for two commits.

It is **not** under `schemas/` and is not a JSON Schema. A document at a schema path is
loadable as a schema whether or not it is one, and one that is not becomes a validator that
accepts everything — which is finding `dd46cac-F1`, and is exactly the mistake that naming
tempts you into.

Nothing validates against it, which is precisely why it is machine-checked:
`dev/schema-fixture-check.py` refuses a state machine with an unreachable state, a terminal
state that has grown an outgoing edge, a state missing from the terminal list, a transition
to an undeclared state, or an unknown actor. Each of those is a coordinator that hangs or
loses an attempt, and none of them is visible by reading.

Three decisions in that file are worth defending here, because they are choices rather than
descriptions.

**`build_id` identifies an attempt, not a build of a bundle.** A retry is a new id carrying
`retry_of`, reusing the same immutable validated bundle. Reopening a terminal attempt would
mean its logs, its artifacts and its retention clock describe two different executions.

**Operator cancellation is refused once `PUBLISHING` has begun, and a deadline is not.** By
then a push may already have produced a digest, and a cancel that races publication is how an
image comes to exist with no row describing it. A deadline is different in kind: the worker's
lifetime bound covers publication too, because a push or a verification can stall after the
build has finished, so `PUBLISHING` has a `TIMED_OUT` outcome and the lease generation fences
a late worker out of inserting a version. Recovery from a refused cancellation is deleting the
*content* — the only delete the admin API has. There is no version-delete endpoint, and this
rationale does not invent one.

**`INTERRUPTED` is distinct from `FAILED`.** A failure is a build that ran and did not work;
an interruption is an attempt the platform lost — worker death, lease loss, a restart across
it — about which nothing is known, including how far it got. They are retained identically
but must be distinguishable, because reconciliation can conclude something about the second
that it cannot conclude about the first.

### Storage layout and completion protocol

`C`, `U`, `B`, `V`, `R` below mean content UUID, bundle UUID, build UUID, version UUID
and rendition UUID. They are not user-supplied object keys.

| Bucket role | Key |
|---|---|
| bundles (`skald-bundles` in dev) | `v1/content/C/bundles/U/bundle.tar.gz` |
| bundles | `v1/content/C/bundles/U/manifest.json`, `inventory.json`, `receipt.json` |
| logs (`skald-logs`) | `v1/content/C/builds/B/chunks/000000000001.jsonl` and subsequent sequences |
| logs | `v1/content/C/builds/B/index.json`, `final.json` |
| output (`skald-output`) | `v1/content/C/versions/V/renditions/R/files/<validated-relative-path>` |
| output | `v1/content/C/versions/V/renditions/R/descriptor.json` |

Bundle bytes are immutable once a receipt is committed. Receipt includes layout/schema
version, IDs, compressed SHA-256, byte counts and inventory digest. `receipt.json` is
written last; only a DB `VALIDATED` bundle may be built. Incomplete uploads and descriptors
do not make objects public. Use server-calculated SHA-256, not S3 ETag as a content hash.
Copy/re-extraction by a worker verifies the recorded digest again.

Logs are independent completed objects, not an uncompleted multipart upload. An index
advertises only persisted contiguous chunks; `final.json` includes last sequence, byte
count, build outcome and completeness/truncation flags. `index.json` is a mutable,
rebuildable progress hint, the explicit exception to immutable artifact data. The DB's
fenced committed cursor is authoritative while building; `final.json` is immutable after
completion. A single trusted log writer conditionally creates chunks and rejects an
attempt to replace different bytes at an existing sequence. Late-generation writes
cannot advance the committed cursor or publish completion. Readers may lag but cannot
observe a completion index pointing at absent chunks. Prove this with late-writer tests.

The **output layout is reserved and documented now**, with a descriptor round-trip test,
but rendering, “current rendition” publication and downloads belong to #5/#6/#8. The
descriptor has `layout_version`, C/V/R, content version number, producer kind/ID, creation
time and file list (relative path, size, SHA-256, media type). Files are written first,
descriptor last. R/Python helpers later follow authorized descriptors, not bucket listing
or a mutable object named `latest`. No DB output table or pins-compatible API is smuggled
into V2. Evidence: T4.

S3 roles are least-privilege, buckets private, credentials absent from worker payloads.
Transient scratch is permitted; it is quota-limited and disposable, never a filesystem
durability fallback. The platform reads/writes S3; a build does not receive bucket admin
credentials or arbitrary object keys. MinIO outage must be an explicit storage failure.

### V2 and lifecycle

`V2__bundles_and_builds.sql` is forward-only and tested on both a fresh schema and a
populated V1 database. Suggested tables/columns, finalized together in task 6:

- `bundle`: UUID, content FK, initiating actor, upload/idempotency information, status,
  raw object key and digest, validated manifest/inventory digest, byte counts, timestamps,
  validation/error code. Its states and their transitions are in `spec/lifecycle-v1.json`.
- `build`: UUID, content/bundle FKs, `retry_of`, initiating actor, idempotency key and input
  fingerprint, status, recipe/base/platform/cache descriptors, effective limits,
  lease owner/expiry/fencing generation, opaque worker handle, output digest, error code,
  log cursor/completeness, timestamps. Uniqueness makes completion/idempotency enforceable.
- `content_version`: nullable unique `build_id` link for managed versions; old direct-image
  rows remain valid. `image` stays NOT NULL; `spec_json` is server-generated metadata,
  not the uploaded manifest and never a deserialized unrestricted ProxySpec.
- `artifact`/`artifact_gc`: durable ledger/outbox of server-generated object/image refs,
  owning IDs, kind, digest, pin/retention and deletion state. Cleanup records survive
  content deletion; their denormalized subject UUID is not a cascading FK.

Build states and every legal transition are in `spec/lifecycle-v1.json`, not restated here.
A lost worker lease fences subsequent updates and publication from the old generation.

1. Admin admission checks authorization, quotas, media type and idempotency before reading
   significant bytes. A bounded upload/validation step stores a durable bundle or rejects
   it without scheduling execution. HTTP disconnect aborts partial upload work.
2. A short transaction creates/returns a build request. Same actor/content/idempotency key
   plus same inputs returns the existing attempt; different inputs give 409.
3. A coordinator claims with a DB lease and fenced state transition. One running build
   globally initially; bounded queue. Enforced admission limits cannot wait until #9.
4. The driver restores verified input into a private workspace, runs the trusted recipe,
   persists logs and pushes the immutable image. No request thread waits for this.
5. Verify the pushed digest and recorded platform/configuration, and perform a bounded
   isolated startup/health probe. Publish a complete log descriptor. Then lock the content
   row, verify it still exists, allocate a version through the shared allocator, insert
   image/runtime metadata and unique build link, mark success and audit in **one** commit.
6. Explicit activation selects a successful version. Failed image pull or application
   startup cannot quietly change the active pointer. Activation does not rebuild.

Crash after push but before the transaction leaves an orphan image, never a half-version.
On restart reconcile DB records, worker labels/handles and artifact receipts. For a
`PUBLISHING` attempt, verify persisted results and finish exactly once if safe; otherwise
mark interrupted and retain diagnostics. Do not trust a stale worker callback. Retries
are new attempts. Simulate crashes at each boundary, including after DB commit before
HTTP reply. Evidence: T6/T9.

Deletion takes the same content-row coordination lock as admission/finalization, refuses
nonterminal builds, and retains the existing live-proxy refusal. Enqueue artifact cleanup
records in the content-deletion transaction before cascading owned metadata. Fence new
admission against deletion. Content path reservations remain untouched. Do not claim a DB
lock synchronizes ContainerProxy's in-memory proxy store; test the existing runtime race
separately and bring a discovered conflict back rather than invent a stronger guarantee.

### Extraction contract and independent fixture corpus

T2 supplies the fixture bytes, expected decisions and outside-root sentinels **before**
the extractor exists. Its builder/oracle must not import the extractor, path validator or
manifest validator. Use an independent tar producer plus hand-constructed header cases;
check fixture hashes and a machine-readable expectation table into `dev/fixtures/bundles/`.
The independent reviewer adds withheld cases at T5. A fixture generated through the same
normalizer being tested does not establish containment.

**Limits are operator configuration, not constants (Q3, decided 2026-09-17).** A laptop and
a build host do not want the same ceilings, so every bound is a configured property
with its documented default recorded beside it in `spec/extraction-limits-v1.json`, and the
extractor reads them rather than embedding them. Two consequences the implementation owes: a configured value is itself untrusted
input and is validated at startup — positive, within a sane absolute maximum, and refused
rather than silently clamped — and the defaults must appear in one place that the
documentation and the code agree on, or they will drift.

**The values are in `spec/extraction-limits-v1.json` and are deliberately not restated
here.** Ten bounds, each with its default, the absolute maximum past which the bound stops
meaning anything, and why that maximum is where it is. `ExtractionLimits` reads that file
from the classpath at startup instead of carrying constants, so the one place the code and
the documentation must agree on is a place neither of them copies;
`dev/schema-fixture-check.py` holds the corpus profile to the same file and fails if this
section starts restating a number again. Bounded parser memory is an invariant of the
implementation rather than a number an operator sets, and is recorded there as one. Check
totals against **actual streamed bytes** as well as declared sizes; arithmetic must be
overflow-safe. Limits apply to ignored metadata too.

Making them configurable does not make them optional. A deployment may raise a ceiling; it
may not remove one. The corpus in T2 therefore parameterises the boundary cases off the
configured values rather than hard-coding the entry cap, so that the N/N+1 pairs still
straddle the real limit after an operator changes it.

Accept only regular files and directories. Reject all symlinks and hardlinks, even ones
apparently pointing inside the tree; there is no build functionality requiring them in
the upload. Reject device nodes, FIFOs, sockets, sparse encodings, setuid/setgid/sticky
bits and unknown tar types. Strip ownership, timestamps, xattrs and ACL metadata; create
private directories and controlled file modes, with executability from the manifest.
Library defaults must not create files or preserve permissions behind the validator.

Paths must be relative slash-separated UTF-8 in NFC. Reject, rather than normalize away,
absolute/UNC/drive paths, backslashes, `.`/`..` segments, empty segments, control/NUL
characters, invalid encoding and aliases. A conventional trailing slash is allowed only
on a directory header and removed for duplicate detection. Case is preserved and case
collisions are rejected for portability. `%2e%2e` in an archive filename is literal text,
not URL-decoded; never apply a URL decoder during extraction or key creation.

Validate the **effective** path after any approved PAX `path` override. Reject global PAX,
linkpath, sparse/xattr/ACL overrides and unknown interpretation-changing extensions;
allowlisted innocuous metadata may be ignored under bounds. Accept a single bounded gzip
member and tar end marker; reject concatenated archives/members and non-padding trailing
data. Any library unable to expose these distinctions is unsuitable without an outer
validator; do not just document rejection that the API cannot enforce.

Extract into a newly created private directory, with no other writer. Every parent walk
and create must refuse links, with descriptor-relative/no-follow operations where
available; a lexical `normalize().startsWith(root)` is insufficient. A substituted or
symlinked root/parent must fail closed. If the platform cannot supply the chosen safe
filesystem primitives, reject startup/build admission on that platform. Freeze the
validated tree before handing it to a worker. Delete it on all failure/cancellation paths.

| Corpus group | Required cases and observable result |
|---|---|
| Positive controls | Minimal real R and Python Shiny apps; nested assets; spaces/Unicode; empty file; exact-limit files; legitimate executable bit; supported PAX filename. Correct bytes/hash/modes, runnable output. |
| Traversal/absolute paths | `../`, embedded traversal, `/etc/...`, Windows drive/UNC/backslash forms, dot/empty-segment aliases, PAX override. Reject; outside sentinels unchanged. |
| Links and parent substitution | Symlink file, symlink directory followed by child, chained links, hardlink target outside/inside, pre-existing symlinked parent/root, rename race during extraction. Reject without outside reads/writes. |
| Bombs and malformed sizes | Entry cap N/N+1; expanded cap N/N+1; tiny compressed huge expansion; huge PAX field; sparse claimed file; negative/overflow size; truncated gzip/tar; many empty entries; concatenated members. Reject within measured memory/time/disk bounds. |
| Paths and types | Segment/path/depth boundary pairs; invalid UTF-8/NUL/control; device/FIFO/socket; setuid/setgid/sticky. Reject with typed error; never materialize a device or privileged mode. |
| Duplicate/alias ordering | Duplicate regular entries, duplicate manifest, file→directory and directory→file, repeated directories, case/Unicode aliases, file before its conflicting parent. Reject; no last-entry-wins overwrite. |
| Manifest/inventory | Missing/late/duplicate manifest, duplicate JSON keys, unsupported schema/type/runtime, missing/extra file, hash/size mismatch, missing lockfile/entrypoint, remote `$ref`. Entrypoint kind mismatches both ways: R naming a file, Python naming a directory, an R directory with neither accepted layout, and one evidenced only by a directory header. No queued job and no network schema lookup. |

For every negative case assert both rejection **and** no version, no worker, bounded
temporary state and unchanged sentinels. Each case has a positive control proving the
harness can create/read the target it claims is protected. Deliberately remove a bound,
link check or duplicate guard and record the specific assertion that fails.

### Build sandbox and dependency network

This is a target contract requiring T3/T5 evidence, not a claim that existing Compose
already implements it. Current Compose has a shared dev network and a plain local
registry; attaching workers there would violate the contract.

Start with a pinned rootless BuildKit image and native snapshotter candidate to avoid a
blanket host device grant. The launcher owns a disposable worker workspace/volume, never
a host bind mount. UID 0 inside an inner user namespace must map to an unprivileged host
UID; record and test both identities. Package build steps run as a non-root image user.
No insecure entitlements, user-selected frontends, host network or process-sandbox disable.
Document all allowed syscalls/capabilities and why; rootless setup helpers must not be
assumed compatible with `no-new-privileges` until the actual configuration is tested.

Initial ceilings: 2 CPUs, 4 GiB RAM with bounded/no extra swap, 512 PIDs, 10 GiB build
scratch, 20-minute wall deadline, 32 MiB log output, one active worker, finite queue (10).
Each can be made stricter by the operator; no manifest can raise it. Cgroup limits include
the daemon and descendants; disk is a real quota, not a best-effort free-space check.
The external supervisor kills the worker and descendants on timeout/cancel, independently
of the servlet, BuildKit RPC connection or an untrusted process ignoring SIGTERM.

Network policy defaults deny. Workers are isolated from the dev/runtime service network
and from each other. Approved dependency traffic goes through an operator-controlled
egress proxy/mirror with a finite repository allowlist; no direct egress. Block host
gateway, RFC1918/link-local/metadata destinations, IPv6 equivalents, DNS rebinding and
redirect/CONNECT tricks. “Internet is allowed” is not this policy. Deny direct access to
Postgres, Keycloak, MinIO, platform management, registry admin, Docker Unix/TCP sockets
and canaries in other containers. Test numeric addresses as well as service names.

Registry/base/cache transport is a trusted control-plane operation with scoped credentials,
not an unauthenticated shared registry writable by dependency hooks. BuildKit registry
auth travels via its trusted session; it is not a build arg, environment variable or
mounted Docker config. T3 must demonstrate that an ExecOp cannot read session credentials,
use a reachable daemon API to escalate, or push/overwrite another build's artifacts. If
the selected rootless networking model cannot separate these capabilities, stop at Q2.
Do not advertise network containment on the strength of `--network none` while the actual
restore or exporter uses an untested network.

| Isolation assertion | Required live attempt and positive control (T3, repeated at T5/T10) |
|---|---|
| No daemon/host access | From a real dependency hook, attempt Unix and TCP Docker APIs, read/write host sentinels, mount, namespace entry and device creation. The trusted harness proves targets exist. |
| No lateral network | Reach active host and sibling-container HTTP canaries by DNS/IP, Docker bridge gateway, service ports, IPv4/IPv6 and rebinding/redirect variants. Trusted peer reaches them; job cannot. |
| Controlled dependency egress | Fetch an allowed package successfully; disallowed host/private-IP/redirect target cannot receive a canary payload. Record server-side receipts, not just curl's exit status. |
| Process isolation and cleanup | Try ptrace/signalling the worker daemon, fork children and orphan grandchildren, ignore TERM. No unauthorized control; timeout/cancel leaves zero job descendants and worker handles. |
| Bounded resources | Allocate memory, fork, burn CPU, fill disk and flood logs. Observe actual enforcement and a responsive platform/control request; never exhaust the host to prove the limit. |
| No credentials/shared data | Enumerate env/files/proc and attempt known credential canaries, previous build files/cache namespaces and other object keys; no disclosure or cross-job writes. |

These tests support a specific deployed configuration; they do not prove resistance to
all kernel vulnerabilities. Pin and patch the worker/runtime tools and record their
versions with evidence. Unsupported hosts fail admission, not silently fall back.

### Base images, recipes and runtime projection

`images/` contains reviewed Dockerfiles and a machine-readable catalog keyed by content
type, language, exact language version, architecture and recipe revision. Each entry
resolves to a base digest and fixed launcher. OS packages are installed while maintaining
these trusted bases, not by arbitrary uploaded commands. Record their provenance/licenses.

The delivery matrix, incorporating the user's R-and-Python requirement, is:

| Family | #2 responsibility | Later track |
|---|---|---|
| R / Shiny | Full locked-dependency build, non-root image, fixed launcher on `0.0.0.0:3838`, real app acceptance | #3 clients generate this manifest |
| Python / Shiny | Full hash-locked dependency build, non-root image, fixed Shiny launcher on `0.0.0.0:3838`, real app acceptance | #3 Python CLI generates this manifest |
| R / Plumber; Python / FastAPI | Versioned base/launcher contract and base smoke tests; executable bundle branches deferred | #7 sharing, identity headers and API-key serving |
| R / Quarto + R Markdown; Python / Quarto | Versioned render-base contract and tool/version smoke tests; no public rendition activation here | #5 rendering/output, #6 schedules |
| Data / pre-rendered output | No unnecessary image; reserved output descriptor contract | #5/#8 admission and serving |

Select at least one maintained exact R version and one maintained exact Python version
in T1, pin their base digests and package-manager versions, and test them on the actual
host architecture. Record exact Quarto versions for render bases too. Additional supported
language versions are additive catalog entries, not a reason to put `latest` in a manifest.

Python's `pip-hashed` contract is a complete transitive lock in `requirements.lock`, with
exact package versions and approved SHA-256 hashes. The server supplies repository and
pip options. Reject editable/VCS/URL requirements, recursive includes, index overrides,
unhashed dependencies and source distributions initially; restore hash-verified wheels
only. This avoids silently downloading unpinned PEP 517 build dependencies. A Python app
needing a source-only package gets a clear unsupported-dependency failure; adding source
build support requires its own fully pinned build-dependency contract. `shiny` itself is
part of the lock. The chosen trusted launcher must support both accepted application
styles without importing application code during validation. R uses `renv.lock`, an exact
R/base/renv toolchain and recorded package sources/checksums; start restoration with a
trusted `R --vanilla` invocation, not an uploaded bootstrap/profile in the platform.

Private sources requiring credentials are unsupported in #2. Permit no `renv.lock` URL
outside the egress policy. The initial R recipe rejects remote mutable VCS references and
local package dependencies; future local-dependency support must obey decision 7's full
input key. Public repository R source installation remains arbitrary untrusted code and
is part of the live sandbox acceptance. Include at least one such dependency hook in T3.

For managed images write a versioned **allowlisted** runtime description into `spec_json`
(contract version, recipe ID, port, fixed user and resource policy); provenance belongs
to the build record. Keep {} compatible for existing direct-image versions. Map only
server-owned values to `ContainerSpec`, including non-root user and actual CPU/memory
limits. Do not deserialize uploaded JSON to privileged/volume/network/SpEL properties.
Maintain stable spec objects and include the normalized runtime description in the cache
fingerprint. Test a runtime-field-only change invalidates it without breaking index views.

Run the built image both through the isolated readiness probe and through ContainerProxy.
Assert effective user, no host mounts/socket, enforced limits and HTTP behavior in the
real container. A passing BuildKit build does not prove a safe or runnable deployment.
If a runtime guarantee needs unsupported engine fields or a second override, report it
under ADR-0001 instead of labelling the build sandbox as a runtime guarantee.

### Status, logs, admin transport and cleanup

#2 adds admin-only endpoints under `/admin/content/{id}` for upload, build creation,
status/list, log replay/tail and cancellation. **The exact shapes are now fixed, in
`spec/admin-transport-v1.json`**, and are not restated here. `/__api__/v1`, API keys and
owner/editor publishing remain #3.

Three of those shapes are choices rather than transcription. **Upload is two steps** — a JSON
create that returns a bundle id, then a raw `PUT` of the bytes — so the binary endpoint
carries no metadata and stays a pure stream, and so the bundle exists in `UPLOADING` before
any byte arrives. **The upload is `PUT`, not `POST`**, because it is idempotent against one
bundle id — in the sense set out below, which is narrower than it first sounds. And **cancel is
`POST`, not `DELETE`** — cancelling removes nothing, and it can be refused, which `DELETE`
would make an odd thing to answer 409 to.

**`PUT` here means "never a second bundle and never rewritten bytes", not "send it again and
it works".** Once the receipt is committed the bytes are immutable and the bundle has left
`UPLOADING`, so a repeat is refused with 409 and its current state; a client whose response
was lost recovers by *reading* status, not by uploading again. Different bytes at the same id
get the same 409, because a bundle id names particular bytes a build may already have read —
replacement means a fresh id. The earlier wording promised a replay would "re-upload the same
bundle", which would have meant either rewriting an immutable object or reopening a terminal
state.

The CSRF rule is the one to read before adding an endpoint. ShinyProxy protects `POST /login`
alone, so "accepts no media type an HTML form can produce" *is* the defence for everything
here — and the obvious way to build a file upload, `multipart/form-data`, is exactly the one a
cross-site form can forge. `dev/schema-fixture-check.py` refuses any endpoint that accepts a
form-producible type, any endpoint outside `/admin`, an upload without its custom header, and
a `cancel_refused_states` entry that disagrees with the lifecycle. Shared services
take explicit actor/target/policy inputs so #3 does not need to copy the pipeline.

Upload is a bounded raw `application/gzip` body with a required custom upload header,
not an HTML multipart form or a caller-selected filesystem/object-store path. Existing
security only protects POST `/login` with CSRF: the JSON-only defense on old endpoints
does **not** automatically cover a new binary/stream endpoint. Reject form media types,
missing custom header and unauthorized CORS preflight. Test a hostile-origin browser
form/fetch and real session-authenticated positive upload. No new broad CORS permission.
If this needs changes to the global CSRF matcher, bring the concrete auth change back
for sign-off before implementing it.

Build creation returns 202 plus build ID/status URL; it never waits for image construction.
Status and paginated logs are usable over HTTP/curl before any UI exists. Provide cursor
replay plus SSE (or an equivalently reviewed streaming transport) backed by committed
chunks: sequence IDs, bounded payloads, keepalive, resume after disconnect, finite
subscriber queues and terminal event. Slow/disconnected clients do not block the build.
“Viewable” means an admin can read/tail an in-progress and failed build now, not a promise
of a future UI. Source/build logs are admin-only here; runtime viewers do not inherit
source/log access through `canAccess`.

Flush chunks at most every two seconds or 256 KiB. Escape logs as text, cap line lengths,
neutralize terminal controls in viewers, and do not interpolate them into HTML. On a
MinIO outage use only bounded scratch buffering and bounded retry; if durability cannot
be recovered, stop the build and report a storage/log failure rather than mark a silent
success. Reaching the log cap stops execution with a typed limit error and a truncation
marker. Do not expose registry/S3 credentials in process arguments, audit details or logs.

Cleanup uses the artifact ledger, grace periods and repeatable mark/recheck/delete steps.

**Retention policy, decided in Q3 on 2026-09-17. This table is the only authoritative
statement; earlier proposals elsewhere in this document are superseded.** The earlier draft
said failed artifacts were collectable after 24 hours, which would have destroyed evidence
28 days before the decided policy allows, and let a successful build's logs live forever by
attaching them to the version. A collector cannot be written against two policies.

| Artifact | Retained | Clock starts |
|---|---|---|
| Incomplete upload (no committed receipt) | 1 hour | last write to the multipart upload |
| Bundle of a **published** version | until the content is deleted | — |
| Image of a **published** version | until the content is deleted | — |
| Artifacts of a `FAILED`, `CANCELLED`, `TIMED_OUT` or `INTERRUPTED` attempt | **30 days** | the attempt reached that terminal status |
| **Build logs, whatever the outcome** — `SUCCEEDED` and every terminal alternative alike | **90 days** | the attempt reached its terminal status |
| Unused dependency cache | 14 days | last cache hit |

**Logs are retained for 90 days regardless of how the build ended.** An earlier revision of
this table gave a failed attempt's logs 30 days so that they expired alongside its artifacts,
on the reasoning that a log outliving its artifacts might imply the build is recoverable.
That was a policy invented while implementing one, and it is exactly backwards: a failed
build's log is the *more* valuable of the two, because it is the only record of why the
failure happened, and nobody diagnoses a three-week-old failure from an image that was never
produced. The decision on record is 90 days for build logs and 30 days for failed-build
artifacts, and the two clocks are independent by design.

A published version's **image and bundle are pinned indefinitely** while its logs expire on
the same 90-day clock as any other build's: the artifacts are what rollback needs, the logs
are diagnostics, and treating them as one thing is what made the first draft retain logs
forever.

**Build** retention clocks start at a **terminal status**, never at creation, so a build that
runs for six hours cannot have its logs aged out from under it while it is still running.
That rule is about builds only — the multipart row is measured from its last write and the
cache row from its last hit, because neither has a terminal status to measure from.

The safety rule is not optional and is not a retention period: never collect retained
versions, live-proxy images, nonterminal attempts, leased work or in-flight publication,
whatever the table says. An expiry is permission to collect, not an instruction to collect
something still referenced. Recheck pins before destructive work and pause publication
during registry maintenance. Keep referenced digest tags so registry `delete-untagged`
cannot silently erase DB-referenced images. Never GC external/direct-image admin
repositories.

Registry manifest deletion and blob reclamation are different operations. The selected
registry's GC runs with writes stopped/read-only, with a dry-run report first. Object
deletion retries and worker/volume cleanup are idempotent; restart reconciles leftovers.
Test failed cleanup without losing ledger records, and test rollback after a real GC pass.

## Tasks

Order matters. T2's independently authored corpus precedes T3/T5 extraction work. T5 is
the mandatory independent security gate **before** wiring an upload to production builds;
it is performed by the reviewer agent, and T5 records both what that buys and what it
leaves owed to a human.
Every task records commands, versions, commit, assertions and actual outcomes; no checks
below are marked passed by this planning document.

- [x] **T0. Confirm scope and baseline.** Record Q1's confirmed R/Python scope, Q2's proof
      gate and Q3's proposed defaults; record explicit sign-offs where required. The actual
      Q2 deployment profile is decided after T3, not assumed here. Read current source,
      verify branch and ContainerProxy tag. Run `make dev`, `bash dev/smoke.sh`,
      `bash dev/acl-live.sh`, `make test`; retain output and actual totals. Capture V1's
      checksum and a populated V1 database fixture. Do not silently fix failures or copy
      prior totals into the new track. **Pass:** reproducible baseline plus decision log;
      unresolved locked-scope conflict stops dependent work.

      **Done 2026-09-17.** Every number below was produced by the run recorded here, not
      carried forward from spine #1's records.

      *Environment, as verified rather than assumed.*

      | Fact | Value | How |
      |---|---|---|
      | Branch / commit | `skald` @ `475651f606889945e55a67a3a83e05f491b753a8` | `git rev-parse` |
      | Engine source | `~/projects/containerproxy` tag `v1.2.4`, `0170bc5c0ef1948cdf8f18da598b8cf039d5523e` | `git -C … describe --tags` |
      | Engine dependency | `containerproxy.version` = `1.2.4` (`pom.xml:34`) — matches the source checkout | `grep` |
      | Docker Engine | 27.1.2 | `docker version` |
      | Kernel | 6.18.33.2-microsoft-standard-WSL2 | `uname -r` |
      | PostgreSQL | 16 (dev stack) | `docker-compose.dev.yml` |

      *V1 checksums, both forms, so a later accidental edit is detectable either way.*
      Flyway `skald.flyway_schema_history` records version 1 as checksum **`-1235024336`**,
      `success = t`, script `V1__content_registry.sql`. The file's SHA-256 is
      **`4d7ebe2d556b57f41a44d85e09fa031849c27318c3d01f066a293314a843b02f`**. V2 is additive;
      neither value may change.

      *Baseline runs.* `make dev` exit 0. `bash dev/smoke.sh` **47/47**, exit 0.
      `bash dev/acl-live.sh` **18/18**, exit 0. `make test` **138/138**, BUILD SUCCESS,
      exit 0. Nothing failed, so nothing was fixed.

      *State found, disclosed rather than tidied away.* The dev registry was not empty: one
      content row `e85071c6…` at path `host-probe`, left by the `Host`-header probe in the
      review of `475651f`. It is residue from that investigation, not product state; the
      suites clear content at start and did. Recorded because "the registry is empty at
      rest" is an invariant this project relies on, and a silent cleanup would have hidden
      that it had been broken.

      *Populated V1 fixture:* `dev/fixtures/v1-populated.sql`. Insert-only, no DDL, fixed
      UUIDs, valid before and after V2 exists. Verified by applying `V1__content_registry.sql`
      and then the fixture to a scratch database on the dev PostgreSQL (dropped afterwards):
      5 content, 7 versions, 5 live paths, 1 retired path, 2 orphaned reservations
      (`content_id IS NULL`), 4 ACL rows, 1 `content_env` row, 6 audit events, 1 content whose
      **active version is not its highest** and 1 content with **no version at all**. Those
      last two are the shapes a migration written against the happy path quietly breaks.

      *Q1 — CLOSED.* R and Python Shiny, both end to end, per the user's decision of
      2026-09-16. No change.

      *Q2 — OPEN, and T0 found two host facts that constrain the T3 proof. Neither is a
      relaxation; both are recorded so T3 measures rather than assumes.*
      - **AppArmor is not enabled** on this host (`/sys/module/apparmor/parameters/enabled`
        = `N`). The isolation profile therefore cannot claim AppArmor confinement here.
        seccomp is available (`Seccomp` present in `/proc/self/status`), user namespaces are
        (`user.max_user_namespaces` = 63771), and `gakro` has a subuid/subgid range
        (100000:65536), so rootless is viable — but by userns + seccomp + cgroups, and the
        eventual write-up must say so rather than listing AppArmor as if it applied.
      - **cgroup v2 is in use, but the user session has only `memory pids` delegated** —
        not `cpu`, not `io`
        (`/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cgroup.controllers`).
        The locked isolation contract requires bounded **CPU** as well as memory and PIDs, so
        as this host stands a rootless worker cannot enforce a CPU quota. T3 has to resolve
        that — a systemd `Delegate=` drop-in for `user@.service`, or a system-level slice the
        trusted launcher owns — and must not quietly drop the CPU bound to get a green.
        Finding it here costs a paragraph; finding it at T3 costs a redesign.

        > **Superseded 2026-09-18 by T3(a).** That cgroup path does not exist on this
        > host, and a worker launched through the rootful Docker daemon is bounded by the
        > daemon rather than by a user manager. CPU, memory, PIDs and disk are all
        > measured as enforced; see the T3(a) table and the Q2 gate row. The concern was
        > recorded honestly from what was visible then and is superseded by measurement,
        > not contradicted — it still stands for a *rootless* worker, which is a choice
        > this project has not yet made.

      *Q3 — proposed, NOT confirmed.* The limits in "Extraction contract" and the retention,
      repository and OS-package proposals are recorded as this track's starting profile and
      are **awaiting the user/operator decision the plan assigns to T0/T1**. T0 does not
      confirm them on the user's behalf. T1 cannot freeze the contract until they are
      confirmed, which is the stop condition, not a formality.

      *Q4 — no dependency added yet.* Commons Compress, networknt JSON Schema Validator and
      the AWS SDK v2 S3 client remain candidates only; exact versions and transitives get
      flagged with their licences at the point of addition, per CLAUDE.md.

      *No locked-scope conflict found.* The plan's "Existing behavior" table was re-checked
      against the source at `475651f` and matches, including `content_version.image NOT NULL`,
      the content-row lock in `addVersion`, `spec_json` being selected but unused, and the
      fixed port 3838 in `ContentSpecRepository`.

- [x] **T1. Review and freeze contracts — Opus 5.** Depends T0. Finalize schema v1,
      examples, supported type/language/lockfile matrix, output descriptor, IDs/states,
      admin transport and object/image layouts. Specify literal safe launch arguments
      and all semantic validators. Add schema validation fixtures, including future-version
      rejection and compatibility fixtures. Flag dependency licenses before adding them.
      **Pass:** producer examples for both languages from independent tooling validate;
      invalid examples fail the named rule; no unresolved one-way door is hidden in code.
      Entrypoint resolution is acceptance-tested in both directions, because the first draft
      of this contract made a valid R application unrepresentable (finding `00a1b2d-F1`):
      positives — root R app at `.`, nested R app, single-file `app.R` and two-file
      `ui.R` + `server.R`, each with and without optional directory headers, plus the Python
      file entrypoint as a control; negatives — R entrypoint whose directory has neither
      layout, R entrypoint naming a regular file, Python entrypoint naming a directory,
      entrypoint evidenced only by a directory header with no files beneath it, and a
      directory smuggled into `files`.

      **T1(a) done 2026-09-17 — the manifest contract only.** T1 covers several contracts;
      this is the first and most irreversible of them. Still open within T1: the output
      descriptor, ID/state vocabulary, admin transport, object/image layout wording, literal
      safe launch arguments, and the semantic validator specification.

      - `schemas/manifest/v1.schema.json` — authoritative and immutable, dialect 2020-12,
        `additionalProperties: false` throughout, `schema_version` pinned by `const`.
      - `schemas/manifest.schema.json` carries the **real schema**, byte-identical to
        `schemas/manifest/v1.schema.json`, and every fixture is validated through both with
        identical verdicts required.

        *An earlier revision of this commit put a non-schema "index" there and claimed the
        two requirements in decision 2 could not both hold. That was wrong, and instructive.*
        JSON Schema ignores unknown keywords, so the index **was** a schema — one that
        accepted `null`, `42`, `{}` and every malformed manifest. Anything loading the
        published path would have validated literally anything, and the runner's assertion
        that the file "must not be a schema" locked the bypass in. There is no tension to
        resolve: a published copy and immutable versioned documents coexist by being equal
        and checked for equality (finding `dd46cac-F1`).
      - 46 fixtures in `dev/fixtures/manifests/`, split three ways by
        `expectations.json`: **7 valid**, **28 schema-invalid**, **11 semantic-invalid**.
        The third group is the load-bearing one. Those manifests are structurally valid on
        purpose — `../escape.txt` in the inventory, a duplicate path, an R entrypoint naming
        a file, a Python entrypoint naming a directory, `renv` declared under a Python
        runtime — and the schema **must accept them**, because containment, inventory
        membership and entrypoint resolution are not expressible in JSON Schema. Recording
        them as expected-accepted is what stops a later reader mistaking the gap for a hole,
        and what keeps the debt visible for the semantic validator in T5.
      - `dev/validate-manifests.sh` runs the fixtures through **python `jsonschema` 4.26.0
        in a container** — deliberately not networknt, which the server will use. One
        implementation agreeing with itself is not evidence that a document says what it is
        meant to say. Result: all 40 behaved as specified.
      - **Patterns are anchored with `(?![\s\S])`, not `$`.** `$` does not mean end of
        string in either implementation this schema will meet: Python's `re` and
        `java.util.regex` both let it match immediately before a final newline. Appending one
        `U+000A` to `sha256`, `runtime.version`, `entrypoint`, `files[].path` or
        `dependencies.path` was therefore accepted — a **65-character SHA-256** passed, and
        paths carried the very control character their description says is rejected
        (finding `dd46cac-F2`). Six fixtures now cover trailing and leading newlines, and
        `sha256` additionally carries `minLength`/`maxLength` 64 so the digest is bounded
        even if a pattern is later loosened.
      - The runner cross-checks the raw patterns against **ECMA-262 via node**, because the
        anchors have to hold in the server's engine too and one implementation agreeing with
        itself proves nothing about the other.
      - Guards mutation-tested rather than assumed: restoring the bare `$` anchor makes
        `trailing-newline-in-file-path` and `-dependency-path` report "ACCEPTED by the
        schema"; putting the index back at the published path fails with "…differ; the
        published path could validate something the released version rejects".
      - Positive fixtures carry **real** sizes and SHA-256 values of the payload bytes they
        describe, so T2 can build archives from them rather than inventing a second set.
      - Q4: no Maven dependency added. networknt remains a candidate for the server side;
        the fixture runner is a container-only dev tool and ships nothing.

      **T1(b) done 2026-09-17 — the output descriptor.** Reserved and specified now, as this
      plan requires, while rendering, current-rendition publication and downloads stay with
      #5, #6 and #8. Nothing writes or reads a rendition yet.

      - `schemas/output-descriptor/v1.schema.json` carries the field list decision 3 fixes:
        `layout_version`, content/version/rendition UUIDs, the version's display number,
        producer kind and id, RFC 3339 creation time with a mandatory offset, and a file list
        of relative path, size, SHA-256 and media type. 25 fixtures — 4 valid, 21 invalid —
        including `producer.kind = render`, reserved for #6 so that adding it later is not a
        layout change, and an **empty** file list, since a render that legitimately produced
        nothing is a complete rendition and is not the same as an incomplete one, which has
        no descriptor at all.
      - **The input and output path rules are checked for drift.** `payloadPath` and
        `renditionPath` are duplicated rather than `$ref`'d across files — a released schema
        that resolves a reference into another file has a meaning that depends on what that
        file says later — so the runner asserts they agree on type, pattern and both bounds.
        An output path and an input path face the same hostile input and must not diverge by
        accident.
      - **Names needing URL encoding are pinned**: spaces, `#`, a literal `%`, a literal
        `%25`, accented and Japanese characters, `+`, `&` and an apostrophe. The descriptor
        carries them literally, so that whatever encodes them for an S3 key or a URL does it
        at one boundary rather than inheriting something already mangled.
      - The ECMA-262 cross-check now covers the descriptor's UUID, timestamp, media-type and
        path patterns too, and rejects **CR and CRLF** as well as LF — a value from a
        Windows-authored file carries those, and `$` is not the only lenient anchor.
      - **`format: date-time` is enforced as an assertion, and the runner refuses to start
        without the checker.** Two separate things have to be true and neither is a default:
        in JSON Schema 2020-12 `format` is an *annotation* unless a validator is told to
        assert, and in this library being told is not enough — `date-time` only exists in the
        checker registry when a date-time implementation is installed alongside. With
        `pip install jsonschema` alone, passing `FORMAT_CHECKER` silently checks nothing.
        Month 99, **February 30th**, hour 99 and offset `+99:99` all validated against a
        schema advertising RFC 3339 (finding `c225d50-F1`). Six impossible-value fixtures and
        three positive controls — a leap day, a negative offset, fractional seconds — now
        cover it, because "rejects everything" and "works" look identical without them.
      - **The server-side validator inherits this requirement and must be proved, not
        assumed.** networknt follows the same 2020-12 default, so reading this schema is not
        enough to enforce the timestamp. Run the `created-at-impossible-*` fixtures against it
        when it lands. Not verified here: no Java validator exists in the tree yet.
      - Guards mutation-tested: widening `renditionPath.maxLength` reports the drift;
        percent-encoding one fixture filename reports the mismatch against the stated
        expectation; stripping `type`/`required` from the descriptor schema trips the vacuity
        probe on `null`, `42` and `{}`; removing `rfc3339-validator` from the container aborts
        with "format checker(s) not installed: date-time" and exit 2 rather than passing; and
        keeping the package but not passing the checker to the validator reports every
        `created-at-impossible-*` case as "ACCEPTED by the schema". Both halves fail
        independently, which is the property that matters — a missing dependency must not be
        able to quietly restore the green this once had.
      - Q4: `jsonschema==4.26.0` and `rfc3339-validator==0.1.4`, both MIT, both container-only
        dev tools pinned in `dev/validate-manifests.sh`. Neither ships in the jar and neither
        is a Maven dependency.
      - The round-trip check compares the parsed fixture against `url_encoding_expected_paths`
        in `expectations.json`, not against its own re-serialisation. An earlier draft did the
        latter, which is true whatever the fixture contains — a check that cannot fail is
        worse than no check, and this project has shipped two of those already.
      - The two fixture runners moved out of shell heredocs into `dev/schema-fixture-check.py`
        and `dev/schema-regex-check.js`, so `$schema`, `$defs` and `$ref` are not exposed to
        shell expansion and each can be read on its own.

      **T1(d) and T1(e) FROZEN 2026-09-18 by the user, as proposed and unchanged.**
      `spec/lifecycle-v1.json` (the ID/state vocabulary) and `spec/admin-transport-v1.json`
      (the nine admin endpoints) are public API shapes, so `CLAUDE.md` puts them to the user
      rather than to this plan. Both were taken as written. What freezing them commits to,
      stated here because a later reader will meet the consequences before the rationale:

      - Cancellation is **refused** once a build reaches `PUBLISHING`, and the recovery is
        deleting the *content*. **A version-delete endpoint was offered and declined**: it
        would have to prove nothing is running the version and nothing references its image,
        which is the live-proxy cleanup race this track deliberately does not open. It
        remains available to a later track that brings the machinery for it.
      - A **deadline** is not refused there, so `PUBLISHING` has a `TIMED_OUT` outcome and
        lease generation fences a late worker out of inserting a `content_version`.
      - `INTERRUPTED` stays distinct from `FAILED`, because reconciliation can conclude
        things about a build that ran and broke which it cannot conclude about one the
        platform lost.
      - The admin transport's CSRF defence is that **no endpoint accepts a media type an
        HTML form can produce** — ShinyProxy protects `POST /login` alone — so upload is a
        raw `application/gzip` `PUT` with a required `X-Skald-Upload` header and explicitly
        not `multipart/form-data`.

      These are now the source T6's tables and CHECK constraints, the coordinator and T8's
      controllers are written from. Changing them after this point is a migration and a
      client break, not an edit.

      **T1(g) done 2026-09-18 — the literal safe launch arguments. T1 is complete.**
      `spec/isolation-profile-v1.json`. The last item T1 owed, unblocked by the Q2 decision
      of the same day.

      - **Nine bounds, each carrying its literal argument and the probe that proves it** —
        `--cpus`, `--memory`, `--pids-limit`, `--security-opt=no-new-privileges`,
        `--read-only`, a `noexec,nosuid,nodev` sized tmpfs, the loop-backed workspace
        volume, the network, and `--security-opt=seccomp`. Thirteen forbidden arguments are
        listed **literally** — `--privileged`, `--cap-add`, the three `unconfined`
        security-opts, the four `host` namespaces, `--device`, the Docker socket bind and
        `--oci-worker-no-process-sandbox` — so a driver can be checked against them
        mechanically instead of being read for intent.
      - **The correspondence with `dev/sandbox-probe.py` is checked in both directions**,
        by parsing the probe with `ast` rather than trusting a list. A bound whose probe
        does not exist fails; a probe no bound claims fails. One direction alone is what
        lets a bound be written down and never measured — which is the entire failure this
        file exists to prevent, since a launch argument nobody measured is a sentence.
      - **A name the probe records as a FACT may not be a bound's proof.** This is finding
        `7b6e931-F2` made permanent instead of fixed once: AppArmor is unavailable here and
        `--storage-opt size` is refused outright, and both are recorded as facts. A profile
        citing either as proof of an enforced bound now fails the runner.
      - **The seam's refuse-to-start rule is machine-checked, not prose.** A runtime is
        selectable only if its status is `measured` and it enforces every bound. Today that
        is `runc-rootful` alone — and the file therefore says out loud that **the default,
        `runc-rootless`, is unmeasured and not selectable**, with the three things it owes
        listed against it. `runsc` is a candidate; `kata` is marked unavailable on this host
        because there is no `/dev/kvm`. Recording the intention as though it were the
        measurement is precisely the move this gate exists to refuse.
      - Mutation-tested, **fifteen mutations, every one caught by the branch it was aimed
        at**: a dropped bound, a probe that does not exist, a fact cited as proof, two
        bounds sharing a probe, an unmeasured runtime marked selectable, a selectable
        runtime missing a bound, an emptied forbidden list, a forbidden argument used as a
        bound, a deleted profile, emptied runtimes, emptied bounds, a runtime enforcing
        something unmeasured, a broken probe parser, and no selectable runtime at all. The
        last needed its own case: the obvious mutation for it was caught by a *different*
        check, which is the f1078e5-F1 lesson — a mutation caught for the wrong reason
        leaves the branch it was meant to cover untested.
      - The forbidden-argument check was itself wrong on first write: it compared the flag
        *name* before `=`, so `--security-opt=seccomp=unconfined` reduced to
        `--security-opt` and failed five times against a correct profile. It now compares
        whole flags.
      - `bash dev/validate-sandbox.sh` re-run on the host the same day rather than quoted
        from T3(a): **9 of 9 bounds, 2 facts**, docker 27.1.2. The `measured` status in the
        file is that run, not a recollection of one.
      - **Corrected before T1 could be relied on (`0164896-F1`, `0164896-F2`).** The first
        version of this file matched a bound to a probe by NAME only, and the sentence
        above — "each carrying its literal argument and the probe that proves it" — was
        therefore false for two of the nine. A bound could specify `--cpu-shares`, a
        relative weight that bounds nothing on an idle host, and be reported green as
        "proved by a distinct probe"; and two bounds in the shipping file were already
        wrong that way. The tmpfs bound specified `noexec,nosuid,nodev` while the probe
        measured only the size cap — on the bound whose own rationale is "noexec is not
        decoration". The seccomp bound was proved by `docker info` reporting that the
        **daemon supports** seccomp, a string that does not change when a worker runs
        `seccomp=unconfined`, which is the "flag-reading isolation test" decision 6 rejects
        by name. Both are now measured on the worker: noexec demonstrated behaviourally
        with the mount options read back from `/proc/mounts`, and seccomp shown as
        `Seccomp: 2` plus a denied syscall against an unconfined control at `Seccomp: 0`.
        The checker now compares the **literal argument** in both directions, so an option
        dropped from the profile fails as surely as one the probe never ran. Eighteen
        mutations, each caught by its own branch.

- [x] **T2. Author the adversarial corpus independently — before extractor code.**
      Depends T1. Implement the corpus/oracle and external sentinel harness described above
      without production validation helpers. Store fixture generator, hashes and expectations.
      Test the oracle against a deliberately unsafe disposable extractor and a deliberately
      unbounded variant under outer test limits. **Pass:** the oracle detects outside-root
      changes, duplicate overwrite, limit bypass and unexpected acceptance; it is not a
      collection of negative fixtures that would “pass” because nothing runs.

      **T2(a) done 2026-09-17 — the corpus and its self-check.** The oracle, the sentinels
      and the deliberately unsafe extractor are T2(b) and are what the Pass line above
      actually turns on; this is the material they will be pointed at. Counts below are as
      of the limits slice (2026-09-18): 90 fixtures, 19 accepted, 80 predicates, 18 hostile
      properties.

      - `dev/fixtures/bundles/generate.py` builds **90 fixtures** across all seven required
        groups: 14 positive controls, 10 traversal, 6 links, 20 bombs, 13 types and path
        limits, 8 duplicate/alias, 19 manifest and inventory. Standard library only, no
        import of any Skald class, and hand-written tar headers wherever a polite writer
        would refuse — a negative size, a NUL inside a name, a bad checksum, a GNU sparse
        member, an undefined typeflag. A corpus built solely with a well-behaved library
        omits exactly the cases worth having.
      - Seventeen fixtures are marked **accept**, not fourteen: three boundary halves live
        in the bombs group because that is where their pair is. The suite keys the hostile
        sweep on the fixture's expected decision rather than on its group name, so a
        boundary half cannot escape it by being filed elsewhere.
      - **Archives are generated, not checked in.** The plan asks for the generator, hashes
        and expectations; storing 3.4 MB of bombs as well would add a second place for the
        corpus to drift. Every SHA-256 is recorded and regeneration is byte-identical, so a
        generator change that alters a fixture fails loudly instead of redefining the test.
      - Boundary fixtures **and the predicates that police them** are parameterised off the
        configured limits, so an N/N+1 pair still straddles the real value after an operator
        changes one. Verified by reconfiguring all six limits at once (entries 20000→500,
        expanded 2 GiB→64 MiB, per-file 512 MiB→16 MiB, path 1024→256, segment 255→64,
        depth 32→8) and re-running the whole suite green.
      - `dev/bundle-corpus-check.py` asserts **every negative fixture exhibits the property
        its name claims**, with one predicate per fixture rather than per group. This is the
        part that matters: a corpus of negatives that nothing runs against reports itself as
        complete forever, and the way it rots is a fixture quietly becoming benign while
        still being counted. Accepted fixtures are checked to exhibit **none** of fifteen
        hostile properties, so "rejects everything" stays distinguishable from "works".
        Eleven of the eighteen are about size and shape against the configured limits.
      - A sweep can only say what a fixture is **not**, so nine accepted fixtures also
        carry a predicate of their own: each boundary half proves it sits *at* its limit,
        and the PAX control proves its override resolves to a member really present. They
        are marked `pins` in the generator and the checker refuses to run without a
        predicate for each, so a future boundary half cannot be added without one.
      - Its tar reader is hand-written rather than `tarfile`-based, because several fixtures
        are malformed on purpose and a library that refuses to parse them would leave
        precisely those uninspectable. It walks a **stream**: a member declaring two
        gigabytes has its header read and its payload skipped at constant memory, so the
        total expanded size and any later oversized member are still measurable. A bounded
        in-memory prefix is kept alongside it for the questions that are about raw bytes.
      - Mutation-tested: a traversal fixture made benign, a symlink added to a positive
        control, the setuid fixture losing its bit, the case-alias fixture ceasing to
        collide, a fixture's bytes changing without its hash, an at-limit control pushed
        over the limit, an over-limit negative pulled inside it, an accepted fixture
        shipping a file its manifest never declares, the streaming walker reverted to a
        bounded buffer, each boundary half shrunk until it straddles nothing, a PAX path
        record emptied and then pointed at a member that does not exist, and a pinning
        fixture stripped of its predicate. Each reported and failed.

      Two defects in the checker were found by the checker, both of the class this project
      keeps meeting. Its tar walker could not resolve GNU long names, so every fixture whose
      point is a long path was being inspected through a `././@LongLink` placeholder — which
      first surfaced as a *positive* control tripping the traversal check, because the
      placeholder contains `/./`. And the decompression bound discarded its buffer, so the
      expansion bombs' headers were invisible and `bomb-expanded-over-limit` appeared not to
      exhibit its own property.

      Review of 29857f7 found four more, and they share a single shape: **the checker had no
      predicate for the limits, so nothing policed the fixtures that are only about limits.**
      The one at-limit positive control was four bytes over the segment cap and invisible;
      three predicates compared against a literal rather than the configured limit, one of
      them against the 100-byte tar name field instead of `max_path_bytes`; and several
      required cases were absent, including any positive control with a PAX filename, which
      let an extractor that rejects every PAX header pass the whole corpus. The corrections
      are in the commit that references those findings. Review of that commit then found
      the mirror image, 3438045-F1: four accepted fixtures were swept for hostile
      properties but asserted nothing, so a boundary half could stop straddling its limit
      in silence — the same pair failing to pin anything, from the other side. The lesson
      is recorded here because it recurs: a checker inherits the blind spots of whoever
      wrote the thing it checks.

      **T2(b) in progress — the bounds, then the oracle.**

      - **Every documented bound is now configuration and every one has a fixture**
        (2026-09-18). Three were missing from `LIMITS`: 256 MiB compressed, 64 KiB per
        extended header, and the 60-second extraction deadline. Two of them had already
        produced the defect this corpus keeps finding — `bomb-huge-pax-field` compared
        against a literal `64 * 1024`, and `manifest-over-limit` against a literal 4 MiB
        with a 60000-entry fixture that a raised cap would have made benign while the
        predicate still called it covered. The deadline is not expressible in archive
        bytes; it lives in `LIMITS` because Q3 requires one home for the defaults, and the
        oracle meters it.
      - Four fixtures: compressed cap N/N+1 and extended-header cap N/N+1, all four
        parameterised. The compressed pair is the expensive one — 256 MiB of deterministic
        incompressible payload each — and it takes the suite from 47s to ~73s. Worth it:
        the compressed cap is the first bound anything hits, checked on the uploaded byte
        count before a header is parsed, and it was the only documented bound with no
        fixture at all.
      - **Nothing holds an archive.** Both sides stream: the generator writes the tar body
        to a temp file and gzips it to disk in chunks, and the checker hashes and walks
        from the file. The only payloads kept are the two that *are* content — PAX records
        and the manifest — and both are read by the walker rather than out of a
        fixed-size decompression prefix, so no size question depends on how much of a
        payload the checker chose to keep. Peak resident memory for the whole suite is **69 MiB**, against
        924 MiB in the checker and 2094 MiB in the generator when the pair was first
        added. The suite prints its own peak, including the generator's, so the next
        fixture that buffers something shows up there rather than in a CI runner being
        killed. Disk is the remaining cost: a generation writes 518 MiB into a temporary
        directory.
      - Hitting the cap **exactly** needs two levers. The tar body only moves in 512-byte
        blocks and deflate's output on incompressible data jitters a few bytes either side
        of the trend, so a search on payload size oscillates and never lands (measured:
        consecutive sizes gave 268435459, 268435461, 268435460). The remainder is taken up
        by the gzip member's stored original filename, which is outside the deflate stream
        and costs exactly its own length. The N+1 half is the same payload with one more
        byte of filename, which is what makes it a true pair.

      - **The outside-root sentinels** (2026-09-18), `dev/bundle_sentinels.py` and
        `dev/validate-sentinels.sh`. A disposable world — a private extraction root, a
        pre-created file where a relative traversal lands, a symlinked root, an ordinary
        sibling — plus a snapshot/diff over it and over the absolute targets the corpus
        actually names (`/etc/passwd`, `/etc/skald-escape.txt`, `/tmp/escape.txt`). No
        extractor is involved; it photographs the world, lets something else run, and
        photographs it again.
      - The suite's job is to prove the harness **can fail**. It performs each change it
        claims to detect — overwrite, create, delete, re-mode, retarget a symlink,
        replace a file with a directory, write through a symlinked root, and rewrite a
        file in place at the same size with mtime restored — and asserts the diff reports
        it. Three things it refuses to fake: a walk that hits its bound raises instead of
        returning a shorter snapshot; a sentinel target this process cannot write to is
        reported WEAK and fails the run, because watching an unwritable path reports
        "unchanged" forever; and read detection is *measured* rather than claimed.
      - Two of those came from review (6d7b790-F1/F2) and are worth keeping in mind for
        anything else that watches a filesystem. **ctime is the timestamp a writer cannot
        set**: above the hash limit, mtime can be restored after a same-size overwrite,
        and ctime is what survives it. And **taking the picture is itself an access** —
        hashing a file and listing a directory both move atime, so each entry records
        where the snapshot's own access left the clock, and a comparison runs "after the
        earlier walk" against "before the later walk".
      - Read detection is honestly unavailable. `read_detection()` asks the question that
        actually decides it — does a read move atime when atime is *already recent*? —
        and the answer under the default relatime is no, because the snapshot's own read
        consumes the single update. The harness prints the regime and the self-test
        asserts the blindness rather than papering over it. Verifying "reject without
        outside reads" needs syscall tracing, which belongs with the extractor.
      - It therefore runs as root in a disposable container with `--network none` and the
        repository mounted read-only. Unprivileged, the same suite exits 1 with "2
        sentinel target(s) this process cannot touch, so watching them proves nothing" —
        verified both ways.

      - **The oracle and the disposable extractor** (2026-09-18).
        `dev/fixtures/bundles/disposable_extractor.py` is test scaffolding — clearly
        labelled, standard library only, no shared code with the corpus checker, because
        the checker is the inspector and this is the subject. It has seven removable
        guards (`--without path|types|duplicates|limits|framing|pax|manifest`), plus
        `--unsafe`, which is `tarfile.extractall(filter="fully_trusted")` and really does
        write to `/etc` and through symlinks.
      - The corpus immediately earned its keep: a tarfile-only extractor **accepts**
        `bomb-bad-checksum` and `bomb-declared-size-negative` (tarfile reads an
        unparseable header as the end of the archive and returns cleanly — "a lenient
        parser may skip past into attacker-chosen bytes", silently, as an accept),
        accepts `bomb-huge-pax-field` (tarfile never reports an extended header's own
        size), accepts `trav-pax-override` (it does not apply that override, so the
        *effective* path is never checked) and crashes on `path-invalid-utf8`. That is
        the plan's "any library unable to expose these distinctions is unsuitable without
        an outer validator", demonstrated rather than assumed — the extractor now walks
        the raw 512-byte headers itself before tarfile sees them.
      - `dev/bundle-oracle.py` extracts every fixture for real, in a fresh world, and
        judges more than the return code: the decision matches the corpus, a **crash is
        never a rejection**, nothing outside the root moved, a rejected bundle left an
        empty root, an accepted bundle produced its declared inventory byte for byte with
        no extra files and no privileged modes, and the run stayed inside an outer
        deadline and disk budget. It imports no extractor — the extractor is a subprocess
        named on the command line, so the same oracle judges the real one at T5.
      - It runs a **reduced limit profile** by default (`generate.py --limit k=v`, which
        refuses to write expectations so the committed ones can only describe the
        documented defaults). At the defaults the bombs alone write about three gigabytes
        per pass; the boundary properties are parameterised, so they hold at any profile.
        `--full` uses the defaults.

      - **The Pass line is met and policed** (2026-09-18). `dev/bundle-oracle-matrix.py`
        and `dev/validate-oracle-matrix.sh` hand the oracle twenty-one subjects, each
        wrong in one specific way, and assert *which* finding comes back on *which*
        fixture — not that something failed, which an oracle failing everything for the
        wrong reason would satisfy. ~87s.
      - The four classes the Pass line names, each with the subject that demonstrates it:
        outside-root change (an extractor whose *decisions are all correct* and which
        plants one file outside the root — a decision-only oracle passes it), duplicate
        overwrite, limit bypass, and unexpected acceptance. Plus residue after rejection,
        unexpected *rejection*, and the outer deadline.
      - The most useful row is "rejects everything": it passes **71 of 90**, and the 19
        it fails are exactly the accepted fixtures. The positive controls are the only
        thing between a do-nothing extractor and a clean report.
      - **Removing one bound is usually masked by another guard.** With only `--without
        limits`, the inventory check rejects most bombs first — a bomb that ships an
        undeclared file is caught as inventory-extra-file long before any cap is
        consulted; `dup-regular` is likewise caught by the manifest hash check, not by
        the duplicate guard. Good news about layering, bad news for single-guard
        matrices, and the reason the limit-bypass and duplicate-overwrite scenarios
        remove two guards: to isolate the guard under test, not to inflate the numbers.
      - **Coverage is by construction, not by enumeration.** The oracle declares the
        thirteen finding kinds it can emit in one list and asserts it never emits an
        undeclared one; the matrix compares that list against the kinds its own
        scenarios assert and fails on any it does not police. Three commits in a row
        were corrected for "a check that nothing checks" (64f5dd8-F1, 3e23732-F1), each
        fix closing the kinds that had been *named* and leaving the ones nobody had
        counted — the enumeration was the defect. A kind added later now fails the suite
        the day it is added.
      - The dangerous omission was `crash`: under `--unsafe` the oracle sees nine crashes
        on fixtures the corpus expects to be *rejected*, so an oracle that folded crash
        into rejection would have turned all nine into silent passes with nothing
        objecting.
      - The matrix is mutation-tested against the oracle, which is the only way a suite
        asserting that another suite can fail is itself not vacuous. Neutering the
        outside-root detection fails three scenarios; the residue, crash, disk-budget,
        no-verdict, extra-output, wrong-output and privileged-mode checks each fail
        exactly their own; and declaring a kind with no scenario behind it fails the
        coverage check.

      - **A symlinked root fails closed** (2026-09-18). `--symlinked-root` points the
        subject at `<world>/via-symlink` instead of the real root, and every fixture —
        positives included — must then be rejected. This is not expressible as a fixture:
        every path check passes and every member still lands wherever the link points.
        The guarded extractor got it wrong until this was measured — extracting
        `pos-r-root` into the symlinked root wrote three files into
        `via-symlink-target` and reported **accept**. It now refuses the root up front,
        and `O_NOFOLLOW` covers the root itself and not only the components below it.

      - **The rename race** (2026-09-18), T2's last case. `--rename-race` swaps a
        directory inside the root for a symlink pointing out of it, over and over, while
        the subject writes 400 files into it — the classic time-of-check/time-of-use:
        every path the extractor validated was fine, and by the time it opens the parent
        the parent is a link. Under a race **either decision is acceptable** — refusing
        is correct and finishing is correct — so only containment is judged.
      - A negative result from a race is worth nothing on its own, so two things back it:
        a run where the racer never swapped **anywhere** is a failure with its own kind,
        `race-not-raced`, and the same race against `--without path` must escape. It
        does, 32 outside-root changes over 8 repeats, stable across five consecutive
        suite runs.
      - The racer gets exactly **one swap per repeat**, and the reason is the result:
        the guarded extractor fails closed on the first swap it meets
        (`parent-not-a-directory`), which ends the extraction. Eight repeats are
        therefore eight genuine encounters, each survived — and the vulnerable variant
        escapes on that same single swap, which is what calibrates the window as wide
        enough to matter.
      - Finding the racer's own bug is the point worth keeping: it first raced
        `<root>/www` only, and an extractor with the path guard removed does not strip
        the payload root, so it writes `<root>/app/www`. The *vulnerable* variant was
        never raced at all, and its clean run read as a pass. It now races both spellings.

      **T2 is done.** One thing in the plan's links row is not verifiable and is not
      claimed: "reject without outside **reads**". Reads are only observable through
      atime, and the default relatime mount makes them invisible once the harness has
      taken its own picture — the sentinels measure and report this rather than asserting
      silence. Verifying it needs syscall tracing of the extractor, which belongs with
      the extractor at T5.

- [~] **T3. Prove the sandbox on the actual Docker host — Opus 5 leads.** Depends T0/T2.
      Pin a rootless BuildKit candidate and prototype only the launcher/worker contract,
      quota enforcement, egress gateway and trusted registry transport. Exercise malicious
      code in a real dependency-install hook, not merely a sibling test container. Include
      a second worker/canary despite normal concurrency one. Run every isolation attempt
      above and an allowed package build/push as positive controls. **Pass:** measured
      containment and cleanup plus the exact deployment profile. If it requires a weakened
      invariant, stop and present the failed probe and alternatives for Q2 sign-off.

      **T3(a) done 2026-09-18 — what this host can actually enforce.**
      `dev/sandbox-probe.py` and `dev/validate-sandbox.sh`. **Nine bounds**, each
      exercised against a container that tries to exceed it and failing the run if it is
      not demonstrably enforced, plus **two recorded facts** about what the host offers.
      The two are counted separately: "AppArmor is not available" is not an enforced
      bound however prominently the detail line says so. It runs on the host, not in a
      container, because the host is the subject.

      | Bound | Measured |
      |---|---|
      | CPU | `--cpus=0.5` → 0.51 cores, `--cpus=2` → 2.01, unrestricted → 3.99 |
      | Memory | 256 MiB allocated under a 64 MiB limit → exit 137 (SIGKILL) |
      | PIDs | `--pids-limit=32` → fork blocked at 30 |
      | no-new-privileges | `NoNewPrivs: 1` with the flag, `0` without |
      | Read-only rootfs | writes to `/root` and `/tmp` both refused |
      | Sized tmpfs | 200 MiB asked, 64 MiB written |
      | Loop-backed volume | 200 MiB asked into a 64 MiB volume, 53 MiB written |
      | Network | `--network none` → outbound connect refused |
      | seccomp | `name=seccomp,profile=builtin` |

      **Q2 — the CPU worry T0 raised does not apply, and the disk one is solved.**
      - T0 recorded that the user session delegates only `memory pids`. That path
        (`/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service`) **does not exist
        on this host**; this shell's cgroup is `0::/` and the root cgroup delegates
        `cpuset cpu io memory hugetlb pids rdma`. Workers run under the rootful Docker
        daemon, which applies the quota itself — measured above, scaling exactly. The
        finding was recorded honestly and is simply superseded by measurement.
      - **Disk was the real gap.** `--storage-opt size=` is refused outright (overlay2 on
        extfs needs xfs with `pquota`), and an unbounded container wrote 200 MiB into its
        own layer at 3.4 GB/s. The contract calls for a real quota, not a free-space
        check. Solved without changing the host filesystem: a **loop-backed ext4 volume**
        plus `--read-only`. A sparse image is made and attached by one-off *privileged
        setup containers* — that privilege is the trusted launcher's; the worker receives
        the volume, never the device, and cannot write anywhere else.
      - **AppArmor stays unavailable** (`enabled = N`), confirming T0. Confinement here
        rests on user namespaces, seccomp and cgroups, and no profile may claim otherwise.

      Mutation-tested, because a probe suite that cannot fail measures nothing: dropping
      the CPU quota reports `0.5 -> 4.00 cores`; dropping the memory limit reports
      `exited 0`; swapping the 64 MiB volume for a 1 GiB tmpfs reports the full 200 MiB
      written. Each turns the run red.

      **T3(b) done 2026-09-19 — five of the six owed items, and the sixth is blocked.**
      Four new suites, each with a self-test that weakens the thing it measures and
      requires the matching check to notice.

      | Owed item | Suite | Outcome |
      |---|---|---|
      | Malicious code in a real dependency-install hook | `dev/validate-hostile-deps.sh` | **9 escape attempts** in `dev/hostile-dep-probe.py` from inside a real `setup.py`, across 11 detection sites, all contained; 9 deliberate holes, all detected |
      | Second worker/canary | same | A sibling workspace with data in it, looked for and not found; proved by mounting it |
      | Egress gateway and allowlist | `dev/validate-egress.sh` | Deny-all except the configured host, 6 checks, 7 weakenings detected |
      | Rootless BuildKit | `dev/validate-rootless-buildkit.sh` | Builds under Docker's **deny-by-default** profile plus 2 syscalls, `process-mode:sandbox` intact |
      | Launcher/worker contract | `dev/validate-launcher-contract.sh` | One daemon per attempt by its own id, no socket, no context mount, no credentials, none outliving its attempt |
      | Trusted registry transport | same | Base pulled from the registry **through** the allowlisted gateway; pushing a built image is part of the blocked item below |

      **Q2's default needed no relaxation.** Every published rootless-BuildKit recipe
      reaches it through `seccomp=unconfined`, `apparmor=unconfined` or
      `--oci-worker-no-process-sandbox`. Decision 6 rejects all three and the first is in
      the isolation profile's own `forbidden_arguments`. None is used: Docker's default
      profile plus `clone` and `mount` is enough, which is a *named* profile rather than
      the absence of one. No sign-off was required and none is requested.

      **A minimal syscall set is a property of a configuration, not of a program.** The
      two above were measured where the base is pulled over ordinary Docker egress. Where
      a layer is *extracted* from a registry pull, that set intermittently fails on
      `umount2`, so `umount2` is carried in a separate `INTERMITTENTLY_NEEDED` list — its
      justification is an observed flake, and the self-test would rightly refuse to
      certify it as required.

      **BLOCKED, and this gates T7.** The nested `RUN` step does not reliably complete in
      the full configuration — internal network, proxied egress, registry pull,
      TCP-addressed worker, session-streamed context. Two intermittent failures seen,
      `failed to unmount ...: operation not permitted` and `nsexec: failed to sync with
      stage-1`, and widening the syscall set to
      `clone,mount,umount2,setns,unshare,pivot_root` did not help (0 of 2). The host is
      not the cause: `dev/validate-rootless-buildkit.sh`, which builds on the default
      bridge with a mounted context, passed 5/5 immediately before and after. The launcher
      suite therefore asserts reaching build stage 2 — which proves the context streamed
      and the base pulled through the gateway — and does not claim the RUN or the push.
      **Decision 6's gate holds: no production build driver connects until this is
      understood.**

      One finding against the earlier work, recorded because no review caught it:
      `dev/rootless-buildkit-probe.py` bind-mounts the build context into the worker,
      which decision 6 forbids in terms. The launcher suite streams instead and asserts
      the mount's absence by reading the container.

- [x] **T4. S3 adapter and layout proof.** Depends T1. Use real MinIO and scoped service
      credentials; implement immutable artifacts, checksums, completion descriptors,
      multipart abort and log chunk replay. Round-trip bundle/log/output descriptors
      through an independent small reader, including filenames requiring URL encoding.
      Kill writes between object and descriptor completion; revoke permissions and stop
      MinIO. **Pass:** no partial artifact advertised, no public/cross-key read, observable
      storage failure, restart-safe retries and no filesystem durability fallback.

      **T4 done 2026-09-19.** `publisher/storage/`: `ObjectKeys`, `ObjectStore` +
      `S3ObjectStore`, `BundleWriter` + `BundleReceipt`, `BuildLogWriter` + `LogIndex` +
      `LogFinal`. **46 tests** in that package, 32 of them against a real MinIO container
      pinned by digest and 14 needing none — `ObjectKeysTest` and `AwsSdkClasspathTest`
      earn their keep precisely by being true without a container. `make test` 184/184,
      up from 138 before this track.

      - **The key layout is parsed from this file's storage table, not restated.** A
        mistake in a key is a migration, not a bug fix. The one component the platform does
        not generate — the path inside a rendition — is validated here, because the output
        descriptor schema says containment "is the writer's to enforce"; and the limit that
        binds is the **key** in UTF-8 bytes, not the path in characters, which a
        1024-character path producing a 1172-byte key made plain (`2b483fb-F1`).
      - **Digests are ours.** SHA-256 computed over the bytes that moved, never the ETag,
        and recomputed on a verified read. A streamed put cannot record its digest as
        metadata — headers precede the body — so `receipt.json` is the durable record and
        `StoredObject.sha256()` is an `Optional` so that absence cannot be missed
        (`f440ce4-F2`).
      - **Completion is the receipt and nothing else.** Bytes first, `receipt.json` last,
        every object create-only, and `readReceipt` deliberately never looks at the archive.
        Commit checks the receipt's claims against the objects rather than only their
        existence (`d319b14-F1`); `archiveSha256` is the one claim taken on trust, because
        verifying it would mean re-reading the archive, and the javadoc says so.
      - **The log index advertises a contiguous run**, never the highest sequence present,
        so completion can never point past a hole. `complete`, `truncated` and the build
        outcome are three separate facts. The generation guard is a **compare-and-swap**,
        not a read-then-write, after the read-then-write was shown to fail under
        interleaving (`4f81ee0-F1`).
      - **Every Pass condition has a control.** The scoped-credential denials are measured
        against an object placed by the root user and asserted present; "no multipart
        upload to abort" is measured against one created deliberately, seen, and aborted.
        An absence proves nothing unless the probe can see a presence.

      **Not covered, and not claimed.** Chunk replay against a *committed cursor* is T6's,
      since the cursor is the DB's; this track built the storage half. Stopping MinIO is
      exercised as an unreachable endpoint rather than by killing the container mid-write.
      `head()` returning 403 rather than 404 for a forbidden object is MinIO's behaviour;
      real S3 depends on whether the caller holds `s3:ListBucket`, and that is unverified
      here.

- [ ] **T5. Extractor plus mandatory independent mid-track security review.** Depends
      T1–T4. Implement bounded extraction, validation and private workspace handling,
      including rules S1–S11 of "Semantic validation" above — S10 and S11 in particular,
      which no earlier task can prove because they need real extracted bytes.
      Run the untouched T2 corpus and resource measurements; mutation-test each defense.
      A new reviewer/session reads the extractor and sandbox configuration, adds withheld
      archive/escape fixtures and drives T3's live attempts independently. Review all
      security comments against named tests. **Pass:** a completed review with every
      finding resolved, the five conditions below satisfied and recorded, and no skipped
      isolation probe; same corpus through the upload pipeline once T8 exists.
      Driver/log plumbing may proceed only against reviewed boundaries after this gate.

      **The reviewer is the independent reviewer AGENT, decided 2026-09-18 by the user.**
      There will be no human security review at this gate. The two-session split in
      `code_review/` is the mechanism: the coding agent implements and commits, a separate
      session that cannot see its reasoning reads the commit and the tree, writes its own
      probes and fixtures, and records findings in a report. The earlier wording said
      "signed review", which implied a human signature; it is struck rather than quietly
      redefined to mean something else.

      **What this genuinely provides, on the evidence of T2 and T3(a).** Across seventeen
      review cycles (`3f8bdd2..2124414`, ten of them CHANGES_REQUIRED) the reviewer found
      defects the author had missed, several of them in things the author had just asserted
      were fixed: an at-limit fixture four bytes over its limit (`29857f7-F1`), four
      predicates comparing against literals instead of the configured limit (`29857f7-F2`,
      `29857f7-F3`), a 924 MiB peak a commit had described only in seconds (`6987f01-F1`),
      a check with nothing asserting it, three commits running (`6d7b790-F1`, `64f5dd8-F1`,
      `3e23732-F1`), and commit messages asserting what was not so — a coverage claim in T2
      that named groups while required cases inside them were missing (`29857f7-F4`) and,
      in T3(a), a claim that this workplan said something it did not (`7b6e931-F1`). It
      wrote its own extractors, mutations and probes rather than re-running the author's.
      That is a real control, not a formality.

      The IDs are here rather than a bare count because this paragraph's whole authority is
      that its numbers are checkable. Each draft of this sentence has been wrong about that
      in a different way — a miscount first, then three citations that did not support the
      claims attached to them — which is the argument for the paragraph, not against it.

      **What it does not provide, and this plan must not pretend otherwise.** It is not an
      external human security review. Both agents share a model and therefore share blind
      spots; a class of mistake invisible to one is likely invisible to the other, and no
      number of review cycles fixes a correlated blind spot. There is no accountable
      signature. Nothing here discharges the need for a human to look before untrusted
      bundles from real users are accepted — that remains **owed, and owed to the
      operator, not to this plan**.

      **Conditions that make the agent review worth something.** Each is a requirement of
      this gate, not advice:
      - The reviewer **authors its withheld archive/escape fixtures before reading the
        extractor**, and records that it did. Fixtures written afterwards test the
        implementation's own idea of the problem.
      - The review runs in a **fresh session**, not one that watched the extractor being
        built commit by commit. Incremental familiarity is anchoring. This **disqualifies
        the standing per-commit reviewer**, which watches the extractor land commit by
        commit by design (`code_review/README.md`), so the T5 gate is a separately arranged
        session — and, because its fixtures must predate its reading of the extractor, one
        arranged *before* T5's implementation commits begin. Who arranges it is not settled
        here; that it must be arranged in advance is, since a condition nobody schedules is
        not a control.
      - The reviewer **re-runs T2's corpus and T3's probes itself**, from the committed
        tree, rather than accepting the author's reported output.
      - Every finding class gets a **permanent test**, not a one-off fix. T2 produced the
        same finding — "a check that nothing checks" — three commits running
        (`6d7b790-F1`, `64f5dd8-F1`, `3e23732-F1`), because each fix closed only the
        instances that had been named. It stopped when the matrix was made to derive its
        coverage from the kinds the oracle can emit instead of enumerating them (`6024d51`),
        which is what "permanent test" means here.
      - A review that produces **no findings is itself a finding** at this gate: the
        reviewer states what it attacked and failed to break, rather than reporting
        silence.

- [ ] **T6. V2, admission and durable coordinator.** Depends T1/T4/T5. Apply V2 to fresh
      and populated V1 PostgreSQL, preserve V1 checksum/rows/IDs/paths, test NOT NULL and
      uniqueness constraints. Add idempotency, leases/fencing, cancellation and admission
      quotas. Use a fake driver for deterministic crash/concurrency tests **only here**.
      Exercise concurrent version allocation with the legacy image endpoint; content
      deletion vs queued/finalizing work; same-key/different-input 409. **Pass:** no failed
      build produces a version, exactly one version per success, no accidental activation,
      no orphan artifacts whose ledger record was cascaded away.

- [ ] **T7. Trusted bases, recipes, BuildKit driver and cache.** Depends T3/T5/T6.
      Add `images/` catalog and selected language/type bases, fixed non-root launchers,
      dependency restore for both languages, scoped cache import/export and digest publication. Test source-only
      edit gives a dependency cache hit; lockfile/base/architecture/recipe/local-dependency
      change misses; another content cannot read/poison the cache; cold-cache build works.
      Inject failed restores, unreachable repositories, push failure, timeout, cancellation
      and worker death. **Pass:** actual built image with recorded digest/provenance, useful
      failed-build log, bounded teardown, and cold runtime pull from the chosen registry
      authority. No mocked “build succeeded” counts toward this task.

- [ ] **T8. Admin upload, status and live logs.** Depends T4–T7. Add the narrow admin
      transport, streaming/replay and plain-text view; exercise the complete T2 corpus
      through HTTP. Real OIDC Alice allow/Bob deny/signed-out deny for every endpoint,
      cross-content IDs and every log cursor/object lookup; hostile-origin form/fetch
      tests paired with successful authorized uploads. Break MinIO mid-log, disconnect
      clients and resume by cursor. **Pass:** durable in-progress and failed logs are
      readable, no slow client stalls a build, no new CSRF or source/log disclosure path.

- [ ] **T9. Managed publication and unchanged runtime semantics.** Depends T7/T8.
      Wire successful builds into the shared version allocator with explicit activation.
      Consume only the server-generated `spec_json` contract; test its fingerprint and
      legacy {} behavior. Start real built R and Python content through `/c/<path>/`; verify
      HTTP plus Shiny WebSocket interaction, effective user/limits/mounts and identity. Fault-inject
      every push/log/DB/response boundary; replay callbacks and late cancellation. **Pass:**
      success produces one staged digest-pinned version, failed/interrupted work never
      becomes active, and old direct-image tests still pass without a second override.

- [ ] **T10. Live acceptance, rollback, GC and final independent regression review.**
      Depends all above. Add re-runnable `dev/bundles-live.sh` using unique IDs/paths and
      asserted cleanup, described in Done when. Include restart during build, failed build
      retry, log retention, orphan/multipart cleanup and real registry GC with a referenced
      old image protected. **Retention is asserted per row of the policy table above, on both
      sides of each boundary, and the failed-attempt rows are asserted separately from the log
      row because they are on different clocks** — a failed attempt's *artifacts* present at 29
      days and collected at 31, while that same attempt's *logs* are still present at 31 and
      survive to 89, being collected only at 91; a successful build's logs likewise present at
      89 and collected at 91; a published version's image and bundle still present after all of
      those; an `INTERRUPTED` attempt treated as terminal like the rest; and a nonterminal
      attempt never collected however old its clock would make it. "Cleanup ran" is not the assertion;
      "cleanup collected exactly what the policy names, and nothing it protects" is. Re-run the extraction and isolation suite against the final
      integrated artifact; independent reviewer signs off changes since T5. Run
      `make build`, `make dev`, smoke, ACL, bundle live tests and `make test` anew.
      **Pass:** actual output and named failed mutations, no vacuous deny cases, no
      unresolved security finding or unapproved relaxation.

## Risks and open questions

| Question/risk | Recommendation, decision owner and stop condition |
|---|---|
| **Q1 — CLOSED: runnable breadth** | User selected **R and Python Shiny now**. Both are required end to end. T1 selects exact maintained language/tool versions and freezes the two manifest branches; additional version support is an additive catalog choice. Static/API/data behavior remains with its owning track. |
| **Q2 — DECIDED 2026-09-17, superseded 2026-09-18; the profile still owes its proof** | The user takes the systemd route: a `Delegate=cpu cpuset io memory pids` drop-in for `user@.service`, so the user manager can enforce a CPU bound on a rootless worker. T0 found the host delegating only `memory pids`, and the parent slice offering `cpuset cpu io memory hugetlb pids rdma`, so the mechanism exists and was merely switched off. **Not yet verified, and the configuration check is not the proof:** `cgroup.controllers` listing `cpu` says the delegation happened; `systemd-run --user --scope -p CPUQuota=50% sleep 1` succeeding says a quota can be *applied* to a scope. Neither measures **enforcement**, and a sleeping process consumes no CPU, so that command is a preflight and nothing more. T3 still owes a CPU-burning probe against the real worker *and its descendants*, and T5 repeats it independently; a successful preflight does not satisfy either. Record both outputs against this gate before T3 relies on it, labelled as preflight. AppArmor remains unavailable on this host — a fact, not a decision: the profile is confined by user namespaces, seccomp and cgroups, and the write-up must say that rather than listing AppArmor. Privileged mode and a disabled process sandbox remain unaccepted. **Measured 2026-09-18 (T3a) — the premise changed, and the decision above may no longer be needed.** The `user@.service` path T0 read does not exist on this host; this shell's cgroup is `0::/` and the root cgroup already delegates `cpuset cpu io memory hugetlb pids rdma`. More to the point, a worker launched through the **rootful Docker daemon** is bounded by the daemon, not by a user manager, so the `Delegate=` drop-in is moot for that architecture. The CPU-burning probe this row demanded has been run against a container **and its four forked descendants**: `--cpus=0.5` → 0.51 cores, `--cpus=2` → 2.01, unrestricted → 3.99, with memory (SIGKILL at the cap), PIDs (fork blocked at 30 of 32) and a real disk quota measured alongside — `bash dev/validate-sandbox.sh`, 9 of 9 bounds. **What was still the user's call, ANSWERED 2026-09-18 by the decision below:** whether Skald should nonetheless run workers rootless under the user manager, in which case the drop-in and a repeat of this probe in that mode are both still owed. (It should; both are still owed. The paragraph is kept unrewritten because the history is the useful part, but it is no longer an open question and must not be read as one.) This note does not retire the decision; it records that the gap it was taken to close is not present on this host. **DECIDED 2026-09-18 by the user: rootless stays the default, and the worker runtime becomes a configuration seam (decision 6).** The reasoning, because the premise this row spent two rounds on was the wrong premise: "rootless" answers *does the platform need root to build*, which is a deployment question; it does not answer *what happens when build code defeats the kernel*, which is the tenancy question, and only a separate kernel — gVisor, or a microVM under a hypervisor — answers that. T3(a) measured cgroup bounds, which the rootful daemon supplies either way; it never measured escape, so the measurement retired the CPU-quota argument for rootless and left its actual argument untouched. **Where the line falls is this plan's judgement and NOT the cited guidance's, and the guidance leans the other way.** An earlier draft of this row said "the published guidance is equally clear that a hypervisor for builds originating from accounts the operator issued is architecture for its own sake". It says no such thing, and the correction matters because this paragraph is what the T5 review and the human look still owed to the operator will read as the state of the evidence. What the sources actually say: pandastack's test is "whether a person you have never met can cause a command to run on your builder", it limits rootless BuildKit's strengths to "single-tenant scenarios", and it states plainly that "RUN still executes the submitter's code in your namespace, on your kernel"; emirb calls hardened containers "legitimate for trusted workloads of your own code" and names "CI scripts from hundreds of developers, multi-tenant platforms" among the **strongest** microVM cases; fly.io draws its line at whether "the code is yours". Skald's publishers hold accounts in the operator's directory, but a directory account is weaker than the commit access pandastack names, and one node serves many publishers — which is nearer emirb's many-developer CI than to "your own code". **The argument for the default is ours:** an operator issues, revokes and audits those accounts and can bind a bundle to a person, which is a control the container-versus-microVM literature does not weigh at all. That argument is defensible and it is the one the user took; it is not a consensus, and recording it as one would have hidden the strongest objection exactly where a reader goes looking for it. So: rootless by default **because of the account-issuance argument**, seam for the deployments where that argument does not hold — and the contrary reading above is the reason the refuse-to-start clause and the still-owed human review are not decoration. **A hard constraint, measured on this host 2026-09-18 and not a matter of effort:** there is no `/dev/kvm` and no `vmx`/`svm` in `/proc/cpuinfo`, so Firecracker and Kata cannot run here at all and a microVM profile cannot be *measured* — and T3/T5 accept measured containment only. gVisor needs no KVM and is provable here, but BuildKit under it fights overlay-on-overlay and wants a tmpfs upper layer, so it is a candidate profile and not a default. **Still owed by the rootless default, unchanged by this decision:** the `Delegate=` drop-in or an equivalent, a repeat of T3(a)'s nine probes in rootless mode, and a replacement for the loop-backed ext4 disk quota, which today is attached by *privileged setup containers* a rootless worker will not have. |
| **Q3 — CLOSED 2026-09-17** | Four answers, and two of them change the design rather than filling in a number. **(1) Sizes, counts and timeouts are configurable per deployment** with the documented defaults above, so an operator sizes them to their own host; a configured value is validated at startup and a limit may be raised but not removed. **(2) Retention** is decided, and the per-artifact table in "Status, logs, admin transport and cleanup" is the only authoritative statement of it — this row deliberately does not repeat the numbers, because restating them in two places is exactly what produced finding `d4f5baf-F1`. In summary: a published version's bundle and image are pinned until the content is deleted, while logs and failed-attempt artifacts expire. **(3) Package sources are configurable** — default CRAN and PyPI, an operator may point at their own Nexus, Artifactory, Posit Package Manager or a forge-style proxy. The egress rule therefore becomes **deny all except the configured repository hosts**, which is stricter to state and easier to implement than a hard-coded allowlist, and it is what lets a private mirror work without special-casing. R and Python remain the only languages in v1. **(4) System packages are the administrator's**, installed into the base images; a build never installs one. A build that fails for a missing system library **surfaces the build log** and stops there — the publisher takes it to their administrator. A curated error-to-package-name mapping was considered and **rejected as scope**: it can never be complete, and a half-complete lookup that confidently names the wrong package is worse than the compiler's own message. |
| **Q4 — dependencies and base-image licensing** | **AWS SDK S3 LANDED 2026-09-18**, and the version decision is not the obvious one: `s3` and `url-connection-client` are declared at **2.31.21**, pinned to the version ContainerProxy already brings, not to the newest release. The engine carries the entire 2.31.21 module set transitively — `s3` included — so declaring the then-latest 2.55.0 did not sit beside the engine's modules, it *upgraded the engine's own* `s3` and left `sso`/`sts`/`ecs` behind, producing a mixed-version classpath that Maven resolves silently and that fails at runtime rather than at build time. Measured: 33 awssdk artifacts before, 34 after, the one addition being `url-connection-client`. All resolved artifacts are Apache-2.0, so no sign-off was triggered. **Upgrading the set to a newer SDK is flagged and NOT taken**: it changes what ContainerProxy runs with, not only what Skald runs with, and it becomes forced if an advisory lands against 2.31.21. `AwsSdkClasspathTest` fails the build if the single-version invariant breaks. Remaining candidate Java additions: Commons Compress (Apache-2.0), networknt JSON Schema Validator (Apache-2.0); BuildKit (Apache-2.0). Flag exact versions/transitives before adding. Check base-image/package license inventory too; R/toolchain images contain their own licenses. Any new GPL/AGPL dependency follows CLAUDE.md's explicit sign-off rule; the presence of dev MinIO is not blanket approval for an AGPL SDK. |
| Existing ACL decision cache | Keep ACL/visibility mutations out of #2; don't introduce viewer-to-builder authorization via cached `canAccess`. Admin gating remains centralized. #4 still owns revocation/fork question. Test warm sessions as well as fresh ones. |
| Runtime isolation vs build isolation | The engine exposes user/CPU/memory/volume/network settings, but this is not evidence for every sandbox guarantee. T9 tests what the launched image actually gets; missing required engine support is escalated under ADR-0001. |
| Dependency reproducibility | A lockfile cache is not an artifact mirror or deterministic-build guarantee. Record resolved provenance and make cold builds fail clearly when dependencies disappear. Never rebuild to roll back. |
| DB/storage/registry disagreement | Durable intents, unique completion, fenced callbacks and collector grace periods; crash tests are mandatory. Do not report success while image/log evidence is missing. |
| Destructive cleanup and live-proxy races | Protect all retained versions and inspect actual proxy state; no automatic version pruning in #2. Exercise races, retain dry-run evidence, and fail cleanup closed if reference discovery fails. |

External implementation references checked during planning (not proof that Skald meets them):

- Isolation guidance consulted for the **Q2 decision of 2026-09-18**, recorded because the
  decision turns on what they separate rather than on a number any of them gives:
  [Firecracker vs gVisor](https://fly.io/learn/firecracker-vs-gvisor/),
  [Kata vs Firecracker vs gVisor](https://northflank.com/blog/kata-containers-vs-firecracker-vs-gvisor),
  ["Your container is not a sandbox"](https://emirb.github.io/blog/microvm-2026/) and
  [untrusted image builds in microVMs](https://www.pandastack.ai/blog/microvm-container-image-builds/).
  The distinction they draw, and the one this plan adopts: rootless answers whether the
  platform needs root to build; only a separate kernel answers what happens when build code
  defeats the shared one. The same sources say a hypervisor is unwarranted where every build
  comes from an account the operator issued, which is Skald's case. Reading them is not
  evidence Skald meets anything — T3 and T5 measure that, and the no-KVM constraint on this
  host bounds what can be measured at all.
- [Docker in gVisor](https://gvisor.dev/docs/tutorials/docker-in-gvisor/), for why gVisor is
  a candidate profile and not the default: it needs no KVM, so it is provable on this host,
  but overlay-on-overlay is refused by Linux and it wants a tmpfs upper layer.
- [BuildKit rootless requirements and process-sandbox caveats](https://github.com/moby/buildkit/blob/master/docs/rootless.md).
  Its container examples relax security profiles; `--oci-worker-no-process-sandbox` has
  documented process-control/cleanup drawbacks. This is why T3 precedes integration.
- [BuildKit configuration](https://github.com/moby/buildkit/blob/master/docs/buildkitd.toml.md)
  and [registry cache exporter](https://docs.docker.com/build/cache/backends/registry/).
  Cache export is separate from image publication; select and pin actual tool versions
  in the spike rather than relying on moving documentation examples.
- [S3 multipart lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html).
  A completed upload exposes the object; unfinished uploads require abort/cleanup, and an
  ETag is not a reliable content digest. Live logs therefore use completed chunks.
- [Distribution garbage collection](https://distribution.github.io/distribution/about/garbage-collection/).
  Blob reclamation requires write coordination; registry age alone is not a DB reference check.
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12),
  [renv restore model](https://rstudio.github.io/renv/articles/renv.html),
  [Shiny for Python launch API](https://shiny.posit.co/py/api/core/run_app.html),
  [pip hash-checking and wheel-only installs](https://pip.pypa.io/en/stable/topics/secure-installs/),
  [Commons Compress security reports](https://commons.apache.org/proper/commons-compress/security.html),
  [networknt license](https://github.com/networknt/json-schema-validator/blob/master/LICENSE),
  [AWS SDK license](https://github.com/aws/aws-sdk-java-v2/blob/master/LICENSE.txt),
  [BuildKit license](https://github.com/moby/buildkit/blob/master/LICENSE).

## Done when

The operator can run one documented live script against `make dev`, without hand-editing
SQL or providing a prebuilt application image, and observe all of the following. Run the
full build/activation/rollback/cache sequence for **both R and Python Shiny**, including
Python Core and Express positive fixtures; neither language may be represented by a mock.

1. Alice uploads real locked-dependency R and Python Shiny bundles, sees validation/build status and
   logs **while building**, obtains an immutable image-backed staged version, explicitly
   activates it, and interacts with the application at its `/c/<path>/` URL. Bob is denied
   upload, build controls, source and logs; ordinary runtime ACL allow/deny still works.
2. A modified bundle builds version 2. Keep actual version-1 and version-2 containers
   alive across activation and rollback. Rollback points new requests at version 1 while
   both existing proxy IDs stay listed and reachable through their existing routes; neither
   container is restarted or silently rebuilt. Confirm instance-specific state remains.
   `/c/` resolves the currently active version per request: no promise is made to pin a
   fresh `/c/` navigation to an old version. Existing WebSocket connections are tested.
3. A failed dependency build and a timed-out malicious build create no runnable version,
   do not move the active pointer and leave viewable durable failure logs. Retry has a new
   build ID; an HTTP retry has the same ID. Platform restart, client disconnect and MinIO
   or registry outage do not manufacture success or leak workers/volumes indefinitely.
4. The independent extraction corpus rejects escapes and bombs with unchanged outside
   sentinels; real build-code attempts cannot reach the Docker daemon, host or sibling
   workload canaries. Positive controls prove the tests are live. All limits and cleanup
   are measured, and the independent mid-track and final security reviews are recorded.
5. A source-only edit reuses the dependency layer, relevant dependency/toolchain changes
   miss it, another content cannot poison it, and rollback still works after real cleanup
   with all retained-version artifacts protected. No privileged worker, Docker socket
   mount, broad egress bypass or insecure fallback was used to achieve a green.
6. V1 checksum is unchanged; V2 upgrades real existing content without changing IDs,
   paths, ACLs or legacy behavior. `content_env` is still unwritten and no secret injection
   is falsely advertised. The branch builds and all upstream/new tests and live scripts
   pass with actual counts and logs recorded for the implementation commit.

**Next agenda item:** T0/T1 with the confirmed R/Python scope, followed by the Q2 isolation
proof and independent review. Implementation proceeds
only against the agreed contract; this workplan itself adds no schema, code, dependency,
image, service or authorization change.
