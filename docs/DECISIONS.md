# Decisions

Lightweight ADRs. One per decision that would be expensive or embarrassing to reverse.
Newest last. A decision recorded here is **locked** — a track that finds it wrong stops
and escalates rather than working around it.

---

## ADR-0001 — Consume the released ContainerProxy jar; do not fork it (yet)

**Date:** 2026-09-15 · **Status:** accepted

ShinyProxy is a plugin layer over ContainerProxy (`eu.openanalytics.containerproxy`,
v1.2.4), which is consumed as a released jar. The handoff asked whether to also fork
ContainerProxy or live within its extension points.

Reading v1.2.4, most of what we need is already reachable: `IProxySpecProvider` is two
methods and is consulted **per request**; `AccessControl` evaluation is entirely
spec-driven; `ICustomSecurityConfig` is a collected-bean seam; `dispatchAsync` is public.

Exactly one thing blocks us: `ProxyDispatcherService.init()` is `@PostConstruct` and
enumerates specs once at startup, so `getDispatcher(specId)` returns `null` for content
added later. It is injected in exactly one place (`ProxyService.java:104`, field
injection by type), so a `@Bean(name="proxyDispatcherService")` of our own lazy subclass,
with bean-definition overriding enabled, replaces it outright.

**Decision:** stay on the released jar with that single contained override.

**Tripwire:** the moment a **second** upstream override is required, we fork
ContainerProxy. To make that switch cheap, the fork is checked out and buildable from
spine #0 onward.

**Also:** lazy dispatcher creation is a small, genuinely useful upstream change. Offer it
to Open Analytics as a PR rather than carrying it forever.

**Rejected:** forking immediately. It buys freedom we have not yet shown we need and
costs a permanent merge tax against an actively maintained upstream.

---

## ADR-0002 — Product name is Skald; the codebase keeps the ShinyProxy name

**Date:** 2026-09-15 · **Status:** accepted

Apache 2.0 §6 grants no trademark rights: it lets us fork and ship the code, not call the
result "ShinyProxy". "Shiny" is separately Posit's mark. **"ShinyProxy+" is the worst of
the options** — it reads as an official Open Analytics edition, implying an endorsement
that does not exist, while also carrying Posit's mark.

Practically, this only bites on **distribution**. A fork that never leaves your own
infrastructure is not use in commerce. But the cost of choosing a name now is near zero,
and the cost after docs, a CLI binary, image names and URLs exist is real.

**Decision — split by audience:**

- **Keep the ShinyProxy name** in Java packages (`eu.openanalytics.shinyproxy`), the repo
  name, upstream file headers, `LICENSE` and `NOTICE`. The reason is engineering as much
  as legal: renaming packages turns every upstream merge into a conflict. Apache 2.0
  requires *marking* modified files, not renaming them.
- **Use "Skald"** for everything user-facing: UI title and branding, CLI binary, docs,
  published image and artifact names, API documentation.
- **Describe the lineage honestly** — "built on ShinyProxy", "hosts Shiny apps". That is
  nominative use and is explicitly fine.

Skald: the Norse court poet, whose job was to publish and perform others' work. Short,
typeable, and `skald deploy ./myapp` reads well.

**Not verified:** whether "Skald" is free of conflicting marks in this space. Nothing
blocks internal use now; do a proper search before any public release.

---

## ADR-0003 — No rsconnect / Connect API compatibility

**Date:** 2026-09-15 · **Status:** accepted (inherited from the handoff)

Implementing Posit Connect's publishing API would make adoption dramatically easier and
is exactly why it is risky. Pending legal review, we design our own publishing API and
our own bundle format. This extends to data artifacts: we do **not** implement Connect's
pins board API (spine #8).

Do not copy code, UI assets, or documentation text from Posit Connect.

---

## ADR-0004 — Docker single-host backend for v1; Kubernetes deferred

**Date:** 2026-09-15 · **Status:** accepted

The build pipeline is far cheaper on Docker (BuildKit directly) than on Kubernetes
(Kaniko/BuildKit jobs, PVCs, RBAC), and the dev loop is faster.

**Decision:** target Docker single-host for v1. But keep the **storage and build
interfaces backend-agnostic** from the start, so Kubernetes is an added implementation
rather than a rewrite. ContainerProxy already supports Kubernetes for the runtime side —
it is the *build* and *storage* sides we must not paint into a corner.

---

## ADR-0005 — CLI in Python

**Date:** 2026-09-15 · **Status:** accepted

The audience is R and Python data scientists. A Go binary is nicer to distribute, but
`pip install` is already in the Python half of that audience's muscle memory, and the
CLI is thin glue over an HTTP API — not a place where Go's strengths pay off.

**Decision:** Python. An R publishing package is wanted eventually but is not v1; the
HTTP API is the real contract, and both wrap it.

---

## ADR-0006 — Email delivery of scheduled reports deferred past v1

**Date:** 2026-09-15 · **Status:** accepted

Spine #6 is materially larger if "the report is delivered to your inbox" is in scope:
SMTP config, per-user addresses, bounce handling, rendering for mail clients, and the
question of whether the mail carries the output or a link past the ACL.

**Decision:** v1 re-renders on schedule and shows the latest output in the UI. Email is
its own track later. Revisit if a user says the UI is not where they read reports.

---

## ADR-0007 — S3-compatible object storage (MinIO) from the start

**Date:** 2026-09-15 · **Status:** accepted

Bundles, build logs, rendered output and data artifacts all need durable storage.
Filesystem-first is simpler today, but migrating live content later is real work and
touches the one thing we most want to get right once (ADR guiding principle: build the
irreversible things first).

**Decision:** MinIO in the dev stack, S3-compatible API everywhere, no filesystem
fallback path to maintain.

---

## ADR-0008 — Superseded content versions stay resolvable

**Date:** 2026-09-15 · **Status:** accepted

`Proxy` persists only `specId`, not the spec, and `ProxyService.java:536` re-resolves
`getSpec(proxy.getSpecId())` when stopping a proxy. If activating version N+1 makes
version N unresolvable, every container still running on N breaks at shutdown.

**Decision:** the spec provider resolves any version that still has live containers, not
only the active one. Rollback and activation never invalidate a spec id in use. Tested in
spine #1 with a container held alive across a version switch.
