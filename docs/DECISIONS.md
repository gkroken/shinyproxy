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

**Amended 2026-09-15 — the override mechanism.** This ADR originally specified a
`@Bean(name="proxyDispatcherService")` with `spring.main.allow-bean-definition-overriding`
enabled. That flag is **global**: it disables bean-definition collision detection for every
bean in the application, permanently, to solve one bean. Instead we use a
`BeanDefinitionRegistryPostProcessor` that retargets that single definition's bean class
before any bean is instantiated. Same decision — one contained override, no fork — with a
blast radius of exactly one bean, and a loud startup failure if upstream ever renames or
re-registers it.

Note that `ProxyService.java:104` injects the **concrete class** `ProxyDispatcherService`,
not an interface, so the replacement must be a subclass. All of `ProxyDispatcherService`'s
fields are private, so the subclass takes the same constructor arguments, calls `super(...)`
and keeps its own reference to `DefaultProxyDispatcher`.

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

**Decision:** Python. The HTTP API is the real contract, and every client wraps it.

**Amended 2026-09-15 — the R package moves into v1 (spine #3).** The original "not v1"
underestimated one thing: the R package is the only place `renv` dependency discovery can
happen. A Python CLI cannot sensibly introspect an R project's lockfile, and a bundle
published without a dependency manifest deploys and then fails to run. Since R content is
the primary audience, that puts the R package on the critical path to content that actually
works, not on a nice-to-have list.

The R package calls the HTTP API **directly** (httr2/curl). It does not shell out to the
Python CLI — that would make every R user maintain a working Python install and a resolving
PATH, which is a miserable dependency chain for exactly the audience least equipped to
debug it. See ADR-0010.

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

**Correction, 2026-09-16 (spine #1 task 6). The decision stands; this paragraph's mechanism
was wrong.** Line 536 is in `startOrResumeProxy`, not a stop path. `ProxyService.stopProxy`
(line 346) never calls `getSpec` at all — it needs only
`proxyDispatcherService.getDispatcher(specId)`, which `LazyProxyDispatcherService` already
answers for any id. So containers do **not** break at shutdown when a version becomes
unresolvable. What actually depends on resolvability, verified by
`VersionResolvabilityTest`:

| Operation | Needs | Survives an unresolvable spec? |
|---|---|---|
| Stop (`:346`, `:376`) | `getDispatcher` only | **Yes** — demonstrated |
| Stop-all on shutdown (`:140`) | `getDispatcher` only | Yes |
| Pause support checks (`:397`, `:431`) | `getDispatcher` | Yes |
| Health check (`:455`, `:457`) | `getDispatcher` | Yes |
| **A user's own proxy list** (`:231`) | `getSpec` via `canAccess` | **No** — demonstrated: the proxy silently vanishes from its owner's list |
| Resume a paused proxy (`:536`) | `getSpec` | Latent only — see below |

Two caveats on that last row, because the first version of this correction over-claimed it.
`startOrResumeProxy` is reached on **start** as well as resume, but a start resolves the id
being started, which is normally the active version. And the **resume branch is unreachable
in 1.2.4**: `IContainerBackend.supportsPause()` defaults to `false`, no backend overrides
it, and `ProxySharingDispatcher.supportsPause()` explicitly returns `false`. So it is a
dependency in the code, not one that can fire today. App recovery does not resolve specs
either — it scans existing containers through the backend.

So the requirement stands on a narrower but entirely sufficient basis: the one reachable,
user-visible consequence is that **the owner stops seeing their own running app**. That is a
*silent* failure, which is worse to diagnose than the loud shutdown failure this ADR
originally imagined, not better.

**Consequence for spine #1 task 7.** `content_version` is `ON DELETE CASCADE` from
`content`, so deleting a content item takes its versions with it. The write path must refuse
to delete a content item or version that still has live proxies. *Done: `/admin/content`
refuses such a delete with 409.*

**Second correction, 2026-09-16 (task 8). "While their containers live" is a condition, and
the implementation was ignoring it.** `ContentSpecRepository.findSpec` resolved *any* version
unconditionally, which is broader than this ADR has ever said. The consequence was found by
driving the dev stack: with v2 active and nothing running on v1, `/app/<slug>--v1` returned
200 and the proxy API started a real container on v1. Activation and rollback therefore
controlled *discovery* but not *execution* — so publishing a fix never retired the version it
fixed, and any permitted user could keep starting a superseded version from a bookmarked URL
forever.

`findSpec` now resolves a version only when it is **active** or **still has live proxies**,
which is what this ADR always specified. The active version short-circuits before the proxy
store is consulted, so the hot path is unchanged. Three existing tests had encoded the old
behaviour and were rewritten; one of them asserted a superseded version stays resolvable
"while its containers live" with nothing running, which never matched its own stated intent.

**Decision:** the spec provider resolves any version that still has live containers, not
only the active one. Rollback and activation never invalidate a spec id in use. Tested in
spine #1 with a container held alive across a version switch.

---

## ADR-0009 — What Skald is, and who it is not for

**Date:** 2026-09-15 · **Status:** accepted

Skald is frequently described as "a free alternative to Posit Connect". That is true about
*cost* and misleading about *scope*, and the gap is large enough to strand someone
mid-migration if it is not written down.

**Skald v1 is for** a team whose content is mostly Shiny, Quarto and Plumber, that is
comfortable publishing from a CLI or an R console, that does not depend on emailed reports,
and for whom licence cost is the binding constraint. For that team the trade is strong:
no per-seat maths, self-hosted, no vendor lock-in, and mature inherited auth (LDAP, OIDC,
SAML, Kerberos) and container orchestration rather than newly written equivalents.

**Skald v1 is not a drop-in Connect replacement.** Named honestly, what a migrating user
loses on day one:

| Connect habit | Skald v1 |
|---|---|
| Click Publish in the IDE | `skald deploy` / `skald::deploy()` (ADR-0010) |
| Report arrives by email | Scheduled re-render, viewed in the UI (ADR-0006) |
| `pins::board_connect()` in existing code | Rewrite — pins compatibility is refused (ADR-0003) |
| Streamlit / Dash / Jupyter / Bokeh | Not in v1 — depth over breadth |
| Off-host execution on Kubernetes | Single-host Docker (ADR-0004) |

The two that most often decide whether a team *can* move are email delivery and the
absence of an `rsconnect`-compatible path — the latter meaning there is no gradual
migration, only a cutover plus retraining.

**Decision:** describe Skald as a Connect *alternative for a stated profile*, never as a
Connect replacement, in the README, the docs and any public material. Revisit this ADR
when email delivery (ADR-0006) and the dependency/lockfile story ship, which are the two
changes that would most move it toward genuine replacement.

---

## ADR-0010 — Publishing clients: a CLI and an R package, and no IDE integration

**Date:** 2026-09-15 · **Status:** accepted

"Easy to publish" is a requirement. "Press the Publish button in RStudio" is one
implementation of it, and the most expensive one available.

RStudio's native publish icon is wired to the `rsconnect` package, which speaks Connect's
API — foreclosed by ADR-0003. The next option, an RStudio Addin shipped as an R package,
carries no such problem and gives a real button, but it is an additional client with a
Shiny gadget UI, and it covers only RStudio: Positron and VS Code are a separate extension
in a separate language.

**Decision:** v1 ships **two clients over one HTTP API** and no IDE integration:

- `skald` — the Python CLI (ADR-0005), for Python content and for anyone who prefers a
  terminal.
- the `skald` R package — `skald::deploy()`, calling the API directly, and owning `renv`
  dependency discovery and manifest generation. Not a thin wrapper.

**Consequence for spine #3's API design.** With no picker dialog to serve, the API does not
need group-listing or slug pre-validation endpoints; ordinary validation with clear errors
on write is sufficient. One requirement does survive and is *stronger* for a CLI than it
would be for a GUI: **build progress and logs must be streamable**, so that `skald deploy`
does not sit silent for minutes. Spine #2 already writes build logs to object storage;
both clients tail them.

**Rejected:** an RStudio Addin and a VS Code/Positron extension in v1. Revisit if the CLI
and R package prove to be the adoption barrier — which is a thing to measure, not assume.

---

## ADR-0011 — Content identity and content address are separate

**Date:** 2026-09-16 · **Status:** accepted · **Amends:** WORKPLAN-REGISTRY decision 4, ADR-0008

Spine #1 derived the ContainerProxy spec id from a publisher-chosen slug: `<slug>--v<n>`.
A review of the finished track found that wrong in two independent ways, and the second
one only became visible because the first was being fixed.

**It made the spec id reusable.** `content_version` is `ON DELETE CASCADE`, and version
numbers were allocated per content row, so deleting content and re-creating it under the
same slug produced `<slug>--v1` again. ContainerProxy's `ProxyAccessControlService`
memoises authorization per `(sessionId, specId)` with no invalidation path, so the new
content inherited the old content's cached decisions. Reproduced on the dev stack: a user
with no ACL entry on the new content opened it and started a container from a warm session,
while a fresh session was correctly refused. The inverse also reproduced — a cached deny
locking out someone the new content did grant.

**It made the URL immutable.** `Proxy` persists only the spec id and ContainerProxy
re-resolves it, so renaming a slug would have orphaned every running container — the
ADR-0008 failure, self-inflicted. A publisher-settable URL is a requirement, and it is
incompatible with deriving a durable identifier from it.

**Decision.**

```
ProxySpec.id      c<content.id as 32 hex>--v<n>    opaque, immutable, never reused
content_path      publisher-settable, renameable, its own rules
```

`--v<n>` and its reasoning are unchanged; only what precedes it is. At most 45 characters,
inside the 63-character Kubernetes label limit.

This also removes review finding F4 by construction rather than by a check: the write path
used to compare a publisher's slug against configured YAML spec ids and compared only the
bare slug, so publishing `probe` produced `probe--v1` and captured an admin's configured
`probe--v1`. The namespaces are now disjoint.

**It does not fix the authorization cache**, which remains ADR-0001's fork question for
spine #4. It removes the id-reuse path into it.

**Path rules.**

1. All content under one prefix, `/c/<path>`. Not root-with-a-denylist, where a future
   platform route would silently steal a published URL.
2. At most 3 segments, each slug-shaped. A path may not be a strict prefix of another:
   content owns its whole subtree, so that case is undecidable at request time and is
   refused at publish time.
3. A rename retires the old path, which is kept forever and redirects (301). Deleted
   content's paths stay reserved and answer **410 Gone** — never 404, and never a redirect
   to whoever takes the name next, which would be this ADR's own bug at the URL layer. The
   history row must survive its content row, so the foreign key is `ON DELETE SET NULL` and
   **not** a cascade; a cascade would delete the reservation along with the content and the
   path would quietly become available again.

   **The redirect carries the sub-path, and a retired path therefore reserves its whole
   subtree** (added when commit C implemented this; the original wording said only that the
   path redirects). `/c/old/chapter2.html` must land on `/c/new/chapter2.html`, not on
   `/c/new/` — a page of a Quarto site or a route inside a Shiny app is exactly the kind of
   link people paste, and dropping the tail turns "your link still works" into "your link
   goes to the front page". That is only possible if nobody else can claim `old/chapter2`
   in the meantime, so the reservation covers the subtree, not just the key. A review of
   commit B reported the subtree reservation as a defect ("a rename burns a whole branch of
   the namespace"); it is the mechanism, and the report was withdrawn.
4. ASCII only, matched case-insensitively with the publisher's capitalisation preserved.
   Uniqueness is enforced on a normalised key across live paths *and* history. The
   normalisation is pinned to ASCII in the application and the column is `COLLATE "C"`,
   because `lower()` is collation-dependent — under a Turkish collation `'I'` lower-cases to
   a dotless `'ı'` — so a `lower(path)` index would mean different things on different
   installations.
5. Unauthenticated requests redirect to login preserving the destination, so a shared link
   works after signing in. Authenticated but not permitted returns **404, not 403**: it is
   non-leaking and consistent with the index, which already hides content a user may not
   see. Path resolution ends in the same `canAccess` the `/app` route uses.

   **Neither half is free, and commit C found out by measuring rather than by reading.**
   Spring's saved request does not restore a `/c/` destination: `UISecurityConfig` installs a
   redirect strategy that only keeps a destination `AppRequestInfo.fromURI` can parse, which
   means `/app*` and nothing else (upstream #30648, #28624). Verified on the dev stack — a
   signed-out visit to `/admin` or `/c/...` lands on the index after signing in, while
   `/app/hello` does not. `ContentController` therefore sets the same session attribute
   upstream's own handler sets, `AUTH_SUCCESS_URL_SESSION_ATTR`, so the open-redirect check in
   `AuthController` stays the one guarding it and no upstream file is modified.

   And the refusal status has to be set explicitly. Forwarding to `/error` with
   `ERROR_STATUS_CODE` set — what upstream's app controllers do — does **not** change the
   response status: measured at 404 for a wildcard `Accept` and **200** for `text/html`, so a
   browser was being shown "not found" with a success status. Upstream is not bitten because
   its app routes are refused by a security matcher before the controller runs. 410 cannot go
   through `/error` at all: `ErrorController` understands 400, 401, 403, 404 and 405 and falls
   through to a 500 for anything else.

**Deferred, not decided: whether a reserved path can ever be reclaimed.** "Never
reassignable" is the v1 default, not a principle, and it should not be written into this
ADR as one. The case it blocks is not typos — those get renamed, and the old path
redirects — but "published it, it was wrong, deleted it, want to republish under the same
name", which is common on a self-service platform. Going from never to sometimes is
additive, so living with the strict default now costs nothing later. When it lands (spine
#3/#4): the previous owner reclaims their own retired path without an admin, anyone else
needs one, both audited. The gate exists for inheriting *someone else's* audience — an
`all_authenticated` page at the finance team's retired report URL, which every stale
bookmark then lands on — not for reusing your own name.

**Note for whoever builds that: releasing a path does not re-open the cache hole, and it
needs no cache-invalidation step.** That hole was spec-id reuse. Ids are now UUID-derived,
so content at a reclaimed path has a different id and a different cache key, and nothing
caches on the path at all. A mechanism built for a problem that no longer exists is one
nobody maintains correctly.
