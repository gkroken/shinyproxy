# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## What this repository is

A fork of [ShinyProxy](https://github.com/openanalytics/shinyproxy) (Apache 2.0, Open
Analytics NV) that adds a **self-service publishing layer**: upload a bundle or point at
a git repo, and the platform builds and deploys it — no admin editing `application.yml`.

Product name for new, user-facing surfaces: **Skald**. See `docs/DECISIONS.md` ADR-0002
for what keeps the ShinyProxy name and what does not, and why.

**Read `WORKPLAN.md` before starting a track.** It holds the spine (dependency-ordered
work items), the locked scope decisions, and the model assignment for each step.

## Build & Run

There is **no local JDK or Maven** on the dev machine. Build through Docker:

```bash
make build       # or `make dev` to build and bring the stack up
```

Produces `target/shinyproxy-<version>-exec.jar` (~152 MB, Spring Boot executable).

Two traps the Makefile already handles, which bite anyone running `docker run` by hand:
the Maven cache lives at `~/.cache/skald/m2` **outside the repo**, because
`license-maven-plugin` runs with `<aggregate>true</aggregate>` and will otherwise scan
every downloaded `.pom`; and the cache directories must exist and be owned by you before
the container starts, or Docker creates them root-owned and Maven dies with
`AccessDeniedException: /m2/org`. `HOME=/m2home` is also required — without it the image
fails on `mkdir /root`.

The dev stack (`docker-compose.dev.yml`: app + PostgreSQL + Keycloak + MinIO + registry)
comes up with `make dev`. `bash dev/smoke.sh` then drives the real OIDC flow for two users
in different groups and asserts both allow and deny — 15 checks, and the deny cases are
the ones that matter. Run it after any change to access control.

## Tests

```bash
make test        # 44 tests, all green as of 2026-09-15
```

Upstream's tests start real containers and then talk to them on published ports. CI runs
Maven **on the host**, so it never had to think about this; we run Maven in a container,
so `make test` adds `--network host` (making `localhost:<port>` the host's localhost) plus
the Docker socket and its group. It also pulls
`openanalytics/shinyproxy-integration-test-app` first. Without all of that, 13 of the 44
tests fail in ways that look like product bugs.

`make build` deliberately does **not** get Docker access — only `make test` needs it.

**Keep upstream's tests green at all times.** They are the regression net for the fork.

## Architecture: the one thing to understand first

ShinyProxy is **not** the engine. The Spring Boot main class is
`eu.openanalytics.containerproxy.ContainerProxyApplication` (see `pom.xml`), and the
engine lives in the separate **ContainerProxy** library (`eu.openanalytics.containerproxy`),
consumed as a released jar from `nexus.openanalytics.eu`. This repo is a *plugin layer*:
50 Java files against ContainerProxy's 248.

So: most of what we need to extend lives in a dependency, not in this repo.
`docs/ARCHITECTURE.md` maps every extension point with file paths and line numbers.

**The load-bearing seams** (all verified against ContainerProxy v1.2.4):

| Seam | Where | What it buys us |
|---|---|---|
| `IProxySpecProvider` | `spec/IProxySpecProvider.java` | Two methods. `ProxyService.getUserSpecs()` calls it **per request**, so a DB-backed provider is dynamic with no cache invalidation. |
| `AccessControl` on the spec | `service/AccessControlEvaluationService.java` | DB ACLs project into a synthesized `AccessControl{users,groups,expression}`. Zero upstream change. |
| `ICustomSecurityConfig` | `security/WebSecurityConfig.java:239` | Collected-bean seam. Our API routes and API-key filter plug in like `UISecurityConfig` does. |
| `ProxyMappingManager.dispatchAsync` | `util/ProxyMappingManager.java:232` | Public. Stable non-iframe URLs (`/content/<slug>/…`) without touching upstream. |

**The known blockers** (do not rediscover these):

1. `ProxyDispatcherService.init()` is `@PostConstruct` — it enumerates `getSpecs()` once
   at startup and registers per-spec singletons. `getDispatcher(specId)` returns `null`
   for anything added later, and `ProxyService` calls it at **12 sites**. A DB-backed
   spec provider alone will NPE on runtime-added content. Fixed in spine #1.
2. `Micrometer` (`stat/impl/Micrometer.java:134`) registers per-spec metrics at startup
   only. Dynamic content silently gets no metrics — degradation, not a crash.
3. `Proxy` persists only `specId`, not the spec. **Superseded content versions must stay
   resolvable while their containers live**, or rolling back breaks running apps.
   *Corrected in task 6:* this used to say `ProxyService.java:536` re-resolves the spec "at
   stop time". It does not — line 536 is `startOrResumeProxy`, and `stopProxy` needs only
   `getDispatcher(specId)`. The one reachable dependant is **a user's own proxy
   list** (`:231`, via `canAccess`) — so the failure is *silent*: the owner stops seeing
   their own running app. (`:536` also resolves the spec, but its resume branch is dead code
   in 1.2.4 — no backend supports pause.) Table in ADR-0008, proven by
   `VersionResolvabilityTest`.

## Working conventions

- **Stay modular.** New code goes in new packages (`eu.openanalytics.shinyproxy.publisher.*`).
  Touch upstream classes only when there is no extension point, keep the diff small, and
  record it in `docs/UPSTREAM_CHANGES.md`.
- **Flag every new dependency before adding it**, with its license. GPL/AGPL needs sign-off.
- For changes over ~30 lines or spanning multiple files, state the plan and wait for
  confirmation before writing code.
- Never reprint a whole file. Show only changed methods or a diff.
- **Commit frequently** — after each self-contained unit of work, not batched by phase.
  Message format: `<scope>: <what and why>` (e.g. `registry: lazy dispatcher lookup for
  runtime-added specs`).
- **Ask before** changing: authentication flows, the database schema after it ships,
  public API shapes, or anything security-sensitive.
- If something in `WORKPLAN.md` conflicts with what the code actually does, stop and
  report it rather than forcing the plan.

## Licensing — two rules that bite

1. **License headers are enforced at `package` phase** by `license-maven-plugin` with
   `strictCheck`. Upstream's `LICENSE_HEADER` reads `Copyright (C) 2016-<year> Open
   Analytics`. Putting that header on code we wrote is **false attribution**. Spine #0
   adds a second `licenseSet` so files under our own packages carry our copyright while
   upstream files keep theirs. Until that lands, build with `-Dlicense.skip=true` and
   do not paste the OA header into new files.
2. **Keep every upstream license header, `LICENSE`, and `NOTICE` intact**, and mark
   modified upstream files as modified — Apache 2.0 §4(b) requires it.

Do not copy code, UI assets, or documentation text from Posit Connect. Do not implement
rsconnect/Connect API compatibility without explicit sign-off (ADR-0003).

## Security invariants (every phase)

- Every bundle is **untrusted code**. Builds and content containers run unprivileged:
  no Docker socket, no host mounts, resource limits, network policy where available.
- Encrypt secrets at rest; key from environment/KMS, never in the DB. Never log them.
- API keys: shown once, stored hashed, revocable, last-use recorded.
- Validate slugs, manifest content, and **bundle paths** — no traversal on extraction.
- Every authorization decision goes through one service, and deny cases get tests.
- Strip client-supplied identity headers before injecting authenticated identity.
