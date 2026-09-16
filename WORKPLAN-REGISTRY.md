# WORKPLAN — Spine #1: Content registry + runtime specs

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

Model: **Opus 5** throughout. This is the irreversible track — schema, URL/spec-id shape,
ACL projection and the one upstream override all ship once and are expensive to change
after content exists.

## Problem

Publishing without an admin editing `application.yml` means content must become startable
**between restarts**. ContainerProxy gives that away for free on the read path — but not
on the start path.

- Free: `ProxyService.getUserSpecs()` calls `baseSpecProvider.getSpecs()` on **every
  request** (`ProxyService.java:172`), so a DB-backed `IProxySpecProvider` is dynamic with
  no cache to invalidate. Authorization is likewise entirely spec-driven, so DB ACLs need
  **zero** upstream change.
- Blocked: `ProxyDispatcherService.init()` is `@PostConstruct` and populates its
  `dispatchers` map once, at startup. `getDispatcher(specId)` returns `null` for anything
  added later, and `ProxyService` calls it at **14 sites** (140, 376, 397, 414, 431, 455,
  457, 494, 508, 544, 547, 565, 594, 631 — `docs/ARCHITECTURE.md` says 12; the count is
  14, verified against the v1.2.4 source). A DB spec provider on its own NPEs the first
  time anyone opens runtime-added content.

That single blocker is what ADR-0001's "don't fork ContainerProxy" bet rests on, so it is
the first commit and it is proven by a test before any schema work happens.

Three further constraints, all verified, shape the rest:

- `Proxy` persists only `specId`, so superseded versions must stay resolvable or rollback
  breaks containers that are still running (ADR-0008). **Corrected in task 6:** this said
  `ProxyService.java:536` re-resolves the spec when *stopping* a proxy. It does not. Line
  536 is `startOrResumeProxy`; `stopProxy` (`:346`) needs only `getDispatcher(specId)`. The one
  reachable dependant is **`getUserProxies` (`:231`, through `canAccess`)**, so losing
  resolvability is a *silent* failure — the owner stops seeing their own running app — not a
  loud one at shutdown.
- `ContainerProxyApplication` excludes `DataSourceAutoConfiguration`
  (`ContainerProxyApplication.java:93`), so `spring.datasource.*` is inert until we define
  a `DataSource` bean ourselves.
- `ProxyService.java:104` injects the **concrete class** `ProxyDispatcherService` by type
  — not an interface. Whatever we substitute must be a subclass of it.

## Decisions (LOCKED)

**1. The override is installed by a `BeanDefinitionRegistryPostProcessor`, not by
`@Bean` + `spring.main.allow-bean-definition-overriding`.**

ADR-0001 sketched `@Bean(name="proxyDispatcherService")` with bean-definition overriding
enabled. That works, but it turns on **global** bean overriding: every accidental bean
name collision anywhere in the app silently becomes a last-one-wins replacement instead of
a startup failure. That is a large blast radius for one bean.

Upstream registers `ProxyDispatcherService` by component scan (`@Service`). A
`BeanDefinitionRegistryPostProcessor` runs before any bean is instantiated, so we retarget
that one definition's bean class to our subclass and leave the rest of the container's
safety intact. The constructor signature is unchanged, so Spring's constructor autowiring
resolves it identically.

This changes the **mechanism**, not ADR-0001's decision — still one contained override,
still no fork. **Signed off 2026-09-15; ADR-0001 amended to record it.**

One consequence: `ProxyDispatcherService`'s fields are all private, so the subclass cannot
reach `defaultProxyDispatcher` through `super`. It takes the same four constructor
arguments, calls `super(...)`, and keeps its own reference.

**2. An unknown spec id falls back to `DefaultProxyDispatcher`. A runtime spec that asks
for proxy sharing is a hard error, never a silent fallback.**

`ProxySharingDispatcher.supportSpec(spec)` is `minimumSeatsAvailable != null`. A sharing
dispatcher is not just an object: `init()` also creates a `ProxySharingScaler`, registers
two Spring singletons per spec, and adds the scaler to a private `closeables` list drained
by `@PreDestroy`. None of that can be conjured lazily in #1 without real surgery.

So: unknown id → `DefaultProxyDispatcher`, which is correct for every content type #1
ships. But if a DB row declares `minimumSeatsAvailable`, we **reject it at registration**
with an explicit message rather than quietly handing back a non-sharing dispatcher.
Silent degradation is exactly blocker 2 (`Micrometer` registers per-spec metrics at
startup only, and dynamic content gets none, with no error). One of those is enough.

**Signed off 2026-09-15.** The consequence is costed into spine #7 rather than left to be
discovered there: without a sharing dispatcher, `DefaultProxyDispatcher` gives one
container *per user session*, which is correct for a Shiny app and wrong for an API. #7
therefore has to build sharing dispatchers lazily — see the risks section.

**3. YAML specs are authoritative and read-only. Collisions are rejected on write, not
shadowed on read.**

The merged provider returns YAML specs first, DB specs second. A DB row whose slug equals
a YAML spec id is refused **when it is created**, with a clear error. Resolving the
collision at read time instead — by precedence — means a publisher can silently change
which app a URL points at, or silently fail to. Rejecting at write gives exactly one
error, at the moment someone can still act on it.

**4. The `ProxySpec` id is version-qualified; the URL is not.**

> **SUPERSEDED in part by ADR-0011 (2026-09-16).** The `--v<n>` suffix and every reason for
> it below still hold. What changed is the part before it: the id was `<slug>--v<n>`, derived
> from a publisher-chosen name, and a review of the finished track showed that made the id
> **reusable** — delete content, re-create it under the same slug, and the new content
> inherited the old one's cached authorization decisions, reproduced live. It also made the
> URL immutable, because renaming would have orphaned every running container. The id is now
> `c<content.id as 32 hex>--v<n>`, and the URL is a separate, renameable `content_path`. Read
> ADR-0011 before the text below, which describes the original scheme.

`Proxy` persists `specId` and re-resolves it at stop time, so a spec id must stay valid
for as long as any container references it. Therefore:

- `ProxySpec.id` = `<slug>--v<n>` — this string lands in the database and in running
  containers' runtime values, so **the format is irreversible**. Not `@`: traced where
  `specId` actually flows, and although Docker container names are built from the **proxy
  id**, not the spec id (`DockerEngineBackend.java:194`), and Kubernetes' `getManifestId`
  SHA1-hashes its input, the spec id does reach a Docker label value and the
  `SHINYPROXY_SPEC_ID` env var (`ProxySpecIdKey.java:28`). Docker label values are
  unrestricted; **Kubernetes label values are not** —
  `[a-zA-Z0-9]([-_.a-zA-Z0-9]*[a-zA-Z0-9])?`, max 63 characters. `@` would work today and
  break under ADR-0004's "do not paint Kubernetes into a corner". `--v<n>` costs nothing
  and is safe on both. Constrain slugs so `<slug>--v<n>` stays under 63 characters.
- `getSpecs()` returns only the **active** version of each content item. That is what
  drives the index listing and `getUserSpecs()`.
- `getSpec(id)` resolves **any** version that is still referenced by a live proxy, active
  or not. The two-method interface splits along exactly this line.
- The user-facing URL carries the slug; `content.active_version_id` says which version it
  means today. Rollback moves that pointer and invalidates nothing.

Superseded versions carry the **same ACL as the content item**, not a snapshot.

> **Correction, task 5.** The original sentence continued "— so a revoked ACL takes effect
> immediately even for someone holding a running old version." The first half holds: the
> projection reads the content item's current ACL for every version. The conclusion does
> not. `ProxyAccessControlService` memoises the decision per `(sessionId, specId)` with no
> invalidation path and an `expireAfterAccess` expiry, so a session that keeps using the app
> refreshes the cached answer indefinitely and the revocation never reaches it. Task 7 must
> decide this before it ships an ACL write path; `docs/UPSTREAM_CHANGES.md` section B has
> the detail. `V1__content_registry.sql` carried the same over-claim in a comment and was
> **corrected in place** while that was still free: the only database that had ever applied
> it was the dev stack. Verified the hard way first — rebuilding with the comment edited and
> the old schema in place fails the whole application at boot with
> `Migration checksum mismatch for migration version 1`, not a warning. The dev schema was
> dropped and Flyway reapplied v1 cleanly. **After spine #1 merges this stops being free**:
> correcting a migration then means `flyway repair` on every database that has applied it.

**5. Flyway owns the schema, and the `DataSource` is declared explicitly.**
`DataSourceAutoConfiguration` is excluded upstream, so `spring.datasource.*` does nothing
on its own. Our own `@Configuration` defines the `DataSource` and Flyway runs against it.

Out of scope for #1, deliberately: bundles, builds, the publishing API, the UI, and any
non-admin write path. #1 ends at "an admin can insert a row and the right users can run
it, with no restart".

## Design

New code under `eu.openanalytics.shinyproxy.publisher.*` — inside the `eu.openanalytics`
root that `@ComponentScan` covers (`ContainerProxyApplication.java:94`), so beans are
actually discovered.

```
publisher/
  dispatch/
    LazyProxyDispatcherService.java      extends ProxyDispatcherService; getDispatcher()
                                         falls back to DefaultProxyDispatcher
    DispatcherOverrideRegistrar.java     BeanDefinitionRegistryPostProcessor; retargets
                                         the `proxyDispatcherService` definition
  registry/
    DbSpecProvider.java                  IProxySpecProvider over content + content_version
    MergedSpecProvider.java              @Primary; YAML first, DB second
    SpecMapper.java                      content_version row -> ProxySpec
    AccessControlProjector.java          content_acl + visibility -> AccessControl
  db/
    DataSourceConfig.java                explicit DataSource + Flyway
  admin/
    ContentAdminController.java          admin-only insert/activate/rollback
```

The dispatcher fix itself is small:

```java
public class LazyProxyDispatcherService extends ProxyDispatcherService {
    @Override
    public IProxyDispatcher getDispatcher(String specId) {
        IProxyDispatcher dispatcher = super.getDispatcher(specId);
        return (dispatcher != null) ? dispatcher : defaultProxyDispatcher;
    }
}
```

`super.init()` still registers sharing dispatchers for YAML specs at startup, so nothing
about the existing configuration changes behaviour. Only the `null` case moves.

Schema (Flyway `V1__content_registry.sql`):

```
content          id, slug (unique), owner, type, visibility, active_version_id, timestamps
content_version  id, content_id, version, image, spec_json, created_at, created_by
content_acl      id, content_id, principal_type (user|group), principal, permission
content_env      id, content_id, key, value_encrypted, is_secret
audit_event      id, actor, action, subject_type, subject_id, detail_json, at
```

`content_env.value_encrypted` is *intended* to be encrypted at rest with a key from the
environment, never stored in the DB and never logged (CLAUDE.md security invariants).

> **Correction (review finding F7).** This said #1 creates "the table and the encryption
> path". #1 creates **only the table** — there is no encryption code anywhere under
> `publisher/`, and nothing writes to `content_env`. The task list never promised the
> encryption path, so nothing was skipped, but CLAUDE.md lists encrypt-at-rest as a
> per-phase invariant and a later track reading the original sentence would have assumed a
> path that does not exist. **Whoever first writes to `content_env` builds it.**

Visibility projects into a synthesized `AccessControl`:

| `content.visibility` | projection |
|---|---|
| `acl_only` | `users[]` + `groups[]` from `content_acl` |
| `all_authenticated` | expression that is true for any authenticated principal |
| `anonymous` | requires verifying how ContainerProxy evaluates an unauthenticated principal — **task 5 proves this with a deny test before it is relied on** |

## Tasks

- [x] **1. The dispatcher fix — first commit, before any schema work.**
      `LazyProxyDispatcherService` + `DispatcherOverrideRegistrar`. **ADR-0001 holds.**
      45/45 tests green (44 upstream + 1 new), and the new test was verified to fail with
      the override disabled — first on the installed-type guard, then, with the guards
      removed, on the real thing: `NullPointerException` at `ProxyService.java:494`
      (`getDispatcher(...).addRuntimeValuesBeforeSpel`) and again at `stopProxy`. Recorded
      in `docs/UPSTREAM_CHANGES.md`.

      Two things turned up that the plan did not predict:
      - `ShinyProxyInstance.TestConfiguration` — ContainerProxy's own test helper —
        substitutes `proxyDispatcherService` with a `@Primary @Bean`, a factory-method
        definition with no bean class. The registrar cannot retarget that, and replacing it
        would break upstream's proxy-sharing tests. It therefore steps aside with a loud
        WARN, and the new test boots its own context instead of using the helper. Booting
        through the helper would have tested the harness, not the product.
      - `ShinyProxySpecProvider.setSpecs()` updates `specs` but not `specsMap`, so
        `getSpec(id)` keeps returning null. Task 4's provider must keep both consistent.
- [x] **2 + 3. Explicit `DataSource` + Flyway, and `V1__content_registry.sql`.**
      Done as one commit rather than two: Flyway wiring cannot be verified without a
      migration to apply, so splitting them would have meant committing an unprovable step.
      The `DataSource` bean is `@ConditionalOnProperty("spring.datasource.url")`, so without
      a database the fork boots exactly as upstream does and Spring Boot's Flyway
      auto-configuration (conditional on a `DataSource` bean) stays dormant — which is what
      keeps upstream's suite untouched. New dependencies: `flyway-core` and
      `flyway-database-postgresql`, both Apache 2.0, both version-managed by the Spring Boot
      parent. The PostgreSQL driver, `spring-boot-starter-jdbc` and HikariCP were already on
      the classpath via ContainerProxy, and `JDBCCollector` builds its stats pool directly
      rather than as a bean, so there is no collision.

      Everything lives in a dedicated `skald` schema so that pointing Skald and
      ContainerProxy's usage-statistics collector at one database cannot collide.

      Verified against the live dev-stack PostgreSQL 16: Flyway created the history table and
      applied v1; all five tables exist; the slug-format and type CHECK constraints reject
      bad input; and a full content -> version -> activate -> ACL round-trip resolves to spec
      id `my-app--v1`, exercising the circular `active_version_id` foreign key.

      Trap worth recording: `license-maven-plugin` checks `.sql` under the **upstream**
      licenseSet, so a new migration fails the build demanding the Open Analytics header —
      false attribution on a file we wrote. `**/*.sql` is now excluded there, alongside the
      other config formats.
- [x] **4. `ContentSpecRepository` + `MergedSpecProvider`.** Registry content becomes a
      resolvable, listed spec with no restart. 51/51 tests green (45 + 6 new, on real
      PostgreSQL via Testcontainers — MIT, version-managed by the Spring Boot parent).

      **The design had to change, and the plan's version would not have worked.**
      `MergedSpecProvider` is a **subclass of `ShinyProxySpecProvider`**, installed by
      retargeting its bean definition, not a sibling `@Primary IProxySpecProvider` as the
      Design section assumed. ContainerProxy injects the *interface*, so a sibling would have
      satisfied it — but ShinyProxy's own `IndexController`, `BaseController` and `Thymeleaf`
      inject the **concrete** class, and `getMaxInstances()` builds its map by iterating
      `ShinyProxySpecProvider.getSpecs()`. Registry content would have been absent from that
      map, so `BaseController.validateMaxInstances` would unbox a null `Integer` and throw on
      every attempt to open published content. Subclassing gives interface and concrete
      injection points one merged view, with the diff against upstream still at zero.

      This is **not** a second ContainerProxy override and does not trip ADR-0001's tripwire:
      `ShinyProxySpecProvider` is a class in this repository. The override exists only to keep
      our diff against it at zero. `proxyDispatcherService` remains the sole ContainerProxy
      override.

      Second trap, same family: `ProxySpec.getSpecExtension()` returns null when absent, and
      `getShinyForceFullReload`, `getHideNavbarOnMainPageLink` and `getAlwaysShowSwitchInstance`
      all dereference it with no null check. Every registry spec is therefore built with an
      empty `ShinyProxySpecExtension` attached, so each value falls back to the provider
      default instead of NPE-ing on render. Covered by a test.

      Access control is **deliberately incomplete and fails closed**: until task 5 projects
      `content_acl` and the visibility modes, a registry spec is visible to its owner and
      nobody else. An unfinished ACL layer that defaults to "visible" is how content leaks.

      **Two further traps, both of which broke the live stack and neither documented upstream.**
      Found by running the dev stack rather than by reading — the unit tests were green while
      the index page was returning 500.
      - **A dynamic provider must return stable `ProxySpec` instances.** ShinyProxy keys
        view-model maps by `ProxySpec` *object*: `IndexController` builds them from one
        `getUserSpecs()` call while `BaseController.prepareMap` (line 191) calls it *again* and
        puts those objects in the model as `apps`, so the template looks the first up by the
        second. `ProxySpec.equals` delegates to `AccessControl`, which defines no `equals` and
        compares by identity — so rebuilding specs per call renders a null into a boolean
        ternary and the index 500s. `ContentSpecRepository` now memoizes, rebuilding only when
        a row's fingerprint changes.
      - **`ProxySharingDispatcher.supportSpec()` dereferences its extension unguarded too**
        (line 102), which made `LazyProxyDispatcherService.rejectIfProxySharing` — task 1's own
        code — NPE on any registry spec. Fixed with a null check. Task 1's test never caught it
        because it clones a YAML spec, which carries every extension.

      Sharing rejection (decision 2) is structural rather than a check: registry specs are
      built without a `ProxySharingSpecExtension`, and `ProxySharingDispatcher.supportSpec()`
      is `minimumSeatsAvailable != null`, so registry content cannot request sharing at all.
      Slug-collision rejection at write lands with the admin endpoint in task 7;
      `ContentSpecRepository.slugExists` is there for it, and `getSpecs()` additionally filters
      and loudly logs a collision that somehow reached the database rather than picking a
      winner silently.
- [x] **5. `AccessControlProjector` + the `maxInstancesCache` fix.** Replaces task 4's
      fail-closed owner-only placeholder. 79/79 tests green (53 + 26 new). Still needs its
      **Opus 5 review before merge** per the standing rule in `WORKPLAN.md`.

      `acl_only` and `all_authenticated` project as designed. Both `viewer` and `editor` ACL
      grants convey the right to open the content — they differ in what may be changed, which
      the write path enforces, not the projection.

      **The `anonymous` mapping does not work, and the Design table above is wrong about it.**
      The table said it "requires verifying how ContainerProxy evaluates an unauthenticated
      principal". It was verified, and the answer is that it cannot be granted at all:
      `AccessControlEvaluationService.checkAccess:56-61` rejects an
      `AnonymousAuthenticationToken` whenever the auth backend has authorization, **before**
      users, groups or the expression are consulted. No `AccessControl` we could synthesize
      grants an anonymous visitor. `anonymous` therefore projects to deny-everyone with a loud
      log, and task 7 must reject the value on write. A second problem outlives that one:
      every anonymous visitor is the principal `"anonymousUser"`, so on container-backed
      content they would share one container and one max-instances budget. Anonymous access
      belongs with spine #5's static documents, which have no container per viewer. Full
      reasoning in `docs/UPSTREAM_CHANGES.md` section A; the design and its risks are
      written up as a spine #5 item in `WORKPLAN.md`.

      **The projection's real hazard is the empty object, not the exception.** An
      `AccessControl` with no users, no groups and no expression means *unrestricted* —
      `hasNoAccessControl()` returns true and every authenticated principal is let through. So
      every branch of the projector emits an explicit positive or negative statement, and
      `AccessControlProjectorTest.noInputEverProducesAnUnrestrictedAccessControl` sweeps every
      visibility/owner combination to prove none of them produces one.

      **The ACL is part of the spec fingerprint.** `ContentSpecRepository` memoises ProxySpec
      instances (task 4's instance-stability requirement), so without this a revoked grant
      would keep being served from the memoised object. Mutation-tested: dropping the ACL from
      the fingerprint fails `aSupersededVersionUsesTheContentsCurrentAclNotASnapshot` and
      `revokingAnAclDeniesOnTheNextEvaluation`, among others.

      **Risk 4 was real and is fixed.** `MergedSpecProvider.getMaxInstances()` now recomputes
      the registry portion of the map on every call and overlays it on the parent's
      per-session cache, which is left alone because it is still correct for YAML specs.
      Confirmed by mutation: with the override reduced to `return super.getMaxInstances()`,
      content published mid-session has no entry and `BaseController.validateMaxInstances`
      would throw on unboxing null. The parent's `PROP_DEFAULT_MAX_INSTANCES` is private, so
      the constant is duplicated rather than the upstream file widened.

      **A second stale-view cache was found, and it is the more serious one.** Risk 4 named
      only `maxInstancesCache`. `ProxyAccessControlService` (ContainerProxy) memoises
      authorization decisions per `(sessionId, specId)` with **no invalidation path at all**,
      and because the expiry is `expireAfterAccess` rather than `expireAfterWrite`, a session
      that keeps using an app refreshes it indefinitely — so a revoked ACL never takes effect
      for that session, not merely "within 60 minutes". Fixing it means changing
      ContainerProxy, i.e. a second override and an ADR-0001 decision, and no ACL write path
      exists until task 7, so it is deliberately not fixed here.
      `ContentAccessControlTest.anAclRevocationDoesNotReachASessionThatIsAlreadyUsingTheApp`
      demonstrates it against a real `RequestContextHolder` rather than asserting it, and
      asserts the contrast — the same revocation *is* honoured for a session that has not yet
      asked, which is why a smoke test that logs in fresh cannot see it.
      **Task 7 must decide this before it ships a write path.** See
      `docs/UPSTREAM_CHANGES.md` section B.

      Every deny assertion was mutation-tested, recorded by the assertion each mutation trips
      rather than by a count — counts go stale the moment a later task adds a test, and a stale
      number presented as evidence is worse than none (review finding F6, which caught exactly
      that here). Making `acl_only` return an empty `AccessControl` trips
      `aUserWithNoGrantIsDenied` (`expected false, got true`) and is named by
      `noInputEverProducesAnUnrestrictedAccessControl`; making `anonymous` downgrade trips
      `anonymousVisibilityDeniesEveryoneRatherThanDowngrading`; dropping the ACL from the
      fingerprint trips `revokingAnAclDeniesOnTheNextEvaluation`. A deny test that has never
      been seen to fail is not evidence.
- [x] **6. Version resolvability (ADR-0008).** 81/81 tests green (79 + 2 new).

      **The capability was already there** — `ContentSpecRepository.findSpec` has resolved any
      version since task 4, because `SELECT_ONE` joins `content_version` on `content_id` rather
      than on `active_version_id`. What task 6 adds is the proof the plan asked for and a
      correction to why it matters. `VersionResolvabilityTest` holds a **real container** alive
      across an activate *and* a rollback and asserts it stays listed, stays reachable through
      the proxy, and then stops cleanly. Mutation-tested: pointing `SELECT_ONE` at
      `active_version_id` trips `aContainerSurvivesActivateAndRollbackAndStopsCleanly`.
      (This originally also claimed `MergedSpecProviderTest` fails with it. That was true when
      written and stale by the end of task 8, which rewrote that test — review finding F6.)

      **The recorded reason for ADR-0008 was wrong, in four documents.** All of them said
      `ProxyService.java:536` re-resolves `getSpec(proxy.getSpecId())` "when stopping a proxy".
      Line 536 is in `startOrResumeProxy`. `ProxyService.stopProxy` (`:346`) never calls
      `getSpec` at all — it needs only `getDispatcher(specId)`, which
      `LazyProxyDispatcherService` answers for any id. Verified both ways in
      `stopNeedsOnlyTheDispatcherButTheUsersProxyListNeedsTheSpec`, which deletes the content
      row out from under a running container and then stops it successfully.

      What actually depends on resolvability is **a user's own proxy list** (`:231`, which
      filters through `canAccess` and therefore resolves the spec). A first pass at this
      correction also listed *resume* (`:536`); that was itself an over-claim, and checking
      rather than reading settled it — `IContainerBackend.supportsPause()` defaults to false,
      no backend overrides it, and `ProxySharingDispatcher` returns false explicitly, so the
      resume branch is dead code in 1.2.4. App recovery does not resolve specs either.

      The narrower basis is still sufficient, and still makes the requirement *more*
      important than recorded rather than less: losing resolvability is a **silent** failure
      — the owner stops seeing their own running app — not a loud one at shutdown. Corrected table in ADR-0008; CLAUDE.md,
      WORKPLAN.md and the constraint above are amended to match.

      **Constraint this hands to task 7:** `content_version` is `ON DELETE CASCADE` from
      `content`, so deleting a content item takes its versions with it and orphans any live
      proxy. The write path must refuse to delete a content item or version that still has
      live proxies. *Done in task 7 — 409.*

      **Incomplete, and corrected in task 8.** This task tested one direction only: that
      superseded versions *stay* resolvable. It never tested that they are not
      **over**-resolvable, and they were — `findSpec` ignored ADR-0008's "while their
      containers live" condition entirely, so a retired version stayed startable from a
      bookmarked URL. Found by driving the dev stack, not by the tests written here.
- [x] **7. Admin-only content endpoints.** `/admin/content` — list, create, add version,
      activate (rollback is the same call with an older version), delete. 92/92 tests green
      (81 + 11 new). No publisher API, no UI.

      **Authorization is inherited, not written.** The path sits under `/admin`, which
      `UISecurityConfig` already gates on `userService.isAdmin(...)`, so the endpoint adds no
      security configuration at all — a second matcher would be a second place for an
      authorization rule to drift. Proven by mutation: moving the controller to `/xadmin/content`
      lets a non-admin list, create, version, activate and delete.

      **The version number is assigned by the server**, not chosen by the caller. Rollback names
      an existing version through the activate endpoint, so accepting one on write would buy
      nothing and cost a class of gap/conflict validation.

      **Refusals, each inherited from an earlier task:** slug shadowing a configured spec → 409
      (decision 3; a registry spec id is always `<slug>--v<n>`, so a non-null lookup on the bare
      slug can only be YAML); `visibility: anonymous` → 400 (task 5); delete with a live proxy →
      409 (task 6, tested with a real container); plus slug format, unknown type, missing owner,
      duplicate slug, and activating a version that does not exist.

      **CSRF.** ShinyProxy protects exactly one route — `WebSecurityConfig:136` restricts CSRF to
      `POST /login` — so a session-authenticated admin on a hostile page could otherwise be made
      to submit a form here. Every content type an HTML form can produce is refused with 415.
      That has **two independent guards**: `@RequestBody` binding (the only converter for these
      records is Jackson's, which declares JSON alone) and an explicit `consumes`. Mutation
      testing found that removing `consumes` alone does *not* break it — the first draft of the
      javadoc claimed `consumes` was the mechanism, which was wrong — and that removing both
      (binding with `@ModelAttribute`) lets a cross-site form create content, 201. The explicit
      declaration is kept because the implicit guard depends on converter configuration nothing
      in this repository owns. Re-declaring `http.csrf(...)` from the `ICustomSecurityConfig`
      seam was rejected: that matcher is global and our seam runs after upstream sets it.

      **Every mutation is audited** into `audit_event`, which had existed unused since task 2.
      The audit sits on the state change, not the endpoint: `setActiveVersion` records
      `content.activate`, so the activation implied by adding a version is recorded too. A test
      caught that gap — the first version audited per endpoint and silently lost it.

      **No ACL or visibility writes, deliberately** — signed off before implementation. Those
      are the two mutations that would make ContainerProxy's per-session authorization cache a
      live bug (`docs/UPSTREAM_CHANGES.md` section B). The operations this task does ship leave
      it dormant: a new spec id has never been cached, activate and rollback do not change who
      may see anything, and delete is safe because
      `ProxyAccessControlService.canAccess(auth, specId)` null-checks the resolved spec *before*
      consulting the cache. **Sharing lands in spine #4 and owns that decision**, which is where
      the ADR-0001 fork question finally has to be answered.
- [x] **8. Deny-case tests.** 94/94 green. The four the plan named were already covered by
      tasks 5 and 7, so this was run as a gap audit rather than as new authorship — and the
      audit is what earned its keep.

      | Named case | Covered by |
      |---|---|
      | Wrong group | `ContentAccessControlTest.aUserInTheWrongGroupIsDenied` |
      | Revoked ACL | `revokingAnAclDeniesOnTheNextEvaluation`, plus the cache characterisation test |
      | Anonymous against `acl_only` | `anonymousIsDeniedAclOnlyContent` |
      | Shadowing a YAML spec | `ContentAdminControllerTest.aSlugThatShadowsAConfiguredSpecIsRefused` (write) and `MergedSpecProviderTest.configuredSpecsAreAuthoritativeOverTheRegistry` (read) |

      **Gap 1, and the reason this task mattered: a retired version was still startable.**
      `findSpec` ignored ADR-0008's "while their containers live" condition and resolved *any*
      version. Found by driving the dev stack, not by reading: with v2 active and nothing
      running on v1, `/app/<slug>--v1` returned 200 and the proxy API started a real container.
      Activation controlled discovery but not execution, so publishing a fix never retired the
      version it fixed. `findSpec` now resolves a version only when it is active or still has
      live proxies; the active version short-circuits before the proxy store is consulted, so
      the hot path is unchanged. Three existing tests had encoded the old behaviour and were
      rewritten — including one whose message said "while its containers live" while running no
      containers, which never matched its own stated intent. Mutation-tested both ways.

      **Gap 2: decision 4's "current ACL, not a snapshot" had never been tested.** It is only
      testable with a container alive, since a superseded version with nothing running no longer
      resolves at all. `aSupersededVersionUsesTheContentsCurrentAclNotASnapshot` revokes a grant
      while a container runs on the superseded version and asserts the revocation applies —
      otherwise an old version would be a way to retain access after it is taken away.
      Mutation-tested by freezing the ACL in the spec fingerprint.

      **Known and deliberately not closed:** `audit_event` is documented as append-only but
      nothing enforces it — any code holding the `JdbcTemplate` can delete rows, and the tests
      do. Enforcement (a rule or a restricted role) belongs with the audit work in spine #9.
- [x] **9. `dev/smoke.sh` covers runtime-added content.** 31/31, up from 15/15.

      Alice creates content through `/admin/content` while the platform runs, adds a version,
      opens it, and bob is denied — **with no restart anywhere between the insert and the run**.
      It goes through the admin API rather than SQL on purpose: a smoke test that reaches around
      the API it is meant to exercise proves the database works, not the product.

      The new block also proves live what unit tests assert: a slug shadowing a YAML spec is
      refused (409), `visibility: anonymous` is refused (400), a form-encoded POST is refused
      (415), and activating v2 makes v1 stop being openable while v2 opens fine.

      **The new deny assertions were mutation-tested against live data**, the way the existing
      ones are. Granting bob through SQL flips his 403 to 200; rolling back to v1 flips the
      retired-version 403 to 200 and makes v2 return 403 instead. They track real state rather
      than constants.

## Risks and open questions

1. **Spine #7 wants proxy sharing for Plumber/FastAPI** ("reusing ContainerProxy's
   existing seat/pre-initialization mechanism") — which decision 2 explicitly refuses for
   runtime-added specs. Either those APIs stay YAML-defined, or #7 extends
   `LazyProxyDispatcherService` to build sharing dispatchers lazily. That would be an
   extension of the *same* override, so it does not trip ADR-0001's tripwire, but it is
   materially harder than the fallback and should be costed into #7 now rather than
   discovered there.
2. ~~The `<slug>@<version>` id format is irreversible.~~ **Settled in task 4.** The format
   is `<slug>--v<n>`: `@` is invalid in a Kubernetes label value and would have worked on
   Docker while quietly foreclosing ADR-0004. Slugs are capped at 50 characters so
   `<slug>--v<n>` stays inside the 63-character limit.
3. **`Micrometer` still registers per-spec metrics at startup only** (blocker 2). Every
   piece of runtime-added content in #1 will have no metrics, silently. That is accepted
   and deferred to #9, but it becomes true the moment this track lands.
4. ~~**`ShinyProxySpecProvider.maxInstancesCache` is per-session with a 60-minute TTL**~~
   **Fixed in task 5**, and it turned out to be the smaller half of the problem —
   `ProxyAccessControlService` caches authorization decisions the same way with no
   invalidation path, which task 7 must decide on. Original text:
   `ShinyProxySpecProvider.maxInstancesCache` is per-session with a 60-minute TTL, built
   on the comment "this never changes during the lifetime of a session"
   (`ShinyProxySpecProvider.java:99-105`). Publishing breaks that assumption: content created
   after a user's session started is absent from that session's cached map, so
   `getMaxInstancesForSpec` returns null for it. It did not bite in task 4 because the
   fallback path held, but the user-visible shape is "my new app doesn't appear until I log
   out" — which gets reported as flakiness, not as a cache. Pulled into task 5 rather than
   left to hardening.

## Done when

An app inserted through the admin endpoint appears for permitted users only, starts, serves
and stops, and is invisible to everyone else — **with no restart**. A container started on
version N keeps working and stops cleanly after N+1 is activated and after a rollback.
Upstream tests stay 44/44 and `dev/smoke.sh` stays green with its new checks.

**Met, then reviewed and reworked, 2026-09-16.** The Opus 5 review the standing rule
requires found seven issues, one of them a live authorization bypass. Post-rework: 119/119
tests, `dev/smoke.sh` 37/37 (re-runnable — verified twice in a row), `dev/acl-live.sh` 18/18
(was reported as 19/19 with three checks that could not fail).

| # | Finding | Outcome |
|---|---|---|
| F1 | Delete + re-create reused the spec id, so a warm session inherited cached access to different content. Reproduced live: a user with no ACL row opened the app and started a container | **Fixed** — ids are now UUID-derived (ADR-0011); paths are reserved, closing it a second time independently |
| F2 | `audit()` hand-rolled JSON; any control character rolled back the whole mutation as a 500 | **Fixed** — Jackson |
| F3 | check-then-insert races surfaced as 500, not the documented 409 | **Fixed** — row lock plus duplicate-key mapping; the delete race is narrowed, not eliminated, and says so |
| F4 | The YAML-collision check compared the bare slug, so `probe` could capture a configured `probe--v1` | **Closed by construction** — the namespaces are now disjoint |
| F5 | `dev/acl-live.sh` counted three assertions that could not fail | **Fixed** — the same anti-pattern this project had already been bitten by once |
| F6 | Mutation results recorded as test counts, stale as soon as a later task added tests | **Fixed** — they now name the assertion each mutation trips |
| F7 | The Design section claimed #1 ships the `content_env` encryption path; it ships only the table | **Corrected** |

The review also confirmed, independently, the things worth confirming: the ADR-0008 table is
right, the deny assertions are not vacuous, `hasLiveProxy`'s startup ordering holds, and the
CSRF defence covers all three form-capable content types.

**What spine #2 inherits, none of it in the original plan:**

1. **The ACL cache decision is now unavoidable.** Task 7 shipped without ACL or visibility
   writes precisely to keep it dormant. Spine #4 adds sharing, and a share button whose
   revocation does not reach a warm session is worse than no share button, so ADR-0001's fork
   question has to be answered before that ships. `docs/UPSTREAM_CHANGES.md` section B.
2. **Anonymous access is designed but not built** — `visibility: anonymous` is stored by the
   schema, refused on write, and denied on read. The route to it needs no ContainerProxy
   change; the design and its blast radius are a spine #5 item in `WORKPLAN.md`.
3. **Registry content gets no metrics** (blocker 2, `Micrometer` registers per-spec metrics at
   startup only). True from the moment this track landed; deferred to #9.
4. **`audit_event` is append-only by documentation only.** Nothing enforces it. #9.

## Next agenda item

Spine #2 (bundles + builds). Note for that track: extraction is the untrusted-input
boundary — traversal, symlink escape, size and entry-count caps — and gets a mandatory
Opus 5 security review regardless of who writes it.
