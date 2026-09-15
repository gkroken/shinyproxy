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

- `ProxyService.java:536` re-resolves `getSpec(proxy.getSpecId())` when **stopping** a
  proxy, and `Proxy` persists only `specId`. Superseded versions must stay resolvable or
  rollback breaks containers that are still running (ADR-0008).
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

Superseded versions carry the **same ACL as the content item**, not a snapshot — so a
revoked ACL takes effect immediately even for someone holding a running old version.

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

`content_env.value_encrypted` is encrypted at rest with a key from the environment, never
stored in the DB and never logged (CLAUDE.md security invariants). #1 creates the table
and the encryption path; the publishing surface that fills it arrives in #3.

Visibility projects into a synthesized `AccessControl`:

| `content.visibility` | projection |
|---|---|
| `acl_only` | `users[]` + `groups[]` from `content_acl` |
| `all_authenticated` | expression that is true for any authenticated principal |
| `anonymous` | requires verifying how ContainerProxy evaluates an unauthenticated principal — **task 5 proves this with a deny test before it is relied on** |

## Tasks

- [ ] **1. The dispatcher fix — first commit, before any schema work.**
      `LazyProxyDispatcherService` + `DispatcherOverrideRegistrar`. Proven by a test that
      boots a `ShinyProxyInstance`, adds a spec **after** startup through a test-only
      mutable spec provider, and starts it through `POST /api/proxy/<spec>` — asserting it
      reaches `Up` and serves. The test must fail without the override (verify by
      reverting it), or it is not evidence.
      **If this does not hold, stop and escalate: ADR-0001 changes shape.**
- [ ] 2. Explicit `DataSource` + Flyway wired into the dev stack's PostgreSQL.
- [ ] 3. `V1__content_registry.sql` — the five tables above.
- [ ] 4. `DbSpecProvider` + `MergedSpecProvider`, with the write-time collision rejection
      from decision 3 and the sharing-spec rejection from decision 2.
- [ ] 5. `AccessControlProjector` — ACL + visibility into a synthesized `AccessControl`,
      including the `anonymous` mapping, verified by deny tests rather than by reading.
- [ ] 6. Version resolvability (ADR-0008): `getSpec()` resolves superseded versions that
      still have live containers. Tested with a container held alive **across** an
      activate and a rollback, asserting it still stops cleanly.
- [ ] 7. Admin-only endpoint to insert/activate/roll back content. No publisher API, no UI.
- [ ] 8. Deny-case tests: wrong group, revoked ACL, anonymous against `acl_only`, and a
      publisher attempting to shadow a YAML spec.
- [ ] 9. Extend `dev/smoke.sh` with a runtime-added app: alice inserts it via the admin
      endpoint, alice runs it, bob is denied — **with no restart between insert and run**.
      Mutation-test the new deny assertions the way the existing ones now are.

## Risks and open questions

1. **Spine #7 wants proxy sharing for Plumber/FastAPI** ("reusing ContainerProxy's
   existing seat/pre-initialization mechanism") — which decision 2 explicitly refuses for
   runtime-added specs. Either those APIs stay YAML-defined, or #7 extends
   `LazyProxyDispatcherService` to build sharing dispatchers lazily. That would be an
   extension of the *same* override, so it does not trip ADR-0001's tripwire, but it is
   materially harder than the fallback and should be costed into #7 now rather than
   discovered there.
2. **The `<slug>@<version>` id format is irreversible** — it is persisted in `Proxy` rows
   and in live containers. Worth one deliberate look before task 4, not after.
3. **`Micrometer` still registers per-spec metrics at startup only** (blocker 2). Every
   piece of runtime-added content in #1 will have no metrics, silently. That is accepted
   and deferred to #9, but it becomes true the moment this track lands.

## Done when

An app inserted through the admin endpoint appears for permitted users only, starts, serves
and stops, and is invisible to everyone else — **with no restart**. A container started on
version N keeps working and stops cleanly after N+1 is activated and after a rollback.
Upstream tests stay 44/44 and `dev/smoke.sh` stays green with its new checks.

## Next agenda item

Spine #2 (bundles + builds). Note for that track: extraction is the untrusted-input
boundary — traversal, symlink escape, size and entry-count caps — and gets a mandatory
Opus 5 security review regardless of who writes it.
