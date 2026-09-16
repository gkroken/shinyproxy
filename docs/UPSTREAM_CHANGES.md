# Upstream changes

Everything this fork does that is not purely additive, and why. Apache 2.0 §4(b) requires
modified upstream files to be marked as modified; this file is the index of those, plus of
the behavioural overrides that change upstream without editing it.

Three categories, kept separate on purpose:

- **Modified upstream files** — a diff against an Open Analytics source file. Each one is a
  permanent merge cost. There are none yet, and the aim is to keep it that way.
- **Behavioural overrides** — our own code, in our own package, that changes how an
  upstream component behaves at runtime. Cheaper than a diff, but still a coupling to
  upstream internals, so each one is recorded here with what it depends on.
- **Upstream behaviour we depend on but have not changed** — places where an upstream
  decision constrains what Skald can do, and we designed around it rather than overriding
  it. Recorded because the reasoning is invisible in the code that accommodates it, and
  because each one is a candidate for the fork conversation if it ever has to change.

## Modified upstream files

None.

## Behavioural overrides

### 1. `proxyDispatcherService` → `LazyProxyDispatcherService`

**Since:** spine #1, 2026-09-15 · **Against:** ContainerProxy 1.2.4 · **ADR:** 0001

`eu.openanalytics.containerproxy.backend.dispatcher.ProxyDispatcherService.init()` is
`@PostConstruct`. It enumerates `getSpecs()` exactly once and registers a dispatcher per
spec, so `getDispatcher(specId)` returns `null` for any spec added after startup.
`ProxyService` calls it at 14 sites covering start, stop, pause, resume and health checks,
so a database-backed spec provider on its own would NPE the first time anyone opened
runtime-added content. Verified: without the override, starting a runtime-added spec throws
`NullPointerException` at `ProxyService.java:494`
(`getDispatcher(...).addRuntimeValuesBeforeSpel`), and stopping it throws again at the
`stopProxy` call.

**What we do:** `DispatcherOverrideRegistrar`, a `BeanDefinitionRegistryPostProcessor`,
retargets that one bean definition's class to `LazyProxyDispatcherService`, a subclass that
changes only the `null` branch of `getDispatcher`. Specs present at startup keep whatever
dispatcher upstream registered for them.

**Why not `spring.main.allow-bean-definition-overriding`:** that flag is global and
permanent — it disables bean-definition collision detection for every bean in the
application in order to replace one of them.

**Fails closed.** If the override cannot be installed, startup aborts. A deployment in that
state silently loses every piece of runtime-added content, which is the silent-degradation
failure this project refuses elsewhere. `skald.dispatcher.require-override=false` downgrades
it to a warning; `pom.xml` sets exactly that for the test run, because ContainerProxy's own
test helper legitimately substitutes this bean. That does not weaken the guarantee —
`LazyProxyDispatcherServiceTest` asserts the installed type directly.

**What this depends on upstream, and how it fails if upstream changes:**

| Assumption | If it breaks |
|---|---|
| A bean definition named `proxyDispatcherService` exists | Startup fails with an explicit message |
| It is defined by class, not by a `@Bean` factory method | **Startup fails**, unless `skald.dispatcher.require-override=false` |
| `ProxyDispatcherService` is non-final with a non-final `getDispatcher` | Compile error |
| Its constructor takes `(IProxySpecProvider, IProxySharingStoreFactory, ConfigurableListableBeanFactory, DefaultProxyDispatcher)` | Compile error |
| `ProxyService` injects the concrete class by type | Silent — covered by `LazyProxyDispatcherServiceTest` |

**Known limitation:** proxy sharing. Building a `ProxySharingDispatcher` also requires a
`ProxySharingScaler`, two per-spec Spring singletons, and `@PreDestroy` cleanup through a
private `closeables` list, none of which can be created from outside. A runtime-added spec
that requests sharing is therefore rejected with an explicit error rather than silently
downgraded. Spine #7 needs lazy sharing dispatchers for Plumber/FastAPI and must extend
this class; that is an extension of the same override, not a second one.

**Test:** `LazyProxyDispatcherServiceTest` boots its own application context — *not*
`ShinyProxyInstance`, whose `TestConfiguration` substitutes its own `proxyDispatcherService`
through a `@Primary @Bean` and would mask the thing under test — adds a spec after startup,
and starts and reaches a real container.

**Offer upstream:** lazy dispatcher creation is a small, generally useful change. Propose it
to Open Analytics as a PR rather than carrying this forever (ADR-0001).

### 2. `shinyProxySpecProvider` → `MergedSpecProvider`

**Since:** spine #1, 2026-09-15 · **Against:** ShinyProxy 3.2.4 (this repository) · **ADR:** 0001

**This is not a second ContainerProxy override.** ADR-0001's tripwire counts overrides of
*ContainerProxy*, the released jar we do not control, and `proxyDispatcherService` remains
the only one. `ShinyProxySpecProvider` is a class in this repository; the override exists
precisely so the diff against it stays at zero and upstream merges stay clean.

Registry content has to appear in the same spec list as YAML-configured content. The obvious
approach — a sibling `@Primary IProxySpecProvider` — does not work. ContainerProxy injects
the interface, but ShinyProxy's `IndexController`, `BaseController` and `Thymeleaf` inject the
**concrete** `ShinyProxySpecProvider`, and `getMaxInstances()` builds its map by iterating
that class's own `getSpecs()`. Registry content would be missing from the map, so
`BaseController.validateMaxInstances` unboxes a null `Integer` and throws when anyone opens
published content.

**What we do:** `SpecProviderOverrideRegistrar` retargets the `shinyProxySpecProvider` bean
definition to `MergedSpecProvider`, a subclass overriding only `getSpecs()` and `getSpec()`.
Swapping the class of the existing definition carries the `@ConfigurationProperties` binding,
the `@Primary` marker and the `@PostConstruct` callback over untouched. Conditional on
`spring.datasource.url`: with no database, the fork behaves exactly as upstream does.

**Related upstream sharp edge, worked around rather than changed:** `ProxySpec.getSpecExtension()`
returns null when the extension is absent, and `getShinyForceFullReload`,
`getHideNavbarOnMainPageLink` and `getAlwaysShowSwitchInstance` dereference it with no null
check. Registry specs are therefore always built with an empty `ShinyProxySpecExtension`
attached.

**Test:** `MergedSpecProviderTest`, against real PostgreSQL via Testcontainers — the schema
uses `jsonb`, `gen_random_uuid()`, CHECK constraints and a circular foreign key, none of which
an in-memory stand-in would exercise honestly.

## Upstream behaviour we depend on but have not changed

None of these is an override. They are upstream behaviours that Skald's design now rests on,
recorded because each is load-bearing and each is invisible in a passing test suite. A and B
are ContainerProxy, so changing either would mean a second ContainerProxy override and
therefore an ADR-0001 decision; C, D and E are in this repository, where the cost of changing
them is a permanent merge conflict instead. A and B were found in spine #1 task 5; C, D and E
in commit C, every one of them by measuring rather than by reading.

### A. Anonymous principals are rejected before access control is evaluated

`AccessControlEvaluationService.checkAccess` (lines 56-61) returns `false` for an
`AnonymousAuthenticationToken` whenever `authBackend.hasAuthorization()`, **before** users,
groups or the expression are consulted. Every backend except `none` returns true there.

**Consequence.** `content.visibility = 'anonymous'` cannot be delivered by projecting an
`AccessControl` — no value of that object grants an unauthenticated visitor. The route side
is not the obstacle: `UISecurityConfig` registers `/app/{specId}/**` with
`.access(canAccessOrHasExistingProxy)` *before* `WebSecurityConfig` adds
`anyRequest().fullyAuthenticated()`, so the spec ACL is already the only gate.

`AccessControlProjector` therefore denies `anonymous` outright and logs it, rather than
downgrading it to `all_authenticated`. `ContentAccessControlTest
.anonymousIsDeniedEvenByTheMostPermissiveProjection` pins the upstream behaviour; if it ever
starts failing, anonymous content became implementable through projection alone.

**A second problem, which changing the above would not solve.**
`AnonymousAuthenticationToken.getName()` is `"anonymousUser"` for *every* visitor. Proxies
are keyed by user id and `proxy.default-max-instances` is 1, so anonymous visitors to a
container-backed app would share one container — one visitor's Shiny session state visible
to the next — or be refused. Anonymous access is therefore natural for spine #5's static
documents, which are served from object storage with no container per viewer.

**There is a route to it that needs no ContainerProxy change**, so this section is a
constraint, not a dead end. An `ICustomSecurityConfig` filter can mint a per-session *guest*
identity that is not an `AnonymousAuthenticationToken`, which sidesteps the short-circuit
entirely; upstream's own `NoAuthenticationBackend.Filter`
(`auth/impl/NoAuthenticationBackend.java:91-134`) is the model for the per-session part. The
cost is blast radius — a synthetic authenticated principal satisfies
`anyRequest().fullyAuthenticated()` across the whole application — so it needs the guest
token scoped to anonymous-content routes and deny tests for everything else. Designed as a
spine #5 item in `WORKPLAN.md`.

### B. Authorization decisions are cached per session, with no way to invalidate them

`ProxyAccessControlService` (lines 55-65, 96-102) memoises `canAccess` per
`(sessionId, specId)`:

```java
// cache authorization results for (at least) 60 minutes, since this never changes during the lifetime of a session
authorizationCache = Caffeine.newBuilder()
    .scheduler(Scheduler.systemScheduler())
    .expireAfterAccess(60, TimeUnit.MINUTES)
    .build();
```

The field is private, there is no eviction method, and nothing in ContainerProxy listens for
session destruction. `ProxyService.getUserSpecs():174` (the index listing) and
`UISecurityConfig:73` (the `/app/{specId}/**` gate) both route through it.

**Consequence.** The comment is true of YAML ACLs, which are fixed at boot, and false for
published content. Because the expiry is `expireAfterAccess` and not `expireAfterWrite`,
every request refreshes the entry — so for a session that keeps using the app, **a revoked
ACL never takes effect at all**, not merely "within 60 minutes". Granting access is stale in
the same way, which presents as "the app someone shared with me doesn't appear until I log
out".

This is inherited, not introduced: an admin editing `application.yml` has always had the
same window. What changes with self-service publishing is that ACL changes become frequent
and user-driven rather than rare and admin-driven.

**Why it is not fixed here.** The fix is roughly ten lines inside `ProxyAccessControlService`
— make the cache invalidatable and call it from the ACL write path — but that is a second
ContainerProxy override, which ADR-0001 says means forking ContainerProxy. No ACL write path
exists until spine #1 task 7, so nothing can currently go stale. The decision belongs with
that task, taken against evidence rather than reasoning:
`ContentAccessControlTest.anAclRevocationDoesNotReachASessionThatIsAlreadyUsingTheApp`
demonstrates the staleness by driving a real `RequestContextHolder`, and asserts the
*contrast* — the same revocation is honoured immediately for a session that has not yet
asked, which is why a smoke test that logs in fresh cannot see the hole.

**Note for whoever writes the deny tests in task 8.** Unit tests do not hit this cache:
`canAccess` bypasses it entirely when there is no request context. A deny test written the
obvious way will pass while the hole is open.


### C. The post-login destination is only restored for `/app*` URLs

`UISecurityConfig` (this repository) replaces the success handler's redirect strategy with one
that stores a destination **only** when `AppRequestInfo.fromURI(url)` parses it — which means
`/app`, `/app_i`, `/app_direct` and `/app_direct_i`, and nothing else. The comment cites
upstream #30648 and #28624, so the narrowness is deliberate.

**Consequence.** A signed-out visitor following any other shared link lands on the index after
signing in. Measured on the dev stack rather than inferred: `/app/hello` comes back to
`/app/hello`, while `/admin` and `/c/...` both come back to `/`.

**What we do instead of widening it.** `ContentController` sets
`AUTH_SUCCESS_URL_SESSION_ATTR` itself before redirecting to `/login` — the same attribute
that handler sets, read by the same `AuthController`. The diff against `UISecurityConfig`
stays at zero, and the behaviour is pinned by
`ContentServingTest.aSignedOutVisitorIsSentToLoginAndTheDestinationIsRemembered` plus a live
`dev/smoke.sh` check that drives the whole Keycloak round trip.

**Do not describe `AuthController`'s check as an origin check.** An earlier version of this
section did. It is `sRedirectUrl.startsWith(<this application's base URL>)` — a string prefix
test, not a parsed-origin comparison, so `https://localhost:8080.example.com/` would satisfy it
against a base of `https://localhost:8080`. Nothing reaches it today: the only writers of that
attribute are upstream's success handler and `ContentController`, and ours builds the value
from `getRequestURL()`, which the servlet container composes — no part of it is chosen by the
caller. But it is not the guard it looks like, and anything that later stores a caller-supplied
value there has to validate it itself. Flagged by review.

### D. Forwarding to `/error` does not set the response status, and it cannot express 410

Upstream's app controllers set `RequestDispatcher.ERROR_STATUS_CODE` and forward to `/error`.
That selects the error *page*; it does not change the response status. It is invisible upstream
because `/app_direct/{specId}/**` is refused by a security matcher before its controller runs,
so the forward is never what produces the 403.

Measured before `ContentController` stopped relying on it: `/c/nope` answered **404** to a
wildcard `Accept` and **200** to `Accept: text/html` — a browser shown "not found" with a
success status.

`ErrorController`'s JSON branch also understands only 400, 401, 403, 404 and 405, falling
through to `ApiResponse.error("unrecoverable error")` with a **500**. So a deleted path
reported itself as a server fault. `ContentController` sets the status itself, reuses the HTML
error page only (which renders whatever status it is given), and writes the JSON shape for
everything else. Changing either would mean a diff against an upstream file for presentation,
which is not worth it.

### E. A spec extension built with its Lombok builder is not the same as a configured one

`@Builder` ignores field initialisers unless `@Builder.Default` is present. On
`ShinyProxySpecExtension` only `maxInstances` has it, so
`ShinyProxySpecExtension.builder().build()` leaves `customAppDetails` and `templateProperties`
**null**, where a YAML-configured spec gets empty collections.
`ShinyProxySpecProvider.getRuntimeValues` then evaluates `new CustomAppDetails(null)`, i.e.
`new ArrayList<>(null)`, and throws.

This broke every container start that goes through `AppController`, `AppDirectController` or
`/c/<path>` for registry content — not only the new route. It stayed hidden because the test
suite starts proxies through the API, which does not build runtime values this way.
`ContentSpecRepository` now sets both explicitly, and
`MergedSpecProviderTest.registrySpecExtensionsHaveNoNullCollectionsWhereAConfiguredSpecHasEmptyOnes`
sweeps every extension reflectively, so a field added upstream with an initialiser and no
`@Builder.Default` fails the build rather than a container start.
