# Upstream changes

Everything this fork does that is not purely additive, and why. Apache 2.0 §4(b) requires
modified upstream files to be marked as modified; this file is the index of those, plus of
the behavioural overrides that change upstream without editing it.

Two categories, kept separate on purpose:

- **Modified upstream files** — a diff against an Open Analytics source file. Each one is a
  permanent merge cost. There are none yet, and the aim is to keep it that way.
- **Behavioural overrides** — our own code, in our own package, that changes how an
  upstream component behaves at runtime. Cheaper than a diff, but still a coupling to
  upstream internals, so each one is recorded here with what it depends on.

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

**What this depends on upstream, and how it fails if upstream changes:**

| Assumption | If it breaks |
|---|---|
| A bean definition named `proxyDispatcherService` exists | Startup fails with an explicit message |
| It is defined by class, not by a `@Bean` factory method | Startup logs a loud WARN and the override is skipped |
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
