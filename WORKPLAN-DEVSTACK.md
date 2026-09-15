# WORKPLAN — Spine #0: Dev stack + orientation

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

Model: **Sonnet 5** for the wiring, **Opus 5** for `docs/ARCHITECTURE.md` and the
license-plugin change.

## Problem

Nothing about this fork is runnable on the dev machine yet. There is no local JDK or
Maven; there is no config file (upstream `.gitignore` ignores `/application.yml`); there
is no identity provider to test group-based access against; and there is nowhere to put
bundles, build logs or rendered output.

Every later track needs all of that. Spine #1's acceptance criterion — "appears for
permitted users only" — is untestable without two real users in two different groups
coming from a real IdP.

## Decisions (LOCKED)

**1. The platform runs in a container, with the Docker socket mounted.**
There is no JDK on the host, so running the jar directly is not an option. ShinyProxy's
Docker backend needs the daemon. The socket is mounted into the **platform** container
only — never into content or build containers, which is the security invariant that
actually matters (CLAUDE.md).

**2. `proxy.docker.internal-networking: true` on a dedicated `skald-dev` network.**
Verified in `AbstractContainerBackend.java:119` / `DockerEngineBackend.java:111`. With
the platform on the same Docker network as the apps it starts, it reaches them by
container IP on the container's own port. App containers publish nothing to the host.
The alternative — `target-url` plus published port ranges — leaks a port per running app
onto the host and does not survive the move to a remote daemon.

**3. Host ports avoid what is already running.** This machine already has PostgreSQL on
5432 (another project) and something on 8000. The stack uses **8080** platform,
**8081** Keycloak, **9000/9001** MinIO, **5000** registry, **55432** PostgreSQL.
8080 is fixed and does not move between sessions.

**4. New code lives under `eu.openanalytics.shinyproxy.publisher`.**
Not a vanity root package: `ContainerProxyApplication` declares
`@ComponentScan("eu.openanalytics")` (line 94), so beans outside that root are simply not
discovered. Our copyright is asserted by the license header, not the package name.

**5. Two license sets, not one.** Upstream's `LICENSE_HEADER` asserts Open Analytics
copyright and `license-maven-plugin` runs with `strictCheck` at `package`. Applying it to
code we wrote is false attribution; deleting the check loses the upstream guarantee. Two
`licenseSet` blocks keep both true.

Out of scope: TLS anywhere, Kubernetes, and any actual publishing. This track ends at
"the stack is up and you are logged in".

## Design

```
docker-compose.dev.yml  (network: skald-dev)
  ├─ skald        dev/Dockerfile ← target/*-exec.jar   :8080   /var/run/docker.sock
  ├─ keycloak     quay.io/keycloak/keycloak:26.0       :8081   --import-realm
  ├─ postgres     postgres:16                          :55432  (skald/skald/skald)
  ├─ minio        minio/minio                          :9000 console :9001
  ├─ minio-init   minio/mc   creates bucket skald-bundles, then exits
  └─ registry     registry:2                           :5000
```

Keycloak realm `skald` (`dev/keycloak/skald-realm.json`), imported on boot:
- client `skald`, confidential, standard flow, redirect `http://localhost:8080/*`
- groups `publishers` and `viewers`
- users `alice` (publishers) and `bob` (viewers), passwords set, non-temporary
- an `oidc-group-membership-mapper` emitting a flat `groups` claim, because
  `proxy.openid.roles-claim: groups` is what reads it

`dev/application-dev.yml` is mounted to `/opt/skald/application.yml` — a distinct name
from the gitignored `/application.yml`, so the dev config is version-controlled while a
personal override stays ignored.

## Tasks

- [x] 1. `Makefile` — `build`, `test`, `dev`, `down`, `logs`, `clean` over the Docker
      Maven image. `HOME=/m2home` is required or the image dies on `mkdir /root`.
- [x] 2. `dev/Dockerfile` — `eclipse-temurin:21-jre`, non-root, copies `target/*-exec.jar`.
- [x] 3. `docker-compose.dev.yml` — the six services above.
- [x] 4. `dev/application-dev.yml` — OIDC against Keycloak, Docker backend with internal
      networking, one demo spec, admin group.
- [x] 5. `dev/keycloak/skald-realm.json` — realm, client, 2 groups, 2 users, groups mapper.
- [x] 6. `pom.xml` — second `licenseSet` + `dev/LICENSE_HEADER_SKALD`.
- [x] 7. `.gitignore` — `/.m2/`, `/.m2home/`, `/dev/data/`.
- [x] 8. `docs/ARCHITECTURE.md` — request flow, extension points, blockers.
- [x] 9. Verify: `dev/smoke.sh` drives the real OIDC flow for both users and asserts
      allow **and** deny — **15/15 green**, including starting the demo container and
      serving it through the proxy. (Corrected at the start of spine #1: this was 14/15
      with one check that could not fail. See finding 5.)
- [x] 10. Record findings in memory; commit per unit of work.

## Findings

Five things cost real time and are worth not rediscovering:

1. **Maven cache must live outside the repo.** `license-maven-plugin` runs with
   `<aggregate>true</aggregate>` and happily scans every downloaded `.pom` under the
   project directory. The cache is now `~/.cache/skald/m2`. Related: the cache dirs must
   exist and be owned by you before the container runs, or Docker creates them root-owned
   and Maven dies with `AccessDeniedException: /m2/org`.
2. **MinIO's Docker Hub images are gated** (`pull access denied for minio/minio`). Use
   `quay.io/minio/minio` and `quay.io/minio/mc`.
3. **Do not set `proxy.openid.userinfo-url` in this topology.** The access token is issued
   for `localhost:8081` (the browser's view of Keycloak); calling userinfo at
   `keycloak:8081` makes Keycloak see a different issuer and return 401, which surfaces
   only as a redirect to `/auth-error`. Every claim we need is in the ID token. The same
   trick is fine for token-url and jwks-url, which are not issuer-validated.
4. **`grep -q` inside a pipeline under `set -o pipefail` inverts the result.** grep exits
   on the first match, curl takes a SIGPIPE, and the pipeline reports failure — so every
   "user sees X" assertion read `no` and every "user does NOT see X" assertion passed for
   the wrong reason. The smoke script captures bodies into variables instead.
5. **The container-start section was wrong in two ways, found re-verifying at the start of
   spine #1.** This track was recorded as 15/15; it was actually **14/15**, and the 15th
   check could never fail. Both bugs are fixed and the fix is mutation-tested.
   - `DELETE /api/proxy/<id>` **is not mapped** — the server answers 405 with
     `Allow: POST,GET,HEAD,OPTIONS`. The stop verb is `PUT /api/proxy/<id>/status` with
     `{"status":"Stopping"}`. The old call silently did nothing *and its result was never
     asserted* (`ok "app 'hello' stopped"` was unconditional), so every run leaked a live
     container — the same "a check that cannot fail" class as finding 4.
   - Serving was fetched from `/app_direct/hello/`, which is **get-or-start** keyed on
     `(user, app, instance "_")` (`BaseController.java:149`). A proxy started through
     `POST /api/proxy/<spec>` carries no `SHINYPROXY_APP_INSTANCE` runtime value, so it
     never matches; `app_direct` then tries to start a **second** instance and trips
     `proxy.default-max-instances`, whose default is `"1"`
     (`ShinyProxySpecProvider.java:117`). The result is a deterministic 500 that reads
     like a container-networking fault and is not one. The script now fetches through
     `/api/route/<proxyId>/`, which is the mapping `ProxyMappingManager` actually serves —
     and is the same seam spine #7 builds on.

## Done when

One command brings the stack up, `alice` logs in through Keycloak with group claims and
starts the demo app, `bob` is correctly denied the restricted one, and `make test` is green.

## Next agenda item

Spine #1 (content registry + runtime specs), starting with the lazy-dispatcher fix.
Note for that track: `@SpringBootApplication(exclude = {… DataSourceAutoConfiguration.class …})`
(`ContainerProxyApplication.java:93`) means Spring Boot will **not** auto-configure a
`DataSource`. We define one explicitly; do not waste time debugging why `spring.datasource.*`
appears inert.
