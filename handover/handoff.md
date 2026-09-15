# Handoff: Self-Service Publishing Platform on a ShinyProxy Fork

## 1. Mission

We are building a free, self-hosted alternative to Posit Connect on top of a fork of
ShinyProxy. ShinyProxy already provides container orchestration, authentication
(LDAP, OIDC incl. Keycloak, SAML, Kerberos), user/group access rules, scaling and
monitoring. What it lacks is the **publishing and automation layer**:

1. Self-service publishing: a data scientist uploads a bundle or points at a git repo,
   and the platform builds and deploys it with no admin editing `application.yml`.
2. Publisher-managed access control: content owners share with users and groups themselves.
3. Static documents: rendered Quarto / R Markdown served behind the same auth.
4. Scheduled renders of Quarto / R Markdown, with run history and logs.
5. Stable APIs (Plumber, FastAPI) with API-key auth.
6. Data artifacts (`.rds` / `.RData` / pins-style datasets) served behind auth.
7. Versioning and rollback of every deployment.

Your job: implement this incrementally, phase by phase (Section 6), keeping the fork
mergeable with upstream wherever possible.

## 2. Ground rules for you (Claude Code)

- **Read before you write.** Complete Phase 0 before changing any code. Do not assume
  class names from this document are correct; verify them in the source.
- **Stay modular.** Put new code in new packages/modules (e.g. `...publisher.*`).
  Touch upstream classes only when there is no extension point, and keep those diffs
  small and documented in `docs/UPSTREAM_CHANGES.md`.
- **Small, reviewable steps.** One logical change per commit. Run the full test suite
  before each commit. Never leave the build broken.
- **Ask before** changing: authentication flows, the database schema after it ships,
  public API shapes, or anything security-sensitive.
- **Never** commit secrets, disable security checks to make tests pass, or mount the
  Docker socket into user content containers.
- **Keep docs current.** Update `docs/ARCHITECTURE.md` and `docs/DECISIONS.md`
  (lightweight ADRs) as you go.
- If something in this handoff conflicts with what you find in the code, stop and report
  it rather than forcing the plan.

## 3. Legal and licensing constraints

- ShinyProxy and ContainerProxy are Apache 2.0. Keep all upstream license headers and
  the `NOTICE`/`LICENSE` files. Mark modified files as modified where Apache 2.0 requires it.
- "ShinyProxy" is Open Analytics' name; "Posit", "Connect", "Shiny", "RStudio" are
  Posit's. **Do not use any of these in the product name, UI branding, package names,
  or artifact names.** Use the placeholder name `PROJECT_NAME` until the owner picks one.
  Descriptive phrases like "hosts Shiny apps" are fine.
- Do not copy code, UI assets, or documentation text from Posit Connect.
- **Do not implement rsconnect / Connect API compatibility** without explicit sign-off
  from the owner (pending legal review). Design our own publishing API.
- Check the license of every new dependency. Flag anything GPL/AGPL before adding it.

## 4. Architecture you need to learn first

ShinyProxy is a Java / Spring Boot application. Most of the engine lives in the
separate **ContainerProxy** library (`eu.openanalytics.containerproxy`), which ShinyProxy
depends on. Much of what we need to change or extend lives there, not in the
`shinyproxy` repo itself.

**Decision required in Phase 0:** either (a) also fork ContainerProxy and build it
locally, or (b) consume the released ContainerProxy artifact and only use its extension
points. Prefer (b); fall back to (a) only for changes that cannot be done otherwise.
Record the decision in `docs/DECISIONS.md`.

Things to locate and document (names are hints; verify them):

- **Proxy spec loading.** How app definitions (`proxy.specs` in `application.yml`) become
  runtime spec objects. Look for a spec provider abstraction (possibly
  `IProxySpecProvider` / a default implementation reading config). This is our most
  important extension point: we want a **database-backed spec provider** so content can
  be added/changed at runtime without restarting.
- **Access control.** How `access-groups`, `access-users` and `access-expression` are
  evaluated (user service / access-control evaluation service).
- **Authentication backends.** The `IAuthenticationBackend` implementations (LDAP,
  OpenID, SAML, Kerberos, etc.) and how groups/roles are extracted from each.
- **Container backends.** Docker, Docker Swarm, Kubernetes, ECS. How a proxy is started,
  stopped and routed to.
- **Routing.** The `/app/<id>` (iframe) and `/app_direct/<id>` paths, and how the reverse
  proxy forwards requests and websockets.
- **Container sharing / pre-initialization.** How shared containers and seats work;
  we will reuse this for APIs.
- **Persistence.** Redis-backed session and app persistence, and the usage-statistics
  database integration.
- **Templates / UI.** Thymeleaf templates, static assets, and how the app list page is
  rendered.
- **Config reload.** How the ShinyProxy Operator does zero-downtime config updates, and
  why a runtime spec provider avoids needing it for content changes.

Deliverable: `docs/ARCHITECTURE.md` with a request-flow diagram (Mermaid) and a list of
extension points with file paths.

## 5. Target design

```
               ┌───────────────────────────────────────────────┐
 Browser/CLI → │ Fork (Spring Boot)                             │
               │  ├─ existing: auth, proxying, container mgmt   │
               │  ├─ NEW Publisher API  (/__api__/v1/...)       │
               │  ├─ NEW Content registry (DB-backed specs)     │
               │  ├─ NEW Static content handler (auth'd)        │
               │  ├─ NEW Scheduler (cluster-safe)               │
               │  └─ NEW Publisher UI (content list, settings)  │
               └──────┬───────────────┬───────────────┬────────┘
                      │               │               │
                 PostgreSQL    Object store / PV   Image builder
                 (registry,    (bundles, rendered  (BuildKit / Kaniko
                  schedules,    outputs, data)      job) → registry
                  audit)
```

### Content model (initial)

- `content`: id (UUID), slug (unique, used in URL), title, description, type
  (`shiny_r`, `shiny_py`, `plumber`, `fastapi`, `streamlit`, `dash`, `quarto_static`,
  `rmarkdown_static`, `quarto_scheduled`, `rmarkdown_scheduled`, `data`), owner,
  created/updated timestamps, active_version_id, runtime settings (min/max seats,
  idle timeout, memory/CPU limits).
- `content_version`: id, content_id, bundle location, manifest (JSON), image reference,
  build status, build log location, created_by, created_at.
- `content_acl`: content_id, principal type (`user` | `group`), principal name,
  role (`viewer` | `collaborator` | `owner`). Plus a content-level visibility setting:
  `acl_only` | `all_authenticated` | `anonymous` (anonymous requires admin approval).
- `content_env`: content_id, key, encrypted value, is_secret.
- `schedule`: content_id, cron expression, timezone, parameters (JSON), enabled.
- `render_run`: id, content_id, version_id, trigger (`manual` | `schedule`), status,
  started/finished, output location, log location.
- `api_key`: id, user, hashed key, name, created, last_used, revoked.
- `audit_event`: who, what, target, when, details.

Use Flyway (or Liquibase) for migrations. PostgreSQL in production; Testcontainers in tests.

### Bundle format (our own)

A `.tar.gz` containing the source plus a `manifest.json` we define:
`type`, `entrypoint`, `r_version` / `python_version`, lockfile path (`renv.lock` or
`requirements.txt`), optional `quarto_version`, and optional default parameters.
Provide a JSON Schema in `schemas/manifest.schema.json` and validate on upload.

### Builds

- Base images per content type and language version, kept in `images/`.
- Build step: restore packages from the lockfile, copy the bundle, set the entrypoint.
  Use BuildKit (Docker backend) or Kaniko/BuildKit jobs (Kubernetes backend).
- Builds run **isolated from the platform** with resource limits and a timeout.
  Build logs are streamed to storage and viewable in the UI.
- Cache package layers aggressively (lockfile hash → cached layer).

## 6. Phases

Each phase ends with passing tests, updated docs, and a short summary for the owner.

### Phase 0: Orientation (no feature code)
- Build and run the fork locally with the Docker backend and a sample Shiny app.
- Stand up a local Keycloak (docker compose) and log in via OIDC with group claims.
- Write `docs/ARCHITECTURE.md` (Section 4) and the ContainerProxy fork decision.
- Add `docker-compose.dev.yml`: fork + PostgreSQL + Keycloak + MinIO + local registry.
- **Done when:** the owner can run one command and log in to a working dev stack.

### Phase 1: Content registry + runtime specs
- Add PostgreSQL, migrations, and the content model.
- Implement a DB-backed spec provider that merges with YAML-defined specs
  (YAML specs remain read-only and admin-owned).
- Content created/changed in the DB is available without restart.
- Access evaluation reads `content_acl` + visibility, using groups from the existing
  auth backends.
- **Done when:** an app inserted via an admin endpoint appears for permitted users
  only, and disappears for others, with no restart.

### Phase 2: Publishing
- Publisher API: create content, upload bundle, list versions, activate version,
  roll back, delete. Authenticate via session or API key.
- Image build pipeline (Section 5) with status and logs.
- Minimal CLI (`cli/`, Python or Go, owner's choice) for `deploy`, `list`, `rollback`.
- Git-backed deployment: register a repo + branch + subdirectory; poll or webhook;
  build on change.
- **Done when:** `cli deploy ./myapp` publishes a Shiny app end to end, and rollback works.

### Phase 3: Publisher UI and sharing
- Content list ("My content" / "Shared with me"), content settings page:
  access (users/groups with type-ahead from the IdP where possible), runtime settings,
  environment variables/secrets, versions, logs.
- Admin view: all content, users, audit log.
- Match existing ShinyProxy look and feel; keep templates in new files.
- **Done when:** an owner can share with a group and a member of that group can open it.

### Phase 4: Static documents
- Types `quarto_static` / `rmarkdown_static`: upload pre-rendered output or render
  once at publish time in a build container.
- Serve files from object storage through the platform, enforcing the same ACLs.
  No container per viewer.
- **Done when:** a rendered Quarto site with multiple pages and assets is served behind auth.

### Phase 5: Scheduled renders
- Cluster-safe scheduler (Quartz with JDBC job store, or Spring scheduling + ShedLock).
- A run starts a one-off container from the content's image, renders with parameters,
  uploads output as a new rendition, stores logs, and marks the run status.
- UI: schedule editor (cron + timezone), run history, "run now", view any past output.
- Optional (later): email notification on success/failure via SMTP.
- **Done when:** a scheduled Quarto report re-renders on time and viewers see the latest output.

### Phase 6: APIs
- Types `plumber` / `fastapi`: long-running shared containers (reuse container sharing /
  pre-initialization), stable URL under `/content/<slug>/`, no iframe.
- Auth via session cookie or `Authorization: Key <api_key>` header; ACLs apply.
- Pass authenticated user identity to the container in headers; strip any
  client-supplied identity headers first.
- **Done when:** `curl -H "Authorization: Key ..." .../content/my-api/predict` works
  and is denied without a valid key or ACL.

### Phase 7: Data artifacts
- Type `data`: versioned files (`.rds`, `.RData`, `.parquet`, `.csv`) with metadata,
  downloadable behind auth via stable URLs.
- Keep the storage layout simple so an R/Python helper package (later) can read and
  write them. Do not implement Connect's pins board API (see Section 3).
- **Done when:** a user can publish and fetch a versioned `.rds` via CLI and URL.

### Phase 8: Hardening
- Audit log coverage for all mutating actions.
- Per-content resource limits, build quotas, bundle size limits.
- Metrics for builds, renders and API calls (extend existing Prometheus setup).
- Backup/restore docs for PostgreSQL + object storage.
- Helm chart / Operator integration notes for Kubernetes.

## 7. Security requirements (all phases)

- Treat every bundle as untrusted code. Builds and content containers run unprivileged,
  with no Docker socket, no host mounts, resource limits, and network policy where available.
- Encrypt secrets at rest (key from environment/KMS, never in the DB). Never log them.
- API keys: show once, store hashed, support revocation, record last use.
- CSRF protection for UI mutations; publisher API uses tokens.
- Validate slugs, file paths (no traversal in bundle extraction), and manifest content.
- Every authorization decision goes through one service; add tests for deny cases.

## 8. Testing

- Unit tests for access evaluation, manifest validation, scheduling logic.
- Integration tests with Testcontainers (PostgreSQL, MinIO, Keycloak where feasible).
- An end-to-end smoke test script: deploy Shiny app, static Quarto doc, scheduled
  report, Plumber API, data file; verify access allowed/denied for two test users in
  different groups.
- Keep upstream ShinyProxy tests passing.

## 9. Explicit non-goals (for now)

- Connect/rsconnect API compatibility (pending legal review).
- Push-button publishing from IDEs (possible later via our CLI/API).
- Multi-tenant SaaS hosting.
- Proprietary database drivers.

## 10. Open questions for the owner

1. Product name and license for new code (default: Apache 2.0, same as upstream).
2. Primary target backend: Docker (single host) or Kubernetes?
3. Object storage: S3-compatible (MinIO) or plain filesystem/PVC?
4. CLI language: Python or Go? Is an R publishing package wanted early?
5. Which IdPs must be tested first (AD/LDAP, Keycloak, Entra ID, other)?
6. Is email delivery of scheduled reports required for v1?
