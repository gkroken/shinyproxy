# Skald — Workplan: ShinyProxy fork → self-service publishing platform

A free, self-hosted publishing platform for R and Python content, built on a fork of
ShinyProxy. ShinyProxy already gives us container orchestration, authentication
(LDAP, OIDC, SAML, Kerberos), access rules, scaling and monitoring. What it lacks —
and what this plan builds — is the **publishing and automation layer**.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

**Current status (2026-09-15):** planning complete. Build verified green through the
Docker Maven image. Spine #0 not started.

---

## 1. Definition of Done

v1 is reached when **all** of the following hold:

- A data scientist publishes a Shiny app from a laptop with one CLI command, and it is
  live behind the existing auth — no admin touched a config file, nothing restarted.
- That person shares it with a group from the UI, and a member of that group can open it.
- A Quarto document renders on a schedule and viewers see the latest output.
- A Plumber API answers `curl -H "Authorization: Key …"` at a stable URL, and is denied
  without a valid key or ACL.
- A versioned `.rds` is published and fetched by URL.
- Every deployment is versioned and rollback works, **including for apps currently running**.
- Upstream ShinyProxy's test suite is still green.
- The end-to-end smoke script passes for two test users in different groups, asserting
  both allow and **deny**.

Non-goals for v1 are in §6.

---

## 2. Guiding principles

1. **Build the irreversible things first.** Storage layout, the content/ACL model, the
   bundle manifest, and URL shape are expensive to change once content exists. Breaking
   changes are free now and brutal later. Everything else waits for a real user to ask.
2. **Depth over breadth.** `streamlit` and `dash` are "Shiny with a different port" —
   near-free whenever someone wants them, and pure unverified surface until then. Six
   content types that genuinely work beat fifteen with holes in them.
3. **Mergeable with upstream.** New code in new packages. Upstream diffs are a last
   resort, kept small, and documented in `docs/UPSTREAM_CHANGES.md`.
4. **One authorization service.** Every access decision goes through it, and deny cases
   are tested. Authorization spread across routes is how holes happen.
5. **Untrusted by default.** Every bundle is hostile code until proven otherwise.
6. **Verification is the bottleneck, not authorship.** The expensive part is proving a
   thing works against real clients — `rsconnect`-shaped publishing flows, real Quarto,
   real `curl`. Budget for that, not for writing the handler.

---

## 3. The spine

Dependency-ordered. Each item gets its own `WORKPLAN-<TRACK>.md` written **when the track
starts**, following the format of this repo's existing track files: Problem → Decision
(LOCKED) → Design → Tasks → Next agenda item.

| # | Track | Model | Why that model |
|---|---|---|---|
| 0 | Dev stack + orientation | **Sonnet 5** | Mechanical wiring against a written spec. Escalate to Opus only for `docs/ARCHITECTURE.md`. |
| 1 | Content registry + runtime specs | **Opus 5** | The irreversible one: schema, dispatcher override, ACL projection, version resolvability. |
| 2 | Bundles + builds | **Opus 5** (manifest, extraction) / **Sonnet 5** (BuildKit driver, logs) | Manifest format is irreversible; tar extraction is an untrusted-input boundary. The build driver is not. |
| 3 | Publisher API + CLI | **Opus 5** (API-key + auth design) / **Sonnet 5** (CRUD, CLI) | Auth design is security-sensitive and shipped-once. The rest is well-specified plumbing. |
| 4 | Publisher UI + sharing | **Opus 5** (IA + design pass) / **Sonnet 5** (templates, wiring) | UI-heavy track with real UX judgment. Load the `frontend-design` skill for the design pass so it doesn't read as templated default. |
| 5 | Static documents | **Sonnet 5**, Opus 5 reviews path handling | Mostly auth'd file serving. The traversal defense is the part that must not be wrong. |
| 6 | Scheduled renders | **Opus 5** (cluster-safety decision) / **Sonnet 5** (runner, UI) | Single-firing under N replicas is a correctness problem with a subtle failure mode. |
| 7 | APIs (Plumber / FastAPI) | **Opus 5** | Identity-header injection and stripping is a security boundary. |
| 8 | Data artifacts | **Sonnet 5** | Versioned files behind the ACLs we already have. |
| 9 | Hardening | **Opus 5** (audit + threat review) / **Haiku 4.5** (mechanical sweeps) | Judgment vs. bulk edits, split honestly. |

**How to read this column.** Work runs in an interactive Opus 5 session, so these are not
handoffs to separate operators. They mean: Opus 5 drives the tracks (or parts of tracks)
marked Opus, and delegates Sonnet-marked work to a Sonnet 5 subagent when the spec is
written and the work is plumbing. Haiku 4.5 is for bulk mechanical edits. Fable is not
available on this plan.

**Standing rule, overrides the table:** any diff touching authentication, ACL evaluation,
bundle extraction, secret handling, or header injection gets an **Opus 5** review before
merge, regardless of which model wrote it.

**Escalation rule:** a model that finds the track's LOCKED decision is wrong stops and
escalates to Opus 5 rather than working around it. Working around a locked decision
silently is the failure mode this rule exists to prevent.

---

### #0 — Dev stack + orientation · Sonnet 5

- [ ] `docker-compose.dev.yml`: app + PostgreSQL + Keycloak + MinIO + local registry.
- [ ] `Makefile` wrapping the Docker Maven build (`make build` / `make test` / `make dev`).
- [ ] Keycloak realm fixture with two users in **different groups** — this is the fixture
      every later access test depends on, so it is built now, not in #1.
- [ ] Second `licenseSet` in `pom.xml` so our packages carry our copyright and upstream
      files keep theirs (see CLAUDE.md — `strictCheck` will otherwise force false attribution).
- [ ] `docs/ARCHITECTURE.md` — request-flow diagram + extension-point map. **Opus 5.**
- [ ] Document the integration-test prerequisites (test-app image, TCP docker socket on 2375).

**Done when:** one command brings up the stack and you log in via Keycloak with group
claims visible, and `make test` is green.

---

### #1 — Content registry + runtime specs · Opus 5

The architectural bet. Everything after this assumes it holds.

- [ ] **First commit: the dispatcher fix.** Replace `proxyDispatcherService` with a lazy
      implementation that falls back to the default dispatcher for unknown spec ids.
      Proven by a test that starts an app added *after* boot. Do this before any schema
      work — if it does not hold, the whole plan changes shape.
- [ ] Flyway + PostgreSQL. Tables: `content`, `content_version`, `content_acl`,
      `content_env`, `audit_event`.
- [ ] DB-backed `IProxySpecProvider` merged with YAML specs. **YAML specs stay read-only
      and admin-owned** — a publisher can never shadow or edit one.
- [ ] `content_acl` + visibility (`acl_only` | `all_authenticated` | `anonymous`)
      projected into a synthesized `AccessControl`. Groups come from the existing auth
      backends, unchanged.
- [ ] **Superseded versions stay resolvable** while their containers live
      (`ProxyService.java:536` re-resolves the spec at stop time).
- [ ] Admin-only endpoint to insert content. No publishing API or UI yet.
- [ ] Deny-case tests: wrong group, revoked ACL, anonymous against `acl_only`.

**Done when:** an app inserted via the admin endpoint appears for permitted users only,
starts and stops, and disappears for others — with no restart.

---

### #2 — Bundles + builds · Opus 5 / Sonnet 5

- [ ] Our own bundle format: `.tar.gz` + `manifest.json`, with a JSON Schema in
      `schemas/manifest.schema.json`, validated on upload. **Opus 5** — irreversible.
- [ ] Hardened extraction: no traversal, no symlink escape, size and entry-count caps.
      **Opus 5** — untrusted input.
- [ ] Base images per content type and language version, in `images/`.
- [ ] BuildKit build → local registry, with lockfile-hash layer caching. **Sonnet 5.**
- [ ] Builds run isolated: unprivileged, resource-limited, timed out, **no Docker socket**.
- [ ] Build status + logs streamed to MinIO and viewable. **Sonnet 5.**
- [ ] Activate version / roll back.

**Done when:** upload → build → activate → the app runs; rollback returns the previous
version without disturbing running containers.

---

### #3 — Publisher API + CLI · Opus 5 / Sonnet 5

- [ ] `/__api__/v1`: create content, upload bundle, list versions, activate, roll back,
      delete. Session **or** API key.
- [ ] API keys: shown once, stored hashed, revocable, last-use recorded. **Opus 5.**
- [ ] CSRF protection for UI mutations; token auth for the API.
- [ ] CLI (`cli/`) — `deploy`, `list`, `rollback`. **Python**, so the audience can
      `pip install` it (ADR-0005). **Sonnet 5.**

**Done when:** `skald deploy ./myapp` publishes a Shiny app end to end, and rollback works.

---

### #4 — Publisher UI + sharing · Opus 5 (design) / Sonnet 5 (build-out)

- [ ] "My content" / "Shared with me" lists.
- [ ] Content settings: access (users/groups, type-ahead from the IdP where possible),
      runtime settings, environment variables and secrets, versions, logs.
- [ ] Admin view: all content, users, audit log.
- [ ] Matches ShinyProxy's existing look and feel; new templates in new files.

**Done when:** an owner shares with a group from the UI and a member of that group opens
the content.

---

### #5 — Static documents · Sonnet 5 (Opus 5 reviews path handling)

- [ ] `quarto_static` / `rmarkdown_static`: render once at publish time in a build
      container, or accept pre-rendered output.
- [ ] Serve from MinIO through the platform under the same ACLs. **No container per viewer.**

**Done when:** a multi-page Quarto site with assets is served behind auth.

---

### #6 — Scheduled renders · Opus 5 / Sonnet 5

- [ ] Cluster-safe scheduling — single firing under N replicas. Quartz JDBC job store or
      ShedLock; decide in the track workplan. **Opus 5.**
- [ ] A run starts a one-off container from the content's image, renders with parameters,
      uploads output as a new rendition, stores logs, marks run status.
- [ ] `schedule` + `render_run` tables; schedule editor (cron + timezone), run history,
      "run now", view any past output.

**Done when:** a scheduled Quarto report re-renders on time and viewers see the latest
output. Deferred: email notification (ADR-0006).

---

### #7 — APIs · Opus 5

- [ ] `plumber` / `fastapi`: long-running shared containers, reusing ContainerProxy's
      existing seat/pre-initialization mechanism.
- [ ] Stable URL at `/content/<slug>/`, no iframe, via `ProxyMappingManager.dispatchAsync`.
- [ ] Session cookie **or** `Authorization: Key <api_key>`; ACLs apply either way.
- [ ] Authenticated identity passed to the container in headers — **after stripping any
      client-supplied identity headers**.

**Done when:** `curl -H "Authorization: Key …" .../content/my-api/predict` works, and is
denied without a valid key or ACL.

---

### #8 — Data artifacts · Sonnet 5

- [ ] Type `data`: versioned `.rds` / `.RData` / `.parquet` / `.csv` with metadata,
      downloadable behind auth at stable URLs.
- [ ] Storage layout simple enough for a future R/Python helper package to read and write.
      **Not** Connect's pins board API (ADR-0003).

**Done when:** a user publishes and fetches a versioned `.rds` via CLI and URL.

---

### #9 — Hardening · Opus 5 / Haiku 4.5

- [ ] Audit log covers every mutating action. **Opus 5.**
- [ ] Per-content resource limits, build quotas, bundle size limits.
- [ ] Metrics for builds, renders and API calls — **including closing the dynamic-spec
      metrics gap from #1** (`Micrometer` registers per-spec metrics at startup only).
- [ ] Backup/restore docs for PostgreSQL + object storage. **Haiku 4.5.**
- [ ] Helm chart / Operator integration notes for Kubernetes.

---

## 4. Testing

- Unit tests: access evaluation, manifest validation, scheduling logic.
- Integration tests: Testcontainers for PostgreSQL, MinIO, Keycloak where feasible.
- **End-to-end smoke script**: deploy a Shiny app, a static Quarto doc, a scheduled
  report, a Plumber API, and a data file; verify **allow and deny** for two users in
  different groups. This is the acceptance tool, in the spirit of forge's
  `scripts/*-validate.sh`.
- Upstream ShinyProxy tests stay green throughout.

---

## 5. Locked scope decisions

Full rationale in `docs/DECISIONS.md`. Summary:

- **Docker single-host backend for v1.** Kubernetes deferred, but storage and build
  interfaces stay backend-agnostic so it is additive later. (ADR-0004)
- **MinIO / S3-compatible object storage** from the start, not filesystem-then-migrate. (ADR-0007)
- **Consume the released ContainerProxy jar; do not fork it yet.** One bean override is
  contained. The tripwire: a *second* required override means we fork. (ADR-0001)
- **Product name is Skald.** Java packages, repo name and upstream headers keep the
  ShinyProxy name for mergeability. (ADR-0002)
- **No rsconnect / Connect API compatibility** without explicit sign-off. (ADR-0003)
- **CLI in Python**, because the audience already has `pip`. (ADR-0005)
- **Email delivery deferred** past v1. (ADR-0006)
- **Git-backed deployment moved out of #2** to an optional track after #3. It is an input
  method, not an irreversible decision, and it competes with things that are.

---

## 6. Non-goals

- Connect / rsconnect API compatibility (pending legal review).
- Push-button publishing from IDEs — possible later via the CLI/API.
- Multi-tenant SaaS hosting.
- Proprietary database drivers.
- Content-type breadth (`streamlit`, `dash`, …) before a user asks for it.

---

## 7. Top risks

| Risk | Mitigation |
|---|---|
| ContainerProxy's startup-bound dispatcher blocks dynamic content | Fixed as the **first commit of #1**, before any schema work, so it fails early and cheap. |
| A second upstream override forces a ContainerProxy fork mid-plan | Keep the fork checked out and buildable from #0 so switching is a day, not a week. |
| Rollback breaks running apps (specs re-resolved at stop time) | Explicit requirement in #1; tested with a container alive across a version switch. |
| Bundle extraction or build escape | Untrusted-input boundary, Opus 5 + mandatory security review; no Docker socket anywhere near user content. |
| Upstream drift makes merges painful | New packages only; upstream diffs logged in `docs/UPSTREAM_CHANGES.md`; upstream tests stay green. |
